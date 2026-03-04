"""
Two-Pass Graph-Aware Cross-Encoder Reranking Module

Research foundation:
- KGPR (Pass 1): Enrich cross-encoder input with KG context (node type, relationships)
- G-RAG (Pass 2): Score neighbors separately, fuse signals with primary score
- PankRAG (Fusion): Composite scoring with weighted primary CE + neighbor CE + structural diversity
"""

import logging
from typing import List, Dict, Tuple

import numpy as np
from sentence_transformers import CrossEncoder

from ..utils import GraphRAGConfig

logger = logging.getLogger(__name__)


class CrossEncoderReranker:
    """
    Stage 3: Two-pass graph-aware reranking

    Pass 1 (KGPR): Score candidates using graph-enriched text that includes
    node type, label, content, and relationship summaries.

    Pass 2 (G-RAG + PankRAG): For top survivors, score their neighbors with the
    cross-encoder, compute structural diversity, and fuse all signals into a
    composite score.
    """

    def __init__(self, config: GraphRAGConfig):
        self.config = config
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load the cross-encoder model"""
        try:
            logger.info("Loading cross-encoder model: %s", self.config.cross_encoder_model)
            self.model = CrossEncoder(self.config.cross_encoder_model)
            logger.info("Cross-encoder model loaded successfully")
        except Exception as e:
            logger.error("Failed to load cross-encoder model: %s", e)
            raise

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def rerank(
        self,
        query: str,
        items: List[Dict],
        top_k: int,
    ) -> List[Dict]:
        """
        Two-pass graph-aware reranking.

        Pass 1: Graph-enriched cross-encoder scoring on all candidates,
                 keep top ``config.rerank_pass1_top_k``.
        Pass 2: Neighbor CE scoring + structural diversity on survivors,
                 composite fusion, keep top ``top_k``.

        Args:
            query: Raw query string
            items: Normalized graph items from retrieval
            top_k: Final number of results to return

        Returns:
            Reranked items with composite scores and component breakdown
        """
        if not items:
            return []

        if self.model is None:
            logger.warning("Cross-encoder model not loaded, returning items as-is")
            return items[:top_k]

        # ---- Pass 1: Graph-enriched cross-encoder ---- #
        pass1_pairs = []
        valid_items = []
        for item in items:
            text = self._build_enriched_text(item)
            if text:
                pass1_pairs.append((query, text))
                valid_items.append(item)

        if not pass1_pairs:
            logger.warning("No valid content for cross-encoder scoring")
            return items[:top_k]

        logger.info("Pass 1: Scoring %d enriched candidates", len(pass1_pairs))
        pass1_scores = self.model.predict(pass1_pairs).tolist()

        # Pair items with their Pass 1 scores and sort descending
        scored = list(zip(valid_items, pass1_scores))
        scored.sort(key=lambda x: x[1], reverse=True)

        pass1_top_k = self.config.rerank_pass1_top_k
        survivors = scored[:pass1_top_k]

        logger.info(
            "Pass 1 top-%d scores: %s",
            pass1_top_k,
            [round(s, 3) for _, s in survivors[:5]],
        )

        # ---- Pass 2: Neighbor CE + structural diversity ---- #
        survivor_items = [item for item, _ in survivors]
        primary_scores = np.array([s for _, s in survivors])

        neighbor_signals = self._score_neighbors(query, survivor_items)
        structural_signals = np.array(
            [self._compute_structural_diversity(item) for item in survivor_items]
        )

        # Min-max normalize each signal to [0, 1]
        norm_primary = self._min_max_normalize(primary_scores)
        norm_neighbor = self._min_max_normalize(neighbor_signals)
        # structural_signals already in [0, 1] by construction

        alpha = self.config.rerank_alpha
        beta = self.config.rerank_beta
        gamma = self.config.rerank_gamma

        composite = alpha * norm_primary + beta * norm_neighbor + gamma * structural_signals

        # Build final results sorted by composite score
        results = []
        order = np.argsort(-composite)
        for idx in order[:top_k]:
            item = survivor_items[idx]
            score = float(composite[idx])
            reranked = self._build_reranked_item(
                item,
                score=score,
                primary_ce=float(primary_scores[idx]),
                neighbor_signal=float(neighbor_signals[idx]),
                structural_signal=float(structural_signals[idx]),
            )
            results.append(reranked)

        logger.info(
            "Pass 2 composite top-%d: %s",
            top_k,
            [round(r["score"], 3) for r in results],
        )

        return results

    # ------------------------------------------------------------------ #
    #  Pass 1 helpers                                                     #
    # ------------------------------------------------------------------ #

    def _build_enriched_text(self, item: Dict) -> str:
        """
        Build KGPR-style enriched text for a candidate.

        Format: ``[NodeType] Label: Content | Related: REL->NbLabel; ...``

        Truncated to ``config.rerank_enriched_max_length`` characters.
        """
        primary = item.get("primarySource", {})
        node_type = primary.get("nodeType", "")
        label = primary.get("nodeLabel", "")
        content = primary.get("nodeContent", "")

        if not content and not label:
            return ""

        # Core text: "[Type] Label: Content"
        parts = []
        if node_type:
            parts.append(f"[{node_type}]")
        if label:
            parts.append(f"{label}:")
        if content:
            parts.append(content)
        core = " ".join(parts)

        # Relationship summary from 1-hop neighbors
        neighbors = item.get("firstHopNeighbors", [])
        rel_parts = []
        for nb in neighbors[:self.config.rerank_enriched_neighbor_count]:
            nb_node = nb.get("primaryNode", {})
            rel_type = nb.get("relationshipType", "")
            nb_label = nb_node.get("nodeLabel", "")
            nb_type = nb_node.get("nodeType", "")
            if rel_type and nb_label:
                rel_parts.append(f"{rel_type}->[{nb_type}] {nb_label}")

        if rel_parts:
            rel_summary = " | Related: " + "; ".join(rel_parts)
        else:
            rel_summary = ""

        max_len = self.config.rerank_enriched_max_length
        # Reserve space for relationship summary
        available = max_len - len(rel_summary)
        if available < 50:
            # Not enough room — just use core text truncated
            return core[:max_len]
        return core[:available] + rel_summary

    # ------------------------------------------------------------------ #
    #  Pass 2 helpers                                                     #
    # ------------------------------------------------------------------ #

    def _score_neighbors(self, query: str, items: List[Dict]) -> np.ndarray:
        """
        Batch-score all neighbors of the given items with the cross-encoder.

        For each item, returns the mean of the top-3 neighbor CE scores.
        Items with no scoreable neighbors get a score of 0.0.
        """
        # Collect all (query, neighbor_content) pairs with back-references
        all_pairs: List[Tuple[str, str]] = []
        pair_to_item: List[int] = []  # item index for each pair

        for i, item in enumerate(items):
            neighbors = item.get("firstHopNeighbors", [])
            for nb in neighbors:
                nb_node = nb.get("primaryNode", {})
                nb_content = nb_node.get("nodeContent", "")
                nb_label = nb_node.get("nodeLabel", "")
                nb_type = nb_node.get("nodeType", "")
                text = nb_content or nb_label
                if text:
                    # Build compact neighbor text: "[Type] Label: Content"
                    if nb_type:
                        text = f"[{nb_type}] {nb_label}: {text}" if nb_label and nb_content else f"[{nb_type}] {text}"
                    all_pairs.append((query, text))
                    pair_to_item.append(i)

        # Batch predict all neighbor pairs at once
        n_items = len(items)
        if not all_pairs:
            return np.zeros(n_items)

        logger.info("Pass 2: Scoring %d neighbor pairs", len(all_pairs))
        scores = self.model.predict(all_pairs).tolist()

        # Group scores by item and compute mean of top-3
        item_scores: Dict[int, List[float]] = {}
        for pair_idx, score in enumerate(scores):
            item_idx = pair_to_item[pair_idx]
            item_scores.setdefault(item_idx, []).append(float(score))

        result = np.zeros(n_items)
        for item_idx, nb_scores in item_scores.items():
            top3 = sorted(nb_scores, reverse=True)[:3]
            result[item_idx] = sum(top3) / len(top3)

        return result

    def _compute_structural_diversity(self, item: Dict) -> float:
        """
        Compute structural diversity score for a candidate's neighborhood.

        Measures variety of neighbor node types and relationship types.
        Score = 0.5 * (unique_node_types / count) + 0.5 * (unique_rel_types / count)

        Already in [0, 1] by construction.
        """
        neighbors = item.get("firstHopNeighbors", [])
        if not neighbors:
            return 0.0

        node_types = set()
        rel_types = set()
        for nb in neighbors:
            nb_node = nb.get("primaryNode", {})
            nt = nb_node.get("nodeType", "")
            rt = nb.get("relationshipType", "")
            if nt:
                node_types.add(nt)
            if rt:
                rel_types.add(rt)

        count = len(neighbors)
        type_diversity = len(node_types) / count
        rel_diversity = len(rel_types) / count
        return 0.5 * type_diversity + 0.5 * rel_diversity

    # ------------------------------------------------------------------ #
    #  Normalization & output building                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _min_max_normalize(scores: np.ndarray) -> np.ndarray:
        """Min-max normalize an array to [0, 1]. Returns zeros if constant."""
        mn, mx = scores.min(), scores.max()
        if mx - mn < 1e-9:
            return np.zeros_like(scores)
        return (scores - mn) / (mx - mn)

    def _build_reranked_item(
        self,
        item: Dict,
        score: float,
        primary_ce: float,
        neighbor_signal: float,
        structural_signal: float,
    ) -> Dict:
        """
        Build reranked item with composite score and component breakdown,
        preserving the full graph structure for downstream generation.
        """
        primary = item.get("primarySource", {}).copy()
        neighbors = item.get("firstHopNeighbors", [])

        # Clean up embeddings (not needed after scoring)
        primary.pop("embedding", None)

        cleaned_neighbors = []
        for neighbor in neighbors:
            neighbor_copy = neighbor.copy()
            neighbor_node = neighbor_copy.get("primaryNode", {})
            if isinstance(neighbor_node, dict):
                neighbor_node = neighbor_node.copy()
                neighbor_node.pop("embedding", None)
                neighbor_copy["primaryNode"] = neighbor_node

            # Clean 2-hop neighbor embeddings
            second_hop = neighbor_copy.get("secondHopNeighbors", [])
            cleaned_second_hop = []
            for sh in second_hop:
                sh_copy = sh.copy()
                related_node = sh_copy.get("relatedNode", {})
                if isinstance(related_node, dict):
                    related_node = related_node.copy()
                    related_node.pop("embedding", None)
                    sh_copy["relatedNode"] = related_node
                cleaned_second_hop.append(sh_copy)
            neighbor_copy["secondHopNeighbors"] = cleaned_second_hop

            cleaned_neighbors.append(neighbor_copy)

        # Store scores for evaluation/debugging
        primary["score"] = score
        primary["crossEncoderScore"] = primary_ce
        primary["primaryCEScore"] = primary_ce
        primary["neighborSignal"] = neighbor_signal
        primary["structuralSignal"] = structural_signal

        return {
            "primarySource": primary,
            "firstHopNeighbors": cleaned_neighbors,
            "score": score,
        }
