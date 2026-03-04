"""
Subgraph pruning for GraphRAG pipeline.

Implements a deterministic PCST-style heuristic that prunes low-value nodes
after reranking and before generation.
"""

import heapq
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Set, Tuple

from ..utils import GraphRAGConfig

logger = logging.getLogger(__name__)


@dataclass
class PrunerNode:
    node_key: str
    node_id: Any
    uri: str
    node_type: str
    label: str
    content: str
    depth: int
    parent_primary_id: Any
    base_score: float


@dataclass
class PrunerEdge:
    src_key: str
    dst_key: str
    rel_type: str
    hop_level: int
    edge_cost: float


@dataclass
class PruningStats:
    pre_nodes: int
    post_nodes: int
    pruned_nodes: int
    prune_ratio: float
    pre_first_hop: int
    post_first_hop: int
    pre_second_hop: int
    post_second_hop: int


class SubgraphPruner:
    """PCST-style deterministic subgraph pruner."""

    _TOKEN_PATTERN = re.compile(r"\b\w+\b")

    def __init__(self, config: GraphRAGConfig):
        self.config = config

    def prune(self, items: List[Dict], query: str, hop_depth: int) -> Tuple[List[Dict], Dict[str, Any]]:
        """Prune reranked items and return (pruned_items, pruning_metadata)."""
        pre_counts = self._count_subgraph(items)

        if not self.config.enable_subgraph_pruning:
            return items, self._build_metadata(
                status="bypassed_disabled",
                hop_depth=hop_depth,
                budget=None,
                pre_counts=pre_counts,
                post_counts=pre_counts,
            )

        if hop_depth <= 0:
            return items, self._build_metadata(
                status="bypassed_hop0",
                hop_depth=hop_depth,
                budget=None,
                pre_counts=pre_counts,
                post_counts=pre_counts,
            )

        try:
            pruned_items, effective_budget = self._prune_internal(items, query, hop_depth)
            post_counts = self._count_subgraph(pruned_items)
            return pruned_items, self._build_metadata(
                status="applied",
                hop_depth=hop_depth,
                budget=effective_budget,
                pre_counts=pre_counts,
                post_counts=post_counts,
            )
        except Exception as exc:  # pragma: no cover - safety path
            logger.warning("Subgraph pruning failed; bypassing pruning: %s", exc, exc_info=True)
            return items, self._build_metadata(
                status="bypassed_error",
                hop_depth=hop_depth,
                budget=None,
                pre_counts=pre_counts,
                post_counts=pre_counts,
                error=str(exc),
            )

    def _prune_internal(self, items: List[Dict], query: str, hop_depth: int) -> Tuple[List[Dict], int]:
        query_tokens = self._tokenize(query)
        graph = self._build_graph(items)

        primary_order = graph["primary_order"]
        outgoing_edges = graph["outgoing_edges"]
        incoming_edges = graph["incoming_edges"]
        nodes = graph["nodes"]
        parent_primaries = graph["parent_primaries"]
        primary_scores = graph["primary_scores"]

        raw_budget = (
            self.config.subgraph_prune_budget_hop1
            if hop_depth == 1
            else self.config.subgraph_prune_budget_hop2
        )

        normalized_primary_scores = self._normalize_scores(primary_scores)
        node_prizes = self._compute_node_prizes(
            nodes=nodes,
            incoming_edges=incoming_edges,
            parent_primaries=parent_primaries,
            normalized_primary_scores=normalized_primary_scores,
            query_tokens=query_tokens,
        )

        selected: Set[str] = set()
        if self.config.subgraph_prune_keep_all_primary:
            selected.update(primary_order)

        min_first_hop = max(0, self.config.subgraph_prune_min_first_hop_per_primary)
        if min_first_hop > 0:
            for primary_key in primary_order:
                first_hop_edges = [
                    edge for edge in outgoing_edges.get(primary_key, [])
                    if edge.hop_level == 1 and edge.dst_key in nodes
                ]
                ranked = sorted(
                    first_hop_edges,
                    key=lambda edge: (
                        -(node_prizes.get(edge.dst_key, 0.0) - edge.edge_cost),
                        edge.hop_level,
                        edge.dst_key,
                    ),
                )
                for edge in ranked[:min_first_hop]:
                    selected.add(edge.dst_key)

        effective_budget = max(raw_budget, len(selected))
        if not selected and primary_order:
            selected.add(primary_order[0])
            effective_budget = max(effective_budget, 1)

        frontier: List[Tuple[float, int, str, str]] = []
        self._push_frontier(frontier, selected, outgoing_edges, node_prizes)

        while frontier and len(selected) < effective_budget:
            neg_gain, hop_level, dst_key, src_key = heapq.heappop(frontier)
            if dst_key in selected or src_key not in selected:
                continue

            gain = -neg_gain
            if gain < 0:
                break

            selected.add(dst_key)
            self._push_frontier(frontier, selected, outgoing_edges, node_prizes, src_override=dst_key)

        pruned_items = self._reconstruct_items(items, selected)
        return pruned_items, effective_budget

    def _push_frontier(
        self,
        frontier: List[Tuple[float, int, str, str]],
        selected: Set[str],
        outgoing_edges: Dict[str, List[PrunerEdge]],
        node_prizes: Dict[str, float],
        src_override: str = None,
    ) -> None:
        sources = [src_override] if src_override else list(selected)
        for src in sources:
            for edge in outgoing_edges.get(src, []):
                if edge.dst_key in selected:
                    continue
                gain = node_prizes.get(edge.dst_key, 0.0) - edge.edge_cost
                heapq.heappush(
                    frontier,
                    (-gain, edge.hop_level, edge.dst_key, edge.src_key),
                )

    def _compute_node_prizes(
        self,
        nodes: Dict[str, PrunerNode],
        incoming_edges: Dict[str, List[PrunerEdge]],
        parent_primaries: Dict[str, Set[str]],
        normalized_primary_scores: Dict[str, float],
        query_tokens: Set[str],
    ) -> Dict[str, float]:
        prizes: Dict[str, float] = {}
        for node_key, node in nodes.items():
            if node.depth == 0:
                prizes[node_key] = 0.0
                continue

            lexical_score = self._lexical_overlap(query_tokens, f"{node.label} {node.content}")
            parent_score = max(
                (normalized_primary_scores.get(pk, 0.0) for pk in parent_primaries.get(node_key, set())),
                default=0.0,
            )
            relation_score = max(
                (self._lexical_overlap(query_tokens, edge.rel_type) for edge in incoming_edges.get(node_key, [])),
                default=0.0,
            )

            base_prize = (
                self.config.subgraph_prune_weight_lexical * lexical_score
                + self.config.subgraph_prune_weight_parent * parent_score
                + self.config.subgraph_prune_weight_relation * relation_score
            )
            if node.depth >= 2:
                base_prize *= self.config.subgraph_prune_second_hop_decay
            prizes[node_key] = base_prize
        return prizes

    def _reconstruct_items(self, items: List[Dict], selected_keys: Set[str]) -> List[Dict]:
        pruned_items: List[Dict] = []
        for item in items:
            primary = item.get("primarySource", {})
            primary_key = self._node_key_from_node(primary)

            if primary_key and primary_key not in selected_keys:
                continue

            first_hop_pruned = []
            for relation in item.get("firstHopNeighbors", []):
                neighbor = relation.get("primaryNode", {})
                neighbor_key = self._node_key_from_node(neighbor)
                if not neighbor_key or neighbor_key not in selected_keys:
                    continue

                relation_copy = relation.copy()
                relation_copy["primaryNode"] = neighbor.copy() if isinstance(neighbor, dict) else neighbor

                second_hop_pruned = []
                for second_hop in relation.get("secondHopNeighbors", []):
                    related = second_hop.get("relatedNode", {})
                    related_key = self._node_key_from_node(related)
                    if related_key and related_key in selected_keys:
                        second_copy = second_hop.copy()
                        second_copy["relatedNode"] = related.copy() if isinstance(related, dict) else related
                        second_hop_pruned.append(second_copy)
                relation_copy["secondHopNeighbors"] = second_hop_pruned
                first_hop_pruned.append(relation_copy)

            item_copy = item.copy()
            item_copy["primarySource"] = primary.copy() if isinstance(primary, dict) else primary
            item_copy["firstHopNeighbors"] = first_hop_pruned
            pruned_items.append(item_copy)
        return pruned_items

    def _build_graph(self, items: List[Dict]) -> Dict[str, Any]:
        nodes: Dict[str, PrunerNode] = {}
        outgoing_edges: Dict[str, List[PrunerEdge]] = defaultdict(list)
        incoming_edges: Dict[str, List[PrunerEdge]] = defaultdict(list)
        parent_primaries: Dict[str, Set[str]] = defaultdict(set)
        primary_scores: Dict[str, float] = {}
        primary_order: List[str] = []
        seen_primary: Set[str] = set()
        edge_seen: Set[Tuple[str, str, str, int]] = set()

        for item in items:
            primary = item.get("primarySource", {})
            primary_key = self._node_key_from_node(primary)
            if not primary_key:
                continue

            primary_score = float(item.get("score", primary.get("score", 0.0)) or 0.0)
            self._upsert_node(
                nodes=nodes,
                node_key=primary_key,
                node=primary,
                depth=0,
                parent_primary_id=primary.get("nodeId"),
                base_score=primary_score,
            )
            parent_primaries[primary_key].add(primary_key)
            primary_scores[primary_key] = max(primary_scores.get(primary_key, float("-inf")), primary_score)
            if primary_key not in seen_primary:
                primary_order.append(primary_key)
                seen_primary.add(primary_key)

            for relation in item.get("firstHopNeighbors", []):
                rel_type_1 = str(relation.get("relationshipType", ""))
                first_hop_node = relation.get("primaryNode", {})
                first_hop_key = self._node_key_from_node(first_hop_node)
                if not first_hop_key:
                    continue

                self._upsert_node(
                    nodes=nodes,
                    node_key=first_hop_key,
                    node=first_hop_node,
                    depth=1,
                    parent_primary_id=primary.get("nodeId"),
                    base_score=primary_score,
                )
                parent_primaries[first_hop_key].add(primary_key)
                self._add_edge(
                    outgoing_edges=outgoing_edges,
                    incoming_edges=incoming_edges,
                    seen=edge_seen,
                    src_key=primary_key,
                    dst_key=first_hop_key,
                    rel_type=rel_type_1,
                    hop_level=1,
                    edge_cost=self.config.subgraph_prune_first_hop_edge_cost,
                )

                for second_hop in relation.get("secondHopNeighbors", []):
                    rel_type_2 = str(second_hop.get("relationshipType", ""))
                    second_hop_node = second_hop.get("relatedNode", {})
                    second_hop_key = self._node_key_from_node(second_hop_node)
                    if not second_hop_key:
                        continue

                    self._upsert_node(
                        nodes=nodes,
                        node_key=second_hop_key,
                        node=second_hop_node,
                        depth=2,
                        parent_primary_id=primary.get("nodeId"),
                        base_score=primary_score,
                    )
                    parent_primaries[second_hop_key].add(primary_key)
                    self._add_edge(
                        outgoing_edges=outgoing_edges,
                        incoming_edges=incoming_edges,
                        seen=edge_seen,
                        src_key=first_hop_key,
                        dst_key=second_hop_key,
                        rel_type=rel_type_2,
                        hop_level=2,
                        edge_cost=self.config.subgraph_prune_second_hop_edge_cost,
                    )

        return {
            "nodes": nodes,
            "outgoing_edges": outgoing_edges,
            "incoming_edges": incoming_edges,
            "parent_primaries": parent_primaries,
            "primary_scores": primary_scores,
            "primary_order": primary_order,
        }

    def _add_edge(
        self,
        outgoing_edges: Dict[str, List[PrunerEdge]],
        incoming_edges: Dict[str, List[PrunerEdge]],
        seen: Set[Tuple[str, str, str, int]],
        src_key: str,
        dst_key: str,
        rel_type: str,
        hop_level: int,
        edge_cost: float,
    ) -> None:
        signature = (src_key, dst_key, rel_type, hop_level)
        if signature in seen:
            return
        seen.add(signature)
        edge = PrunerEdge(
            src_key=src_key,
            dst_key=dst_key,
            rel_type=rel_type,
            hop_level=hop_level,
            edge_cost=edge_cost,
        )
        outgoing_edges[src_key].append(edge)
        incoming_edges[dst_key].append(edge)

    def _upsert_node(
        self,
        nodes: Dict[str, PrunerNode],
        node_key: str,
        node: Dict[str, Any],
        depth: int,
        parent_primary_id: Any,
        base_score: float,
    ) -> None:
        all_props = node.get("allProperties", {}) or {}
        uri = all_props.get("uri", "")
        node_id = node.get("nodeId")
        node_type = node.get("nodeType", "")
        label = node.get("nodeLabel", "")
        content = node.get("nodeContent", "")

        existing = nodes.get(node_key)
        if existing is None:
            nodes[node_key] = PrunerNode(
                node_key=node_key,
                node_id=node_id,
                uri=uri,
                node_type=node_type,
                label=label,
                content=content,
                depth=depth,
                parent_primary_id=parent_primary_id,
                base_score=base_score,
            )
            return

        existing.depth = min(existing.depth, depth)
        if base_score > existing.base_score:
            existing.base_score = base_score
            existing.parent_primary_id = parent_primary_id
        if not existing.label and label:
            existing.label = label
        if not existing.content and content:
            existing.content = content
        if not existing.uri and uri:
            existing.uri = uri
        if existing.node_id is None and node_id is not None:
            existing.node_id = node_id

    def _count_subgraph(self, items: List[Dict]) -> Dict[str, int]:
        node_keys: Set[str] = set()
        first_hop_count = 0
        second_hop_count = 0

        for item in items:
            primary = item.get("primarySource", {})
            primary_key = self._node_key_from_node(primary)
            if primary_key:
                node_keys.add(primary_key)

            for relation in item.get("firstHopNeighbors", []):
                first_hop_count += 1
                first_hop_key = self._node_key_from_node(relation.get("primaryNode", {}))
                if first_hop_key:
                    node_keys.add(first_hop_key)

                for second_hop in relation.get("secondHopNeighbors", []):
                    second_hop_count += 1
                    second_hop_key = self._node_key_from_node(second_hop.get("relatedNode", {}))
                    if second_hop_key:
                        node_keys.add(second_hop_key)

        return {
            "nodes": len(node_keys),
            "first_hop": first_hop_count,
            "second_hop": second_hop_count,
        }

    def _build_metadata(
        self,
        status: str,
        hop_depth: int,
        budget: int,
        pre_counts: Dict[str, int],
        post_counts: Dict[str, int],
        error: str = None,
    ) -> Dict[str, Any]:
        pruned_nodes = max(0, pre_counts["nodes"] - post_counts["nodes"])
        prune_ratio = pruned_nodes / pre_counts["nodes"] if pre_counts["nodes"] else 0.0
        stats = PruningStats(
            pre_nodes=pre_counts["nodes"],
            post_nodes=post_counts["nodes"],
            pruned_nodes=pruned_nodes,
            prune_ratio=prune_ratio,
            pre_first_hop=pre_counts["first_hop"],
            post_first_hop=post_counts["first_hop"],
            pre_second_hop=pre_counts["second_hop"],
            post_second_hop=post_counts["second_hop"],
        )

        metadata = {
            "status": status,
            "hop_depth": hop_depth,
            "budget": budget,
        }

        if self.config.subgraph_prune_enable_diagnostics:
            metadata.update(asdict(stats))
        if error:
            metadata["error"] = error
        return metadata

    def _normalize_scores(self, scores: Dict[str, float]) -> Dict[str, float]:
        if not scores:
            return {}
        values = list(scores.values())
        min_score = min(values)
        max_score = max(values)
        if max_score - min_score < 1e-9:
            return {key: 1.0 for key in scores}
        return {key: (value - min_score) / (max_score - min_score) for key, value in scores.items()}

    def _lexical_overlap(self, query_tokens: Set[str], text: str) -> float:
        if not query_tokens:
            return 0.0
        text_tokens = self._tokenize(text)
        if not text_tokens:
            return 0.0
        overlap = query_tokens.intersection(text_tokens)
        return len(overlap) / len(query_tokens)

    def _tokenize(self, text: str) -> Set[str]:
        if not text:
            return set()
        return set(token.lower() for token in self._TOKEN_PATTERN.findall(str(text)))

    def _node_key_from_node(self, node: Dict[str, Any]) -> str:
        if not isinstance(node, dict):
            return ""
        all_props = node.get("allProperties", {}) or {}
        uri = all_props.get("uri")
        if uri:
            return f"uri:{uri}"
        node_id = node.get("nodeId")
        if node_id is not None:
            return f"id:{node_id}"
        node_type = node.get("nodeType", "")
        node_label = node.get("nodeLabel", "")
        if node_type or node_label:
            return f"fallback:{node_type}:{node_label}"
        return ""
