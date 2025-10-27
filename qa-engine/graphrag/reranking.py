"""
Reranking Module for GraphRAG Pipeline
Handles Stage 3: Reranking with neighbor context and relationship scoring
"""

from typing import List, Dict
from collections import defaultdict
from .utils import GraphRAGConfig, cosine_similarity


class GraphReranker:
    """
    Stage 3: Reranks results using neighbor context

    Combines primary node similarity with neighbor relevance and
    applies relationship prediction bonuses to improve ranking.
    """

    def __init__(self, config: GraphRAGConfig):
        """
        Initialize the GraphReranker

        Args:
            config: GraphRAGConfig with reranking parameters
        """
        self.config = config
        self.predicted_relationships = []  # Will be set per query

    def set_predicted_relationships(self, predicted_relationships: List[Dict]):
        """Set predicted relationships for relationship scoring"""
        self.predicted_relationships = predicted_relationships

    def rerank(
        self,
        items: List[Dict],
        query_embedding: List[float],
        top_k: int
    ) -> List[Dict]:
        """
        Rerank graph results by recomputing similarity scores

        Steps:
        1. Filter neighbors by similarity (keep top 2 per relationship type)
        2. Apply relationship prediction bonuses
        3. Recalculate combined scores (primary + neighbor)
        4. Return top-k results

        Args:
            items: List of graph items with primary nodes and neighbors
            query_embedding: Query embedding vector for similarity calculation
            top_k: Number of top results to return after reranking

        Returns:
            List of reranked items with updated scores
        """
        ranked_items = []

        for item in items:
            # Handle the nested structure from graph retriever
            if isinstance(item, dict) and 'metadata' in item:
                metadata = item.get("metadata", {})
                primary = metadata.get("primarySource", {})
                neighbors = metadata.get("firstHopNeighbors", [])
            elif isinstance(item, dict) and 'primarySource' in item:
                # Legacy format support
                primary = item.get("primarySource", {})
                neighbors = item.get("firstHopNeighbors", [])
            else:
                # Fallback for other formats
                continue

            # Get primary node embedding
            primary_embedding = primary.get("embedding", [])

            if primary_embedding:
                # STEP 1: Apply similarity-based filtering to 1-hop neighbors
                neighbors = self._filter_neighbors_by_similarity(
                    neighbors,
                    query_embedding,
                    max_per_relationship=2
                )

                # STEP 2: Apply similarity-based filtering to 2-hop neighbors
                for neighbor in neighbors:
                    second_hop = neighbor.get("secondHopNeighbors", [])
                    if second_hop:
                        filtered_second_hop = self._filter_second_hop_by_similarity(
                            second_hop,
                            query_embedding,
                            max_per_relationship=2
                        )
                        neighbor["secondHopNeighbors"] = filtered_second_hop

                # Recompute similarity score for primary node
                primary_score = cosine_similarity(query_embedding, primary_embedding)

                # Compute neighbor relevance scores WITH relationship scoring
                neighbor_scores = []
                relationship_scores = []  # Track relationship relevance

                for neighbor in neighbors:
                    neighbor_data = neighbor.get("primaryNode", {})
                    neighbor_embedding = neighbor_data.get("embedding", [])
                    rel_type = neighbor.get("relationshipType", "")

                    # Base similarity score
                    if neighbor_embedding:
                        neighbor_score = cosine_similarity(query_embedding, neighbor_embedding)

                        # Add relationship prediction bonus
                        if self.config.enable_relationship_prediction:
                            primary_node_type = primary.get("nodeType", "")
                            neighbor_node_type = neighbor_data.get("nodeType", "")
                            rel_bonus = self._score_relationship(rel_type, primary_node_type, neighbor_node_type)
                            neighbor_score += rel_bonus
                            relationship_scores.append((rel_type, neighbor_score, rel_bonus))

                        neighbor_scores.append(neighbor_score)

                # Filter to top N relationship types per node
                filtered_neighbors = neighbors
                if self.config.enable_relationship_prediction and relationship_scores:
                    # Group by relationship type and get top K
                    rel_type_scores = {}
                    for rel_type, score, bonus in relationship_scores:
                        if rel_type not in rel_type_scores or score > rel_type_scores[rel_type]:
                            rel_type_scores[rel_type] = score

                    # Sort and take top K relationship types
                    top_rel_types = sorted(rel_type_scores.items(), key=lambda x: x[1], reverse=True)
                    top_rel_types = [rt for rt, _ in top_rel_types[:self.config.max_relationships_per_hop]]

                    # Filter neighbors to only include top relationship types
                    filtered_neighbors = [
                        n for n in neighbors
                        if n.get("relationshipType", "") in top_rel_types
                    ]

                # Combined score: weighted average of primary and top neighbor scores
                if neighbor_scores:
                    top_neighbor_scores = sorted(neighbor_scores, reverse=True)[:self.config.top_neighbor_count_for_scoring]
                    avg_neighbor_score = sum(top_neighbor_scores) / len(top_neighbor_scores)
                    final_score = (self.config.rerank_weight_primary * primary_score +
                                 self.config.rerank_weight_neighbor * avg_neighbor_score)
                else:
                    # Apply penalty to nodes without neighbors
                    final_score = 0.7 * primary_score

                # Store reranking metadata
                primary["rerankScore"] = final_score
                primary["primaryScore"] = primary_score
                primary["score"] = final_score  # Use reranked score as main score

                # Clean up embeddings (too large for output)
                primary.pop("embedding", None)
                for neighbor in filtered_neighbors:
                    neighbor_data = neighbor.get("primaryNode", {})
                    neighbor_data.pop("embedding", None)

                ranked_items.append({
                    "primarySource": primary,
                    "firstHopNeighbors": filtered_neighbors,
                    "score": final_score
                })

        # Sort by reranked score and return top_k
        ranked_items.sort(key=lambda x: x["score"], reverse=True)
        return ranked_items[:top_k]

    def _filter_neighbors_by_similarity(
        self,
        neighbors: List[Dict],
        query_embedding: List[float],
        max_per_relationship: int = 2
    ) -> List[Dict]:
        """
        Filter neighbors by similarity to query, keeping top N per relationship type

        For each relationship type:
        - If > max_per_relationship nodes share that relationship
        - Rank by similarity to query embedding
        - Keep only top max_per_relationship most similar nodes

        Args:
            neighbors: List of neighbor dictionaries with 'relationshipType' and 'primaryNode'
            query_embedding: User query embedding vector
            max_per_relationship: Maximum nodes to keep per relationship type (default: 2)

        Returns:
            Filtered list of neighbors
        """
        # Group neighbors by relationship type
        grouped = defaultdict(list)
        for neighbor in neighbors:
            rel_type = neighbor.get("relationshipType", "UNKNOWN")
            grouped[rel_type].append(neighbor)

        # Filter each group
        filtered_neighbors = []
        for rel_type, nodes in grouped.items():
            if len(nodes) <= max_per_relationship:
                # Keep all if <= threshold
                filtered_neighbors.extend(nodes)
            else:
                # Compute similarity for each node and keep top N
                scored_nodes = []
                for node in nodes:
                    node_data = node.get("primaryNode", {})
                    node_embedding = node_data.get("embedding", [])

                    if node_embedding:
                        similarity = cosine_similarity(query_embedding, node_embedding)
                        scored_nodes.append((node, similarity))
                    else:
                        # No embedding - give it lowest priority
                        scored_nodes.append((node, 0.0))

                # Sort by similarity and keep top N
                scored_nodes.sort(key=lambda x: x[1], reverse=True)
                top_nodes = [node for node, _ in scored_nodes[:max_per_relationship]]
                filtered_neighbors.extend(top_nodes)

        return filtered_neighbors

    def _filter_second_hop_by_similarity(
        self,
        second_hop_neighbors: List[Dict],
        query_embedding: List[float],
        max_per_relationship: int = 2
    ) -> List[Dict]:
        """
        Filter 2-hop neighbors by similarity to query, keeping top N per relationship type

        Args:
            second_hop_neighbors: List of 2-hop neighbor dictionaries
            query_embedding: User query embedding vector
            max_per_relationship: Maximum nodes to keep per relationship type (default: 2)

        Returns:
            Filtered list of 2-hop neighbors
        """
        # Group by relationship type
        grouped = defaultdict(list)
        for neighbor in second_hop_neighbors:
            rel_type = neighbor.get("relationshipType", "UNKNOWN")
            grouped[rel_type].append(neighbor)

        # Filter each group
        filtered = []
        for rel_type, nodes in grouped.items():
            if len(nodes) <= max_per_relationship:
                # Keep all if <= threshold
                filtered.extend(nodes)
            else:
                # For 2-hop neighbors, keep top N based on order
                top_nodes = nodes[:max_per_relationship]
                filtered.extend(top_nodes)

        return filtered

    def _score_relationship(self, rel_type: str, start_node_type: str, end_node_type: str) -> float:
        """
        Score a relationship based on whether it was predicted as relevant

        Args:
            rel_type: Relationship type (e.g., "UCOEXMITIGATES")
            start_node_type: Starting node label
            end_node_type: Ending node label

        Returns:
            Score boost for this relationship (0.0 or prediction_bonus_score)
        """
        if not self.predicted_relationships:
            return 0.0

        # Check if this relationship matches any predicted relationships
        for pred_rel in self.predicted_relationships:
            if (pred_rel.get("relationship") == rel_type and
                pred_rel.get("start") == start_node_type and
                pred_rel.get("end") == end_node_type):
                return self.config.prediction_bonus_score

        return 0.0
