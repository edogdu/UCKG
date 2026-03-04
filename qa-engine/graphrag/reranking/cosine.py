"""
Legacy Reranking Module for GraphRAG Pipeline (cosine similarity fallback)
Handles Stage 3: Reranking with neighbor context using cosine similarity
"""

from typing import List, Dict
from collections import defaultdict
from ..utils import GraphRAGConfig, cosine_similarity


class GraphReranker:
    """
    Stage 3 (legacy fallback): Reranks results using cosine similarity

    Combines primary node similarity with neighbor relevance.
    Used only when cross-encoder is unavailable.
    """

    def __init__(self, config: GraphRAGConfig):
        """
        Initialize the GraphReranker

        Args:
            config: GraphRAGConfig with reranking parameters
        """
        self.config = config

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
        2. Recalculate combined scores (primary + neighbor)
        3. Return top-k results

        Args:
            items: List of graph items with primary nodes and neighbors
            query_embedding: Query embedding vector for similarity calculation
            top_k: Number of top results to return after reranking

        Returns:
            List of reranked items with updated scores
        """
        ranked_items = []

        for item in items:
            primary = item.get("primarySource", {})
            neighbors = item.get("firstHopNeighbors", [])

            # Get primary node embedding
            primary_embedding = primary.get("embedding", [])

            if primary_embedding:
                # STEP 1: Apply similarity-based filtering to 1-hop neighbors
                neighbors = self._filter_neighbors_by_similarity(
                    neighbors,
                    query_embedding,
                    max_per_relationship=3
                )

                # STEP 2: Apply similarity-based filtering to 2-hop neighbors
                for neighbor in neighbors:
                    second_hop = neighbor.get("secondHopNeighbors", [])
                    if second_hop:
                        filtered_second_hop = self._filter_second_hop_by_similarity(
                            second_hop,
                            query_embedding,
                            max_per_relationship=3
                        )
                        neighbor["secondHopNeighbors"] = filtered_second_hop

                # Recompute similarity score for primary node
                primary_score = cosine_similarity(query_embedding, primary_embedding)

                # Compute neighbor relevance scores
                neighbor_scores = []

                for neighbor in neighbors:
                    neighbor_data = neighbor.get("primaryNode", {})
                    neighbor_embedding = neighbor_data.get("embedding", [])

                    if neighbor_embedding:
                        neighbor_score = cosine_similarity(query_embedding, neighbor_embedding)
                        neighbor_scores.append(neighbor_score)

                filtered_neighbors = neighbors

                # Combined score: weighted average of primary and top neighbor scores
                if neighbor_scores:
                    top_neighbor_scores = sorted(neighbor_scores, reverse=True)[:3]
                    avg_neighbor_score = sum(top_neighbor_scores) / len(top_neighbor_scores)
                    final_score = (0.7 * primary_score + 0.3 * avg_neighbor_score)
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
