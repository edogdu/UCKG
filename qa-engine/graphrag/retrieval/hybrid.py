"""
Hybrid Retriever for GraphRAG Pipeline
Combines BM25 keyword search with Vector semantic search
"""

from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import logging

from .bm25 import BM25Retriever
from .vector import GraphRetriever

logger = logging.getLogger(__name__)


class HybridRetriever:
    """
    Hybrid retriever combining BM25 keyword search and Vector semantic search

    Strategy:
    1. Run both BM25 and Vector search independently
    2. Normalize scores from both methods
    3. Combine scores using weighted average
    4. Sort by combined score and return top-k
    """

    def __init__(self, driver, config, vector_retriever: GraphRetriever):
        """
        Initialize Hybrid Retriever

        Args:
            driver: Neo4j database driver
            config: GraphRAGConfig with retrieval parameters
            vector_retriever: Existing GraphRetriever instance for vector search
        """
        self.driver = driver
        self.config = config
        self.vector_retriever = vector_retriever

        # Initialize BM25 retriever
        try:
            self.bm25_retriever = BM25Retriever(driver, config)
            self.bm25_available = True
            logger.info("[HybridRetriever] BM25 retriever initialized")
        except ImportError:
            self.bm25_retriever = None
            self.bm25_available = False
            logger.warning("[HybridRetriever] BM25 not available, falling back to vector-only")

    def retrieve(
        self,
        query: str,
        top_k: int,
        hop_depth: int = None
    ) -> List[Dict]:
        """
        Execute hybrid retrieval combining BM25 and Vector search

        Args:
            query: User query string
            top_k: Number of results to return
            hop_depth: Graph traversal depth (0, 1, or 2)

        Returns:
            List of items with combined scores
        """
        if not self.bm25_available:
            logger.info("[HybridRetriever] BM25 not available, using vector-only retrieval")
            return self.vector_retriever.retrieve(query, top_k, hop_depth)

        # Calculate how many candidates to fetch from each method
        # Fetch more candidates to allow for better merging
        candidate_multiplier = self.config.initial_top_k_multiplier if hop_depth and hop_depth > 0 else 1
        fetch_k = top_k * candidate_multiplier * 2  # Fetch 2x for merging

        logger.info("Executing hybrid retrieval (BM25 + Vector), fetching %d candidates each", fetch_k)
        logger.info("Starting hybrid retrieval (BM25 + Vector)...")

        # Step 1: Run BM25 and Vector search in parallel
        logger.info("Step 1/2: Running BM25 and Vector search in parallel...")

        with ThreadPoolExecutor(max_workers=2) as executor:
            bm25_future = executor.submit(self._run_bm25_search, query, fetch_k, hop_depth)
            vector_future = executor.submit(self._run_vector_search, query, fetch_k, hop_depth)

            bm25_results = bm25_future.result()
            vector_results = vector_future.result()

        logger.info("Parallel search completed: BM25=%d, Vector=%d results", len(bm25_results), len(vector_results))

        # Step 2: Merge using Reciprocal Rank Fusion
        logger.info("Step 2/2: Merging BM25 and Vector results with RRF...")
        merged_results = self._merge_results_rrf(bm25_results, vector_results)

        final_results = merged_results[:top_k]
        logger.info("Returning %d results after hybrid merge", len(final_results))
        logger.info("Hybrid retrieval completed: %d final results", len(final_results))

        return final_results

    def _run_bm25_search(
        self,
        query: str,
        top_k: int,
        hop_depth: int
    ) -> List[Dict]:
        """Run BM25 search and return results"""
        try:
            # Build index if not already built
            if not self.bm25_retriever._index_built:
                logger.info("Building BM25 index (first time, may take 10-30 seconds)...")
                logger.info("[HybridRetriever] Building BM25 index...")
                self.bm25_retriever.build_index()
                logger.info("BM25 index built, proceeding with search...")

            # Search and format results
            logger.info("Running BM25 search for: '%s...'", query[:50])
            results = self.bm25_retriever.search_and_format(query, top_k, hop_depth)

            logger.info("BM25 found %d results", len(results))
            logger.info("BM25 search completed: %d results", len(results))
            return results

        except Exception as e:
            logger.error("BM25 search failed: %s", e, exc_info=True)
            return []

    def _run_vector_search(
        self,
        query: str,
        top_k: int,
        hop_depth: int
    ) -> List[Dict]:
        """Run Vector search and return results"""
        try:
            results = self.vector_retriever.retrieve(query, top_k, hop_depth)
            logger.info("Vector search found %d results", len(results))
            return results

        except Exception as e:
            logger.error("Vector search failed: %s", e, exc_info=True)
            return []

    def _merge_results_rrf(
        self,
        bm25_results: List[Dict],
        vector_results: List[Dict],
        k: int = 60
    ) -> List[Dict]:
        """
        Merge using Reciprocal Rank Fusion — rank-based, no normalization needed.

        RRF score = sum(1 / (k + rank + 1)) across lists where the node appears.
        This avoids the pitfalls of min-max normalization on different score distributions.

        Args:
            bm25_results: Results from BM25 search (ordered by BM25 score)
            vector_results: Results from Vector search (ordered by vector score)
            k: RRF constant (default 60, standard value from the original paper)

        Returns:
            Merged list of results sorted by RRF score
        """
        rrf_scores = {}
        node_data = {}

        for rank, result in enumerate(bm25_results):
            node_id = result.get('metadata', {}).get('primarySource', {}).get('nodeId')
            if node_id is None:
                continue
            rrf_scores[node_id] = rrf_scores.get(node_id, 0) + 1.0 / (k + rank + 1)
            node_data[node_id] = result

        for rank, result in enumerate(vector_results):
            node_id = result.get('metadata', {}).get('primarySource', {}).get('nodeId')
            if node_id is None:
                continue
            rrf_scores[node_id] = rrf_scores.get(node_id, 0) + 1.0 / (k + rank + 1)
            if node_id not in node_data:
                node_data[node_id] = result
            else:
                # Prefer vector's neighbors (richer graph context)
                vector_neighbors = result.get('metadata', {}).get('firstHopNeighbors', [])
                if vector_neighbors:
                    node_data[node_id]['metadata']['firstHopNeighbors'] = vector_neighbors

        sorted_ids = sorted(rrf_scores, key=rrf_scores.get, reverse=True)
        merged = []
        for nid in sorted_ids:
            r = node_data[nid]
            primary = r.get('metadata', {}).get('primarySource', {})
            primary['score'] = rrf_scores[nid]
            primary['rrf_score'] = rrf_scores[nid]
            merged.append(r)
        return merged
