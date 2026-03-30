"""
BM25 Keyword Retriever for GraphRAG Pipeline
Provides keyword-based retrieval using BM25 algorithm
"""

from typing import List, Dict, Optional
import re
import logging
import os
import pickle
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import rank-bm25, fallback gracefully if not available
try:
    from rank_bm25 import BM25Okapi
    BM25_AVAILABLE = True
except ImportError:
    BM25_AVAILABLE = False
    logger.warning("rank-bm25 not available. BM25 retrieval disabled. Install with: pip install rank-bm25")


class BM25Retriever:
    """
    BM25 keyword-based retriever for GraphRAG

    Uses BM25 algorithm to score nodes based on keyword matching.
    This is particularly effective for:
    - Exact entity names (e.g., "Indian Critical Infrastructure Intrusions")
    - Specific IDs (e.g., "C0043", "T1599")
    - Technical terms that may not match well in vector space
    """

    def __init__(self, driver, config, cache_dir: Optional[str] = None):
        """
        Initialize BM25 Retriever

        Args:
            driver: Neo4j database driver
            config: GraphRAGConfig with retrieval parameters
            cache_dir: Directory to cache BM25 index (default: .cache/bm25_index/)
        """
        if not BM25_AVAILABLE:
            raise ImportError(
                "rank-bm25 is required for BM25 retrieval. "
                "Install it with: pip install rank-bm25"
            )

        self.driver = driver
        self.config = config
        self.bm25_index = None
        self.node_documents = []  # List of (node_id, node_data) tuples
        self._index_built = False

        # Set up cache directory
        if cache_dir is None:
            # Default to .cache/bm25_index/ in the graphrag directory
            # Use parent.parent so cache stays at graphrag/.cache/ (not retrieval/.cache/)
            base_dir = Path(__file__).parent.parent
            cache_dir = str(base_dir / ".cache" / "bm25_index")

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.index_cache_file = self.cache_dir / "bm25_index.pkl"
        self.metadata_cache_file = self.cache_dir / "bm25_metadata.pkl"

    def _tokenize(self, text: str) -> List[str]:
        """
        Tokenize text for BM25 indexing

        Args:
            text: Input text string

        Returns:
            List of lowercase tokens
        """
        if not text:
            return []

        # Convert to lowercase and split on whitespace/punctuation
        text = text.lower()
        # Split on whitespace and common punctuation
        tokens = re.findall(r'\b\w+\b', text)
        return tokens

    def _extract_searchable_text(self, node_type: str, props: Dict) -> str:
        """
        Extract searchable text from node for BM25 indexing

        Uses the shared SEARCHABLE_TEXT_PROPERTIES mapping from utils to ensure
        consistency with embedding extraction.

        Args:
            node_type: Type of node
            props: Node properties dictionary

        Returns:
            Combined searchable text string
        """
        from ..utils import SEARCHABLE_TEXT_PROPERTIES

        properties = SEARCHABLE_TEXT_PROPERTIES.get(node_type, ['label', 'uri'])

        # Extract and combine text
        text_parts = []
        for prop in properties:
            value = props.get(prop)
            if value:
                if isinstance(value, list):
                    text_parts.extend([str(v) for v in value if v])
                else:
                    text_parts.append(str(value))

        # Also include URI for exact matching
        uri = props.get('uri', '')
        if uri:
            text_parts.append(uri)

        return ' '.join(text_parts)

    def _get_database_hash(self) -> str:
        """
        Get a hash of the database state to detect changes

        Returns:
            Hash string representing current database state
        """
        try:
            with self.driver.session() as session:
                # Get count and max node ID as a simple hash
                result = session.run("""
                    MATCH (n)
                    WHERE n.embedding IS NOT NULL
                      AND NOT labels(n)[0] = '_GraphConfig'
                    RETURN count(n) as nodeCount, max(elementId(n)) as maxId
                """)
                record = result.single()
                node_count = record['nodeCount'] if record else 0
                max_id = record['maxId'] if record else 0

                # Create hash from count and max ID
                hash_input = f"{node_count}_{max_id}"
                return hashlib.md5(hash_input.encode()).hexdigest()
        except Exception as e:
            logger.warning("Error computing database hash: %s", e)
            return "unknown"

    def _load_index_from_cache(self) -> bool:
        """
        Load BM25 index from disk cache if available and valid

        Returns:
            True if index was loaded successfully, False otherwise
        """
        try:
            if not self.index_cache_file.exists() or not self.metadata_cache_file.exists():
                logger.info("[BM25] No cached index found")
                return False

            # Load metadata first to check validity
            with open(self.metadata_cache_file, 'rb') as f:
                metadata = pickle.load(f)

            # Check if database has changed
            current_hash = self._get_database_hash()
            if metadata.get('database_hash') != current_hash:
                logger.info("[BM25] Database changed, cache invalid")
                return False

            # Load index and documents
            logger.info("Loading BM25 index from cache...")
            with open(self.index_cache_file, 'rb') as f:
                cache_data = pickle.load(f)

            self.bm25_index = cache_data['index']
            self.node_documents = cache_data['node_documents']
            self._index_built = True

            node_count = len(self.node_documents)
            logger.info("Index loaded from cache: %d nodes", node_count)
            logger.info("BM25 index loaded from cache: %d nodes", node_count)
            return True

        except Exception as e:
            logger.warning("Error loading cache: %s", e)
            logger.warning("Error loading BM25 cache, will rebuild: %s", e)
            return False

    def _save_index_to_cache(self):
        """Save BM25 index to disk cache"""
        try:
            if not self._index_built or not self.bm25_index:
                logger.warning("[BM25] Cannot save: index not built")
                return

            logger.info("Saving BM25 index to cache...")

            # Save index and documents
            cache_data = {
                'index': self.bm25_index,
                'node_documents': self.node_documents
            }

            with open(self.index_cache_file, 'wb') as f:
                pickle.dump(cache_data, f)

            # Save metadata (database hash for validation)
            metadata = {
                'database_hash': self._get_database_hash(),
                'node_count': len(self.node_documents),
                'version': '1.0'
            }

            with open(self.metadata_cache_file, 'wb') as f:
                pickle.dump(metadata, f)

            logger.info("Index saved to cache: %s", self.index_cache_file)
            logger.info("BM25 index saved to cache")

        except Exception as e:
            logger.error("Error saving cache: %s", e)
            logger.warning("Could not save BM25 index to cache: %s", e)

    def build_index(self, max_nodes: Optional[int] = None, force_rebuild: bool = False):
        """
        Build BM25 index from Neo4j nodes

        Fetches all nodes with embeddings and builds a searchable index.
        Tries to load from cache first if available.

        Args:
            max_nodes: Maximum number of nodes to index (None = all nodes)
            force_rebuild: If True, rebuild even if cache exists
        """
        if self._index_built and not force_rebuild:
            logger.info("[BM25] Index already built, skipping rebuild")
            return

        # Try to load from cache first
        if not force_rebuild:
            if self._load_index_from_cache():
                return

        logger.info("[BM25] Building BM25 index from Neo4j nodes...")
        logger.info("Fetching nodes from Neo4j (this may take a moment)...")

        try:
            with self.driver.session() as session:
                # Fetch all nodes with embeddings (same as vector search uses)
                query = """
                    MATCH (n)
                    WHERE n.embedding IS NOT NULL
                      AND NOT labels(n)[0] = '_GraphConfig'
                WITH n, [label IN labels(n) WHERE label <> 'Resource'][0] as nodeType
                RETURN elementId(n) as nodeId, nodeType, properties(n) as props
                ORDER BY nodeId
                """

                if max_nodes:
                    query += f" LIMIT {max_nodes}"

                logger.info("Executing query to fetch nodes...")
                result = session.run(query)

                documents = []
                node_data_list = []
                count = 0

                logger.info("Processing nodes...")
                for record in result:
                    count += 1
                    if count % 1000 == 0:
                        logger.info("Processed %d nodes...", count)

                    node_id = record['nodeId']
                    node_type = record['nodeType']
                    props = record['props']

                    # Extract searchable text
                    searchable_text = self._extract_searchable_text(node_type, props)

                    if searchable_text.strip():
                        # Tokenize for BM25
                        tokens = self._tokenize(searchable_text)
                        documents.append(tokens)
                        # Strip embedding vector from props to reduce cache size
                        # (BM25 only needs text, embeddings waste ~80-90% of cache space)
                        props_slim = {k: v for k, v in props.items() if k != 'embedding'}
                        node_data_list.append({
                            'nodeId': node_id,
                            'nodeType': node_type,
                            'props': props_slim,
                            'searchableText': searchable_text
                        })

                logger.info("Fetched %d nodes, %d with searchable text", count, len(documents))

                if not documents:
                    logger.warning("[BM25] No documents found to index")
                    return

                # Build BM25 index
                logger.info("Building BM25 index from %d documents...", len(documents))
                self.bm25_index = BM25Okapi(documents)
                self.node_documents = node_data_list

                self._index_built = True
                logger.info("Index built with %d nodes", len(documents))
                logger.info("BM25 index built successfully with %d nodes", len(documents))

                # Save to cache
                self._save_index_to_cache()

        except Exception as e:
            logger.error("Error building BM25 index: %s", e, exc_info=True)
            raise

    def search(
        self,
        query: str,
        top_k: int = 10,
        node_type_filter: Optional[str] = None
    ) -> List[Dict]:
        """
        Search nodes using BM25 keyword matching

        Args:
            query: Search query string
            top_k: Number of top results to return
            node_type_filter: Optional node type to filter by (e.g., 'UcoexCAMPAIGNS')

        Returns:
            List of node dictionaries with BM25 scores
        """
        if not self._index_built or not self.bm25_index:
            logger.info("[BM25] Index not built, building now (will try cache first)...")
            self.build_index()

        if not self.bm25_index:
            logger.error("[BM25] Failed to build index")
            return []

        # Tokenize query
        query_tokens = self._tokenize(query)

        if not query_tokens:
            logger.warning("[BM25] Query has no tokens after tokenization")
            return []

        # Get BM25 scores for all documents
        scores = self.bm25_index.get_scores(query_tokens)

        # Create list of (score, node_data) tuples
        scored_nodes = []
        for i, (score, node_data) in enumerate(zip(scores, self.node_documents)):
            # Apply node type filter if specified
            if node_type_filter and node_data['nodeType'] != node_type_filter:
                continue

            scored_nodes.append({
                'nodeId': node_data['nodeId'],
                'nodeType': node_data['nodeType'],
                'props': node_data['props'],
                'bm25Score': float(score),
                'searchableText': node_data['searchableText']
            })

        # Sort by score (descending) and return top_k
        scored_nodes.sort(key=lambda x: x['bm25Score'], reverse=True)

        logger.info("Found %d results, returning top %d", len(scored_nodes), min(top_k, len(scored_nodes)))

        return scored_nodes[:top_k]

    def search_and_format(
        self,
        query: str,
        top_k: int = 10,
        hop_depth: int = 0
    ) -> List[Dict]:
        """
        Search nodes and format results to match GraphRetriever output format.
        Uses batched Cypher queries for neighbor fetching (1-2 queries total
        instead of N+1).

        Args:
            query: Search query string
            top_k: Number of results to return
            hop_depth: Graph traversal depth (0 = no neighbors, 1 = 1-hop, 2 = 2-hop)

        Returns:
            List of formatted items matching GraphRetriever format
        """
        from ..utils import get_node_label, get_node_content

        bm25_results = self.search(query, top_k=top_k * 2)
        if not bm25_results:
            return []

        results = bm25_results[:top_k]

        # Batch-fetch all neighbors in 1-2 queries instead of N+1
        neighbors_map = {}
        if hop_depth > 0:
            node_ids = [r['nodeId'] for r in results]
            neighbors_map = self._get_neighbors_batch(node_ids, hop_depth)

        formatted_items = []
        for result in results:
            node_id = result['nodeId']
            node_type = result['nodeType']
            props = result['props']
            bm25_score = result['bm25Score']

            display_label = get_node_label(node_type, props)
            node_content = get_node_content(node_type, props)

            item = {
                'content': node_content,
                'metadata': {
                    'primarySource': {
                        'nodeId': node_id,
                        'nodeLabel': display_label,
                        'nodeType': node_type,
                        'nodeContent': node_content,
                        'embedding': props.get('embedding'),
                        'initialScore': bm25_score,
                        'score': bm25_score,
                        'allProperties': props
                    },
                    'firstHopNeighbors': neighbors_map.get(node_id, [])
                }
            }
            formatted_items.append(item)

        return formatted_items

    def _get_neighbors_batch(self, node_ids: List[str], hop_depth: int) -> Dict[str, List[Dict]]:
        """
        Batch-fetch graph neighbors for multiple nodes in 1-2 Cypher queries
        (replacing the previous N+1 pattern).

        Args:
            node_ids: List of Neo4j element IDs to fetch neighbors for
            hop_depth: Depth of traversal (1 or 2)

        Returns:
            Dict mapping element_id -> list of neighbor dicts
        """
        from collections import defaultdict
        from ..utils import get_node_label, get_node_content

        if not node_ids or hop_depth < 1:
            return {}

        neighbors_by_node = defaultdict(list)

        with self.driver.session() as session:
            result = session.run("""
                UNWIND $node_ids AS nid
                MATCH (n)-[r]-(neighbor)
                WHERE elementId(n) = nid AND neighbor.embedding IS NOT NULL
                RETURN nid as primaryNodeId,
                       type(r) as relType,
                       elementId(neighbor) as neighborId,
                       labels(neighbor) as neighborLabels,
                       properties(neighbor) as neighborProps
            """, node_ids=node_ids)

            for record in result:
                primary_id = record['primaryNodeId']
                if len(neighbors_by_node[primary_id]) >= self.config.max_neighbors_per_node:
                    continue

                nb_labels = record['neighborLabels']
                nb_props = record['neighborProps']
                node_type = [l for l in nb_labels if l != 'Resource'][0] if nb_labels else 'Unknown'

                neighbors_by_node[primary_id].append({
                    'relationshipType': record['relType'],
                    'primaryNode': {
                        'nodeId': record['neighborId'],
                        'nodeLabel': get_node_label(node_type, nb_props),
                        'nodeType': node_type,
                        'nodeContent': get_node_content(node_type, nb_props),
                        'embedding': nb_props.get('embedding'),
                        'allProperties': nb_props
                    }
                })

        # Fetch 2-hop neighbors in a second batched query
        if hop_depth >= 2:
            all_neighbor_ids = set()
            for neighbors in neighbors_by_node.values():
                for nb in neighbors:
                    all_neighbor_ids.add(nb['primaryNode']['nodeId'])

            if all_neighbor_ids:
                second_hop_map = self._get_second_hop_batch(
                    list(all_neighbor_ids), set(node_ids)
                )
                for neighbors in neighbors_by_node.values():
                    for nb in neighbors:
                        nb_id = nb['primaryNode']['nodeId']
                        nb['secondHopNeighbors'] = second_hop_map.get(nb_id, [])

        return dict(neighbors_by_node)

    def _get_second_hop_batch(
        self, neighbor_ids: List[str], exclude_ids: set
    ) -> Dict[str, List[Dict]]:
        """
        Batch-fetch 2-hop neighbors for multiple 1-hop neighbor nodes.

        Args:
            neighbor_ids: List of 1-hop neighbor element IDs
            exclude_ids: Set of primary element IDs to exclude from 2-hop results

        Returns:
            Dict mapping element_id -> list of 2-hop neighbor dicts
        """
        from collections import defaultdict
        from ..utils import get_node_label, get_node_content

        second_hop_map = defaultdict(list)

        with self.driver.session() as session:
            result = session.run("""
                UNWIND $neighbor_ids AS nid
                MATCH (n)-[r2]-(secondHop)
                WHERE elementId(n) = nid
                  AND secondHop.embedding IS NOT NULL
                  AND NOT elementId(secondHop) IN $exclude_ids
                RETURN nid as firstHopId,
                       type(r2) as relType,
                       elementId(secondHop) as secondHopId,
                       labels(secondHop) as secondHopLabels,
                       properties(secondHop) as secondHopProps
            """, neighbor_ids=neighbor_ids, exclude_ids=list(exclude_ids))

            for record in result:
                first_hop_id = record['firstHopId']
                if len(second_hop_map[first_hop_id]) >= self.config.max_second_hop_per_first:
                    continue

                sh_labels = record['secondHopLabels']
                sh_props = record['secondHopProps']
                node_type = [l for l in sh_labels if l != 'Resource'][0] if sh_labels else 'Unknown'

                second_hop_map[first_hop_id].append({
                    'relationshipType': record['relType'],
                    'relatedNode': {
                        'nodeId': record['secondHopId'],
                        'nodeLabel': get_node_label(node_type, sh_props),
                        'nodeType': node_type,
                        'nodeContent': get_node_content(node_type, sh_props),
                        'allProperties': sh_props
                    }
                })

        return dict(second_hop_map)
