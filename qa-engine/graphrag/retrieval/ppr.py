"""
Personalized PageRank (PPR) Retriever for GraphRAG Pipeline

Replaces fixed-depth BFS neighbor selection with importance-weighted,
variable-depth traversal. Seeds from vector-matched nodes and propagates
relevance through the graph using PPR with inverse-degree edge weighting
to handle hub nodes.
"""

import logging
import os
import pickle
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import sparse

from ..utils import GraphRAGConfig, get_node_label, get_node_content

logger = logging.getLogger(__name__)


class PPRGraphProjection:
    """
    Loads and caches the graph structure in memory as a scipy sparse matrix.

    The projection stores:
    - Weighted adjacency matrix (CSR format, column-normalized)
    - Node metadata (type, properties) indexed by integer position
    - Mapping between Neo4j element IDs and integer indices
    """

    def __init__(self, driver, config: GraphRAGConfig, cache_dir: Optional[str] = None):
        self.driver = driver
        self.config = config

        # Graph data (populated by load_graph)
        self.adj_matrix: Optional[sparse.csr_matrix] = None
        self.node_count: int = 0
        self.id_to_idx: Dict[str, int] = {}
        self.idx_to_id: Dict[int, str] = {}
        self.node_metadata: Dict[int, Dict] = {}  # idx -> {nodeType, props}
        self.node_degrees: Optional[np.ndarray] = None

        # Cache setup — use parent.parent so cache stays at graphrag/.cache/
        if cache_dir is None:
            base_dir = Path(__file__).parent.parent
            cache_dir = str(base_dir / ".cache" / "ppr_graph")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.graph_cache_file = self.cache_dir / "ppr_graph.pkl"
        self.metadata_cache_file = self.cache_dir / "ppr_metadata.pkl"

    def load_graph(self):
        """Load graph from cache or Neo4j. Returns True on success."""
        if self._load_from_cache():
            return True

        logger.info("[PPR] Building graph projection from Neo4j...")
        try:
            self._build_from_neo4j()
            self._save_to_cache()
            return True
        except Exception as e:
            logger.error("[PPR] Failed to build graph projection: %s", e, exc_info=True)
            return False

    # ---- Cache management ----

    def _get_database_hash(self) -> str:
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (n)
                    WHERE n.embedding IS NOT NULL
                      AND NOT labels(n)[0] = '_GraphConfig'
                    RETURN count(n) as nodeCount, max(elementId(n)) as maxId
                """)
                record = result.single()
                node_count = record['nodeCount'] if record else 0
                max_id = record['maxId'] if record else 0
                hash_input = f"{node_count}_{max_id}"
                return hashlib.md5(hash_input.encode()).hexdigest()
        except Exception as e:
            logger.warning("[PPR] Error computing database hash: %s", e)
            return "unknown"

    def _load_from_cache(self) -> bool:
        try:
            if not self.graph_cache_file.exists() or not self.metadata_cache_file.exists():
                logger.info("[PPR] No cached graph projection found")
                return False

            with open(self.metadata_cache_file, 'rb') as f:
                cache_meta = pickle.load(f)

            current_hash = self._get_database_hash()
            cached_strategy = cache_meta.get('edge_weight_strategy')
            if cache_meta.get('database_hash') != current_hash:
                logger.info("[PPR] Database changed, cache invalid")
                return False
            if cached_strategy != self.config.ppr_edge_weight_strategy:
                logger.info("[PPR] Edge weight strategy changed (%s -> %s), cache invalid",
                            cached_strategy, self.config.ppr_edge_weight_strategy)
                return False

            logger.info("[PPR] Loading graph projection from cache...")
            with open(self.graph_cache_file, 'rb') as f:
                cache_data = pickle.load(f)

            self.adj_matrix = cache_data['adj_matrix']
            self.node_count = cache_data['node_count']
            self.id_to_idx = cache_data['id_to_idx']
            self.idx_to_id = cache_data['idx_to_id']
            self.node_metadata = cache_data['node_metadata']
            self.node_degrees = cache_data['node_degrees']

            logger.info("[PPR] Graph projection loaded from cache: %d nodes, %d edges",
                        self.node_count, self.adj_matrix.nnz)
            return True
        except Exception as e:
            logger.warning("[PPR] Error loading cache, will rebuild: %s", e)
            return False

    def _save_to_cache(self):
        try:
            cache_data = {
                'adj_matrix': self.adj_matrix,
                'node_count': self.node_count,
                'id_to_idx': self.id_to_idx,
                'idx_to_id': self.idx_to_id,
                'node_metadata': self.node_metadata,
                'node_degrees': self.node_degrees,
            }
            with open(self.graph_cache_file, 'wb') as f:
                pickle.dump(cache_data, f)

            meta = {
                'database_hash': self._get_database_hash(),
                'node_count': self.node_count,
                'edge_count': self.adj_matrix.nnz,
                'edge_weight_strategy': self.config.ppr_edge_weight_strategy,
                'version': '1.0',
            }
            with open(self.metadata_cache_file, 'wb') as f:
                pickle.dump(meta, f)

            logger.info("[PPR] Graph projection saved to cache")
        except Exception as e:
            logger.warning("[PPR] Could not save graph projection to cache: %s", e)

    # ---- Graph building ----

    def _build_from_neo4j(self):
        """Fetch nodes and edges from Neo4j and build weighted adjacency matrix."""
        with self.driver.session() as session:
            # 1. Fetch all nodes with embeddings
            logger.info("[PPR] Fetching nodes from Neo4j...")
            node_result = session.run("""
                MATCH (n)
                WHERE n.embedding IS NOT NULL
                  AND NOT labels(n)[0] = '_GraphConfig'
                WITH n, [label IN labels(n) WHERE label <> 'Resource'][0] as nodeType
                RETURN elementId(n) as nodeId, nodeType, properties(n) as props
            """)

            idx = 0
            for record in node_result:
                node_id = record['nodeId']
                node_type = record['nodeType']
                props = record['props']

                # Strip embedding to reduce memory
                props_slim = {k: v for k, v in props.items() if k != 'embedding'}

                self.id_to_idx[node_id] = idx
                self.idx_to_id[idx] = node_id
                self.node_metadata[idx] = {
                    'nodeType': node_type,
                    'props': props_slim,
                }
                idx += 1

            self.node_count = idx
            logger.info("[PPR] Loaded %d nodes", self.node_count)

            if self.node_count == 0:
                logger.warning("[PPR] No nodes found")
                self.adj_matrix = sparse.csr_matrix((0, 0))
                self.node_degrees = np.array([])
                return

            # 2. Fetch all edges between indexed nodes
            logger.info("[PPR] Fetching edges from Neo4j...")
            edge_result = session.run("""
                MATCH (a)-[r]-(b)
                WHERE a.embedding IS NOT NULL AND b.embedding IS NOT NULL
                  AND NOT labels(a)[0] = '_GraphConfig'
                  AND NOT labels(b)[0] = '_GraphConfig'
                RETURN DISTINCT elementId(a) as srcId, elementId(b) as tgtId
            """)

            rows = []
            cols = []
            for record in edge_result:
                src_id = record['srcId']
                tgt_id = record['tgtId']
                if src_id in self.id_to_idx and tgt_id in self.id_to_idx:
                    rows.append(self.id_to_idx[src_id])
                    cols.append(self.id_to_idx[tgt_id])

            logger.info("[PPR] Loaded %d directed edges", len(rows))

        # Build adjacency matrix
        self._build_weighted_adjacency(rows, cols)

    def _build_weighted_adjacency(self, rows: List[int], cols: List[int]):
        """
        Build column-normalized weighted adjacency matrix.

        Edge weighting strategies:
        - "uniform": all edges weight 1
        - "inv_degree": weight = 1/degree(target) — strong hub suppression
        - "inv_sqrt_degree": weight = 1/sqrt(degree(target)) — moderate hub suppression
        """
        n = self.node_count
        if not rows:
            self.adj_matrix = sparse.csr_matrix((n, n))
            self.node_degrees = np.zeros(n)
            return

        rows_arr = np.array(rows, dtype=np.int32)
        cols_arr = np.array(cols, dtype=np.int32)

        # Compute node degrees (undirected: count both directions)
        degree_counts = np.zeros(n, dtype=np.float64)
        for c in cols_arr:
            degree_counts[c] += 1
        self.node_degrees = degree_counts

        # Compute edge weights based on strategy
        strategy = self.config.ppr_edge_weight_strategy
        if strategy == "uniform":
            weights = np.ones(len(rows_arr), dtype=np.float64)
        elif strategy == "inv_degree":
            weights = np.array([
                1.0 / max(degree_counts[c], 1.0) for c in cols_arr
            ], dtype=np.float64)
        elif strategy == "inv_sqrt_degree":
            weights = np.array([
                1.0 / max(np.sqrt(degree_counts[c]), 1.0) for c in cols_arr
            ], dtype=np.float64)
        else:
            logger.warning("[PPR] Unknown edge weight strategy '%s', using uniform", strategy)
            weights = np.ones(len(rows_arr), dtype=np.float64)

        # Build sparse matrix (rows=target, cols=source for column-stochastic form)
        # A[i,j] = weight of edge j->i, so matrix-vector multiply propagates correctly
        raw = sparse.coo_matrix((weights, (cols_arr, rows_arr)), shape=(n, n))
        raw = raw.tocsc()

        # Column-normalize to make stochastic
        col_sums = np.array(raw.sum(axis=0)).flatten()
        col_sums[col_sums == 0] = 1.0  # avoid division by zero for dangling nodes
        diag_inv = sparse.diags(1.0 / col_sums)
        self.adj_matrix = (raw @ diag_inv).tocsr()

        logger.info("[PPR] Adjacency matrix built: %d nodes, %d edges, strategy=%s",
                    n, self.adj_matrix.nnz, strategy)


class PPRRetriever:
    """
    Computes Personalized PageRank from seed nodes and selects
    structurally important neighbors ranked by PPR score.

    Outputs the same {primarySource, firstHopNeighbors} format
    expected by downstream reranking and generation stages.
    """

    def __init__(self, graph_projection: PPRGraphProjection, config: GraphRAGConfig):
        self.graph = graph_projection
        self.config = config

    def select_neighbors(self, seed_items: List[Dict], hop_depth: int) -> List[Dict]:
        """
        Main entry point: enrich seed items with PPR-ranked neighbors.

        Args:
            seed_items: Normalized retrieval items (flat format with primarySource)
            hop_depth: 1 for 1-hop neighbors, 2 for 1-hop + 2-hop

        Returns:
            Same items with firstHopNeighbors populated by PPR ranking
        """
        if not seed_items or hop_depth < 1:
            return seed_items

        # Map seed items to graph indices
        seed_indices = []
        seed_scores = []
        for item in seed_items:
            node_id = item.get('primarySource', {}).get('nodeId')
            if node_id and node_id in self.graph.id_to_idx:
                seed_indices.append(self.graph.id_to_idx[node_id])
                seed_scores.append(item.get('score', 1.0))

        if not seed_indices:
            logger.warning("[PPR] No seed items mapped to graph indices")
            return seed_items

        # Build personalization vector
        personalization = np.zeros(self.graph.node_count, dtype=np.float64)
        for idx, score in zip(seed_indices, seed_scores):
            personalization[idx] = max(score, 0.0)

        total = personalization.sum()
        if total > 0:
            personalization /= total

        # Compute PPR
        ppr_scores = self._compute_ppr(personalization)

        # Build set of seed indices for exclusion
        seed_set = set(seed_indices)

        # Enrich each seed item with PPR-ranked neighbors
        for item in seed_items:
            node_id = item.get('primarySource', {}).get('nodeId')
            if not node_id or node_id not in self.graph.id_to_idx:
                continue

            src_idx = self.graph.id_to_idx[node_id]
            neighbors = self._get_ppr_neighbors(
                src_idx, ppr_scores, hop_depth, seed_set
            )
            item['firstHopNeighbors'] = neighbors

        logger.info("[PPR] Enriched %d seed items with PPR-ranked neighbors (hop_depth=%d)",
                    len(seed_items), hop_depth)
        return seed_items

    def _compute_ppr(self, personalization: np.ndarray) -> np.ndarray:
        """
        Compute PPR via power iteration.

        x_{t+1} = alpha * A @ x_t + (1 - alpha) * v

        Where:
        - A is the column-normalized weighted adjacency matrix
        - v is the personalization vector
        - alpha is the damping factor
        """
        alpha = self.config.ppr_damping
        tol = self.config.ppr_convergence_tol
        max_iter = self.config.ppr_max_iterations
        max_degree = self.config.ppr_max_node_degree

        n = self.graph.node_count
        x = personalization.copy()
        teleport = (1.0 - alpha) * personalization

        # Identify hub nodes to cap
        hub_mask = None
        if self.graph.node_degrees is not None and max_degree > 0:
            hub_mask = self.graph.node_degrees > max_degree

        A = self.graph.adj_matrix

        for iteration in range(max_iter):
            x_new = alpha * A.dot(x) + teleport

            # Hub degree cap: redirect hub node probability to teleport
            if hub_mask is not None and np.any(hub_mask):
                hub_mass = x_new[hub_mask].sum()
                x_new[hub_mask] = teleport[hub_mask]
                # Redistribute hub mass proportionally to personalization
                if hub_mass > 0:
                    x_new += hub_mass * personalization

            # Normalize to prevent drift
            x_sum = x_new.sum()
            if x_sum > 0:
                x_new /= x_sum

            # Check convergence
            diff = np.abs(x_new - x).sum()
            if diff < tol:
                logger.debug("[PPR] Converged after %d iterations (L1=%.2e)", iteration + 1, diff)
                return x_new

            x = x_new

        logger.debug("[PPR] Max iterations (%d) reached (L1=%.2e)", max_iter, diff)
        return x

    def _get_ppr_neighbors(
        self, src_idx: int, ppr_scores: np.ndarray,
        hop_depth: int, seed_set: set
    ) -> List[Dict]:
        """
        Get PPR-ranked neighbors for a single seed node.

        1. Get actual 1-hop neighbors from adjacency matrix
        2. Rank by PPR score, keep top ppr_top_k_neighbors
        3. If hop_depth >= 2: get 2-hop neighbors, rank by PPR
        """
        top_k_1hop = self.config.ppr_top_k_neighbors
        top_k_2hop = self.config.ppr_top_k_second_hop
        min_score = self.config.ppr_min_score_threshold

        # Get 1-hop neighbors from adjacency (row of transposed = col of A)
        # Our matrix A[i,j] means edge j->i, so neighbors of src are non-zero in row src
        adj_row = self.graph.adj_matrix.getrow(src_idx)
        neighbor_indices = adj_row.indices

        if len(neighbor_indices) == 0:
            return []

        # Score and rank 1-hop neighbors
        neighbor_scores = [(idx, ppr_scores[idx]) for idx in neighbor_indices
                           if idx not in seed_set and ppr_scores[idx] >= min_score]
        neighbor_scores.sort(key=lambda x: x[1], reverse=True)
        top_neighbors = neighbor_scores[:top_k_1hop]

        result = []
        for nb_idx, nb_score in top_neighbors:
            neighbor_dict = self._format_neighbor(src_idx, nb_idx, nb_score)
            if neighbor_dict is None:
                continue

            # 2-hop neighbors
            if hop_depth >= 2:
                second_hops = self._get_second_hop_ppr(
                    nb_idx, ppr_scores, seed_set, {src_idx} | {n[0] for n in top_neighbors},
                    top_k_2hop, min_score
                )
                neighbor_dict['secondHopNeighbors'] = second_hops

            result.append(neighbor_dict)

        return result

    def _get_second_hop_ppr(
        self, first_hop_idx: int, ppr_scores: np.ndarray,
        seed_set: set, exclude_set: set,
        top_k: int, min_score: float
    ) -> List[Dict]:
        """Get PPR-ranked 2-hop neighbors for a 1-hop node."""
        adj_row = self.graph.adj_matrix.getrow(first_hop_idx)
        sh_indices = adj_row.indices

        if len(sh_indices) == 0:
            return []

        # Exclude seeds and 1-hop nodes
        combined_exclude = seed_set | exclude_set | {first_hop_idx}
        sh_scores = [(idx, ppr_scores[idx]) for idx in sh_indices
                     if idx not in combined_exclude and ppr_scores[idx] >= min_score]
        sh_scores.sort(key=lambda x: x[1], reverse=True)

        result = []
        for sh_idx, sh_score in sh_scores[:top_k]:
            sh_dict = self._format_second_hop(first_hop_idx, sh_idx, sh_score)
            if sh_dict is not None:
                result.append(sh_dict)

        return result

    def _format_neighbor(self, src_idx: int, nb_idx: int, ppr_score: float) -> Optional[Dict]:
        """Format a 1-hop neighbor into the expected dict structure."""
        meta = self.graph.node_metadata.get(nb_idx)
        if meta is None:
            return None

        node_type = meta['nodeType']
        props = meta['props']

        # Infer relationship type from adjacency (not available in projection)
        # Use a generic label; the cross-encoder reranker doesn't depend on rel type
        return {
            'relationshipType': 'GRAPH_EDGE',
            'primaryNode': {
                'nodeId': self.graph.idx_to_id[nb_idx],
                'nodeLabel': get_node_label(node_type, props),
                'nodeType': node_type,
                'nodeContent': get_node_content(node_type, props),
                'pprScore': float(ppr_score),
                'allProperties': props,
            },
        }

    def _format_second_hop(self, first_hop_idx: int, sh_idx: int, ppr_score: float) -> Optional[Dict]:
        """Format a 2-hop neighbor into the expected dict structure."""
        meta = self.graph.node_metadata.get(sh_idx)
        if meta is None:
            return None

        node_type = meta['nodeType']
        props = meta['props']

        return {
            'relationshipType': 'GRAPH_EDGE',
            'relatedNode': {
                'nodeId': self.graph.idx_to_id[sh_idx],
                'nodeLabel': get_node_label(node_type, props),
                'nodeType': node_type,
                'nodeContent': get_node_content(node_type, props),
                'pprScore': float(ppr_score),
                'allProperties': props,
            },
        }
