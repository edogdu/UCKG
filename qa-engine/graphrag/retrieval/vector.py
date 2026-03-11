"""
Retrieval Module for GraphRAG Pipeline
Handles Stages 1 & 2: Semantic search + Graph traversal
"""

import logging
from typing import List, Dict, Any, Optional
from neo4j_graphrag.retrievers import VectorCypherRetriever
from neo4j_graphrag.embeddings import OllamaEmbeddings
from ..utils import GraphRAGConfig, INDEX_NAME, cypher_label_case, cypher_content_case, _LABEL_MAPPING

logger = logging.getLogger(__name__)


class SentenceTransformerEmbeddings:
    """
    Wrapper for sentence-transformers to match neo4j_graphrag embedder interface.
    Supports task-specific prompts (e.g., Retrieval-query, Retrieval-document).
    """

    def __init__(self, model: str, query_prompt: str = "", doc_prompt: str = ""):
        """
        Initialize sentence-transformers embedder.

        Args:
            model: HuggingFace model name (e.g., "google/embeddinggemma-300M")
            query_prompt: Prompt name for queries (e.g., "Retrieval-query")
            doc_prompt: Prompt name for documents (e.g., "Retrieval-document")
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for this embedding backend. "
                "Install with: pip install sentence-transformers"
            )

        self.model = SentenceTransformer(model)
        self.query_prompt = query_prompt if query_prompt else None
        self.doc_prompt = doc_prompt if doc_prompt else None

    def embed_query(self, text: str) -> List[float]:
        """Embed a query string."""
        if self.query_prompt:
            embedding = self.model.encode(text, prompt_name=self.query_prompt)
        else:
            embedding = self.model.encode(text)
        return embedding.tolist()

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple documents."""
        if self.doc_prompt:
            embeddings = self.model.encode(texts, prompt_name=self.doc_prompt)
        else:
            embeddings = self.model.encode(texts)
        return [e.tolist() for e in embeddings]


def create_embedder(config: GraphRAGConfig):
    """
    Factory function to create the appropriate embedder based on config.

    Args:
        config: GraphRAGConfig with embedding settings

    Returns:
        Embedder instance (OllamaEmbeddings or SentenceTransformerEmbeddings)
    """
    backend = config.embedding_backend.lower()

    if backend == "ollama":
        logger.info("Using Ollama embedder: %s", config.embedding_model)
        return OllamaEmbeddings(model=config.embedding_model)

    elif backend == "sentence_transformers":
        logger.info("Using Sentence-Transformers embedder: %s", config.embedding_model)
        if config.embedding_query_prompt:
            logger.info("Embedder query prompt: %s", config.embedding_query_prompt)
        return SentenceTransformerEmbeddings(
            model=config.embedding_model,
            query_prompt=config.embedding_query_prompt,
            doc_prompt=config.embedding_doc_prompt
        )

    else:
        raise ValueError(f"Unknown embedding backend: {backend}. Use 'ollama' or 'sentence_transformers'")


class GraphRetriever:
    """
    Handles Stages 1 & 2: Semantic search + Graph traversal

    Stage 1: Vector similarity search to find initial candidate nodes
    Stage 2: Graph traversal to enrich each candidate with 1-hop neighbors (and optionally 2-hop)
    """

    def __init__(self, driver, config: GraphRAGConfig):
        """
        Initialize the GraphRetriever

        Args:
            driver: Neo4j database driver
            config: GraphRAGConfig with retrieval parameters
        """
        self.driver = driver
        self.config = config
        self.embedder = create_embedder(config)
        self._current_hop_depth = 1  # Default to 1-hop

    @property
    def _include_embedding(self) -> bool:
        """Whether Cypher queries should fetch embedding vectors (needed only for legacy reranker)."""
        return not self.config.enable_cross_encoder

    @property
    def _include_neighbor_embedding(self) -> bool:
        """Whether to include neighbor embeddings in Cypher.
        Needed for legacy reranker (cosine similarity) OR similarity-ordered neighbor selection."""
        return not self.config.enable_cross_encoder or self.config.enable_similarity_neighbor_ordering

    def retrieve(self, query: str, top_k: int, hop_depth: int = None) -> List[Dict]:
        """
        Execute combined semantic search + graph traversal

        Args:
            query: User query string
            top_k: Number of results to return
            hop_depth: Graph traversal depth (0=semantic only, 1=1-hop, 2=2-hop)
                      If None, uses config.enable_second_hop

        Returns:
            List of items with primary nodes and their graph neighbors
        """
        # Set hop depth
        if hop_depth is not None:
            self._current_hop_depth = hop_depth
        else:
            self._current_hop_depth = 2 if self.config.enable_second_hop else 1

        # Fetch extra candidates for reranking stage (if > 0-hop)
        if self._current_hop_depth == 0:
            initial_top_k = top_k  # No reranking, fetch exactly what we need
        else:
            initial_top_k = top_k * self.config.initial_top_k_multiplier

        logger.info("Executing %d-hop retrieval (fetching %d candidates)", self._current_hop_depth, initial_top_k)

        # Build and execute query
        retrieval_query = self._build_query()
        retriever = VectorCypherRetriever(
            driver=self.driver,
            index_name=INDEX_NAME,
            retrieval_query=retrieval_query,
            embedder=self.embedder,
            result_formatter=lambda rec: rec["item"]
        )

        # Handle query preprocessing based on backend
        # - Ollama: Add prefix (e.g., "search_query: " for nomic-embed-text)
        # - Sentence-transformers: No prefix needed (uses prompt_name internally)
        if self.config.embedding_backend == "ollama" and self.config.embedding_query_prefix:
            processed_query = f"{self.config.embedding_query_prefix}{query}"
        else:
            processed_query = query
        results = retriever.search(query_text=processed_query, top_k=initial_top_k)

        # Convert to list format
        if hasattr(results, 'items'):
            result_list = []
            for item in results.items:
                if hasattr(item, '__dict__'):
                    result_dict = item.__dict__
                elif hasattr(item, 'content') and hasattr(item, 'metadata'):
                    result_dict = {
                        'content': item.content,
                        'metadata': item.metadata,
                        'score': getattr(item, 'score', 0.0)
                    }
                else:
                    result_dict = item
                result_list.append(result_dict)
        elif hasattr(results, 'results'):
            result_list = list(results.results)
        else:
            result_list = []

        # Apply similarity-ordered neighbor selection if enabled
        if (self.config.enable_similarity_neighbor_ordering
                and self._current_hop_depth > 0
                and result_list):
            query_embedding = self.embedder.embed_query(processed_query)
            result_list = self._sort_neighbors_by_similarity(result_list, query_embedding)

        return result_list

    def _build_query(self) -> str:
        """Build Cypher query based on current hop depth"""
        if self._current_hop_depth == 0:
            return self._build_zero_hop_query()
        elif self._current_hop_depth == 1:
            return self._build_one_hop_query()
        else:  # 2-hop
            return self._build_two_hop_query()

    def _build_zero_hop_query(self) -> str:
        """
        Build 0-hop query: Semantic search only (no graph traversal)

        Returns structured data compatible with VectorCypherRetriever format.
        Embeddings are never included since reranking is skipped for 0-hop.
        """
        type_expr = "nodeType"
        label_case = cypher_label_case('allNodeProperties', type_expr)
        content_case = cypher_content_case('allNodeProperties', type_expr, primary=True)

        return """
            // STAGE 1: Semantic search only (no graph traversal for 0-hop)
            WITH node, score,
                elementId(node) as nodeId,
                labels(node) as nodeLabels,
                properties(node) as allNodeProperties,
                [label IN labels(node) WHERE label <> 'Resource'][0] as nodeType

            // Extract node label and content based on type
            WITH nodeId, nodeLabels, allNodeProperties, nodeType, score,
                %(label_case)s as displayLabel,
                %(content_case)s as nodeContent

            // Return structured data matching VectorCypherRetriever format
            RETURN {
                content: nodeContent,
                metadata: {
                    primarySource: {
                        nodeId: nodeId,
                        nodeLabel: displayLabel,
                        nodeType: nodeType,
                        nodeContent: nodeContent,
                        initialScore: score,
                        score: score,
                        allProperties: allNodeProperties
                    },
                    firstHopNeighbors: []
                }
            } as item
        """ % {
            'label_case': label_case,
            'content_case': content_case,
        }

    def _build_one_hop_query(self) -> str:
        """Build 1-hop query: Semantic search + 1-hop neighbors"""
        nb_type = "[label IN labels(neighbor) WHERE label <> 'Resource'][0]"
        nb_label = cypher_label_case('neighbor', nb_type)
        nb_content = cypher_content_case('neighbor', nb_type, primary=False)

        emb_with = "node.embedding as nodeEmbedding,\n                " if self._include_embedding else ""
        emb_carry = "nodeEmbedding, " if self._include_embedding else ""
        nb_emb = "embedding: neighbor.embedding,\n                         " if self._include_neighbor_embedding else ""
        max_nb = (self.config.max_neighbors_per_node * self.config.similarity_neighbor_fetch_multiplier
                  if self.config.enable_similarity_neighbor_ordering
                  else self.config.max_neighbors_per_node)

        query = """
            // STAGE 1: Semantic search (node, score from vector index)
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k

            // STAGE 2: Extract primary node properties BEFORE traversal
            WITH node, score,
                elementId(node) as nodeId,
                labels(node) as nodeLabels,
                %(emb_with)sproperties(node) as allNodeProperties

            // STAGE 2: Graph traversal - get 1-hop neighbors
            OPTIONAL MATCH (node)-[r]-(neighbor)
            WHERE neighbor.embedding IS NOT NULL

            // Aggregate 1-hop neighbors
            WITH nodeId, nodeLabels, %(emb_carry)sallNodeProperties, score,
                 collect(DISTINCT {
                     relationshipType: type(r),
                     primaryNode: {
                         nodeId: elementId(neighbor),
                         nodeLabel: %(nb_label)s,
                         nodeType: %(nb_type)s,
                         nodeContent: %(nb_content)s,
                         %(nb_emb)sallProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                     }
                 })[..%(max_nb)s] as neighbors
        """ % {
            'emb_with': emb_with,
            'emb_carry': emb_carry,
            'nb_label': nb_label,
            'nb_type': nb_type,
            'nb_content': nb_content,
            'nb_emb': nb_emb,
            'max_nb': max_nb,
        }

        query += self._build_final_return_section()
        return query

    def _build_two_hop_query(self) -> str:
        """Build 2-hop query: Semantic search + 1-hop + 2-hop neighbors"""
        nb_type = "[label IN labels(neighbor) WHERE label <> 'Resource'][0]"
        sh_type = "[label IN labels(secondHop) WHERE label <> 'Resource'][0]"
        nb_label = cypher_label_case('neighbor', nb_type)
        nb_content = cypher_content_case('neighbor', nb_type, primary=False)
        sh_label = cypher_label_case('secondHop', sh_type)
        sh_content = cypher_content_case('secondHop', sh_type, primary=False)

        emb_with = "node.embedding as nodeEmbedding,\n                " if self._include_embedding else ""
        emb_carry = "nodeEmbedding, " if self._include_embedding else ""
        nb_emb = "embedding: neighbor.embedding,\n                         " if self._include_neighbor_embedding else ""
        multiplier = self.config.similarity_neighbor_fetch_multiplier if self.config.enable_similarity_neighbor_ordering else 1
        max_sh = self.config.max_second_hop_per_first * multiplier
        max_nb = self.config.max_neighbors_per_node * multiplier

        query = """
            // STAGE 1: Semantic search (node, score from vector index)
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k

            // STAGE 2: Extract primary node properties BEFORE traversal
            WITH node, score,
                elementId(node) as nodeId,
                labels(node) as nodeLabels,
                %(emb_with)sproperties(node) as allNodeProperties

            // STAGE 2: Graph traversal - get 1-hop neighbors
            OPTIONAL MATCH (node)-[r]-(neighbor)
            WHERE neighbor.embedding IS NOT NULL

            // STAGE 2 (Extended): Get 2-hop neighbors
            OPTIONAL MATCH (neighbor)-[r2]-(secondHop)
            WHERE secondHop.embedding IS NOT NULL
                AND elementId(secondHop) <> nodeId  // Don't go back to primary node

            // Aggregate 2-hop neighbors per 1-hop neighbor
            WITH nodeId, nodeLabels, %(emb_carry)sallNodeProperties, score,
                 neighbor, r,
                 [item IN collect(DISTINCT {
                     relationshipType: type(r2),
                     relatedNode: {
                         nodeId: elementId(secondHop),
                         nodeLabel: %(sh_label)s,
                         nodeType: %(sh_type)s,
                         nodeContent: %(sh_content)s,
                         allProperties: CASE WHEN secondHop IS NOT NULL THEN properties(secondHop) ELSE {} END
                     }
                 }) WHERE item.relatedNode.nodeId IS NOT NULL][..%(max_sh)s] as secondHopNeighbors

            // Aggregate 1-hop neighbors with their 2-hop neighbors
            WITH nodeId, nodeLabels, %(emb_carry)sallNodeProperties, score,
                 collect(DISTINCT {
                     relationshipType: type(r),
                     primaryNode: {
                         nodeId: elementId(neighbor),
                         nodeLabel: %(nb_label)s,
                         nodeType: %(nb_type)s,
                         nodeContent: %(nb_content)s,
                         %(nb_emb)sallProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                     },
                     secondHopNeighbors: secondHopNeighbors
                 })[..%(max_nb)s] as neighbors
        """ % {
            'emb_with': emb_with,
            'emb_carry': emb_carry,
            'sh_label': sh_label,
            'sh_type': sh_type,
            'sh_content': sh_content,
            'max_sh': max_sh,
            'nb_label': nb_label,
            'nb_type': nb_type,
            'nb_content': nb_content,
            'nb_emb': nb_emb,
            'max_nb': max_nb,
        }

        query += self._build_final_return_section()
        return query

    def _build_final_return_section(self) -> str:
        """Common final RETURN section for 1-hop and 2-hop queries"""
        primary_type = "[label IN nodeLabels WHERE label <> 'Resource'][0]"
        label_case = cypher_label_case('allNodeProperties', primary_type)
        content_case = cypher_content_case('allNodeProperties', primary_type, primary=True)

        emb_carry = "nodeEmbedding, " if self._include_embedding else ""
        emb_return = "embedding: nodeEmbedding,\n                        " if self._include_embedding else ""

        return """

            // Final RETURN with all aggregated data
            // Filter out null neighbors (from nodes with no connections)
            WITH nodeId, nodeLabels, %(emb_carry)sallNodeProperties, score,
                 [n IN neighbors WHERE n.primaryNode.nodeId IS NOT NULL] as neighbors,
                 %(content_case)s as nodeContent,
                 %(label_case)s as displayLabel,
                 %(primary_type)s as nodeType

            RETURN {
                content: nodeContent,
                metadata: {
                    primarySource: {
                        nodeId: nodeId,
                        nodeLabel: displayLabel,
                        nodeType: nodeType,
                        nodeContent: nodeContent,
                        %(emb_return)sinitialScore: score,
                        score: score,
                        allProperties: allNodeProperties
                    },
                    firstHopNeighbors: neighbors
                }
            } as item
        """ % {
            'emb_carry': emb_carry,
            'content_case': content_case,
            'label_case': label_case,
            'primary_type': primary_type,
            'emb_return': emb_return,
        }

    def _sort_neighbors_by_similarity(
        self, items: List[Dict], query_embedding: List[float]
    ) -> List[Dict]:
        """Sort and cap neighbors by cosine similarity to query.

        Called after Cypher retrieval when enable_similarity_neighbor_ordering is True.
        Sorts firstHopNeighbors (and secondHopNeighbors within each) by cosine similarity
        to the query embedding, applies the original caps, then strips neighbor embeddings.
        """
        from ..utils import cosine_similarity

        for item in items:
            metadata = item.get('metadata', {})
            neighbors = metadata.get('firstHopNeighbors', [])
            if not neighbors:
                continue

            # --- Sort 1-hop neighbors ---
            scored = []
            for nb in neighbors:
                nb_node = nb.get('primaryNode', {})
                emb = nb_node.get('embedding') or []
                score = cosine_similarity(emb, query_embedding) if emb else 0.0
                scored.append((score, nb))
            scored.sort(key=lambda x: x[0], reverse=True)

            kept = []
            for _, nb in scored[:self.config.max_neighbors_per_node]:
                nb = nb.copy()
                nb_node = nb.get('primaryNode', {}).copy()

                # --- Sort 2-hop neighbors within each 1-hop ---
                second_hop = nb.get('secondHopNeighbors', [])
                if second_hop:
                    scored_sh = []
                    for sh in second_hop:
                        sh_node = sh.get('relatedNode', {})
                        sh_emb = sh_node.get('embedding') or []
                        sh_score = cosine_similarity(sh_emb, query_embedding) if sh_emb else 0.0
                        scored_sh.append((sh_score, sh))
                    scored_sh.sort(key=lambda x: x[0], reverse=True)
                    nb['secondHopNeighbors'] = [sh for _, sh in scored_sh[:self.config.max_second_hop_per_first]]

                # Strip embedding from neighbor node (no longer needed)
                nb_node.pop('embedding', None)
                nb['primaryNode'] = nb_node
                kept.append(nb)

            metadata['firstHopNeighbors'] = kept

        return items

    def expand_by_ids(
        self,
        items: List[Dict],
        hop_depth: int,
        query_embedding: List[float] = None,
    ) -> List[Dict]:
        """
        Graph-expand a list of already-retrieved seed items by their node IDs.
        Used by HybridRetriever for late graph expansion.

        Mirrors the neighbour-fetching logic of _build_one/two_hop_query but
        seeds by elementId instead of vector similarity, so it can be applied
        to any node set after RRF merge.

        DSA-BFS (enable_similarity_neighbor_ordering) is applied afterwards
        via _sort_neighbors_by_similarity, same as the early-expand path.
        """
        if not items:
            return items

        node_ids = [
            item.get('metadata', {}).get('primarySource', {}).get('nodeId')
            for item in items
        ]
        node_ids = [nid for nid in node_ids if nid is not None]
        if not node_ids:
            return items

        nb_type = "[label IN labels(neighbor) WHERE label <> 'Resource'][0]"
        nb_label = cypher_label_case('neighbor', nb_type)
        nb_content = cypher_content_case('neighbor', nb_type, primary=False)
        nb_emb = (
            "embedding: neighbor.embedding,\n                             "
            if self._include_neighbor_embedding else ""
        )
        multiplier = (
            self.config.similarity_neighbor_fetch_multiplier
            if self.config.enable_similarity_neighbor_ordering else 1
        )
        max_nb = self.config.max_neighbors_per_node * multiplier

        if hop_depth >= 2:
            sh_type = "[label IN labels(secondHop) WHERE label <> 'Resource'][0]"
            sh_label = cypher_label_case('secondHop', sh_type)
            sh_content = cypher_content_case('secondHop', sh_type, primary=False)
            max_sh = self.config.max_second_hop_per_first * multiplier

            cypher = """
                UNWIND $node_ids AS seed_id
                MATCH (n) WHERE elementId(n) = seed_id
                WITH n, elementId(n) AS nodeId

                OPTIONAL MATCH (n)-[r]-(neighbor)
                WHERE neighbor.embedding IS NOT NULL

                OPTIONAL MATCH (neighbor)-[r2]-(secondHop)
                WHERE secondHop.embedding IS NOT NULL
                    AND elementId(secondHop) <> nodeId

                WITH nodeId, neighbor, r,
                     [item IN collect(DISTINCT {
                         relationshipType: type(r2),
                         relatedNode: {
                             nodeId: elementId(secondHop),
                             nodeLabel: %(sh_label)s,
                             nodeType: %(sh_type)s,
                             nodeContent: %(sh_content)s,
                             allProperties: CASE WHEN secondHop IS NOT NULL THEN properties(secondHop) ELSE {} END
                         }
                     }) WHERE item.relatedNode.nodeId IS NOT NULL][..%(max_sh)s] as secondHopNeighbors

                WITH nodeId,
                     collect(DISTINCT {
                         relationshipType: type(r),
                         primaryNode: {
                             nodeId: elementId(neighbor),
                             nodeLabel: %(nb_label)s,
                             nodeType: %(nb_type)s,
                             nodeContent: %(nb_content)s,
                             %(nb_emb)sallProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                         },
                         secondHopNeighbors: secondHopNeighbors
                     })[..%(max_nb)s] AS neighbors

                RETURN nodeId, [item IN neighbors WHERE item.primaryNode.nodeId IS NOT NULL] AS neighbors
            """ % {
                'sh_label': sh_label,
                'sh_type': sh_type,
                'sh_content': sh_content,
                'max_sh': max_sh,
                'nb_label': nb_label,
                'nb_type': nb_type,
                'nb_content': nb_content,
                'nb_emb': nb_emb,
                'max_nb': max_nb,
            }
        else:
            cypher = """
                UNWIND $node_ids AS seed_id
                MATCH (n) WHERE elementId(n) = seed_id
                WITH n, elementId(n) AS nodeId

                OPTIONAL MATCH (n)-[r]-(neighbor)
                WHERE neighbor.embedding IS NOT NULL

                WITH nodeId,
                     collect(DISTINCT {
                         relationshipType: type(r),
                         primaryNode: {
                             nodeId: elementId(neighbor),
                             nodeLabel: %(nb_label)s,
                             nodeType: %(nb_type)s,
                             nodeContent: %(nb_content)s,
                             %(nb_emb)sallProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                         }
                     })[..%(max_nb)s] AS neighbors

                RETURN nodeId, [item IN neighbors WHERE item.primaryNode.nodeId IS NOT NULL] AS neighbors
            """ % {
                'nb_label': nb_label,
                'nb_type': nb_type,
                'nb_content': nb_content,
                'nb_emb': nb_emb,
                'max_nb': max_nb,
            }

        try:
            with self.driver.session() as session:
                result = session.run(cypher, {"node_ids": node_ids})
                neighbors_map = {record["nodeId"]: record["neighbors"] for record in result}
        except Exception as e:
            logger.warning("expand_by_ids Cypher failed: %s", e)
            return items

        for item in items:
            nid = item.get('metadata', {}).get('primarySource', {}).get('nodeId')
            if nid and nid in neighbors_map:
                item['metadata']['firstHopNeighbors'] = neighbors_map[nid] or []

        if self.config.enable_similarity_neighbor_ordering and query_embedding:
            items = self._sort_neighbors_by_similarity(items, query_embedding)

        return items

    def entity_name_lookup(self, query: str, limit: int = 5) -> List[Dict]:
        """
        Find nodes whose display name appears in the query via Neo4j property match.

        Uses case-insensitive CONTAINS on the name properties defined in _LABEL_MAPPING.
        Returns results in the same envelope format as retrieve() for easy merging.

        Args:
            query: User query string
            limit: Maximum number of matches to return

        Returns:
            List of items in metadata-envelope format (same as retrieve())
        """
        # Build WHERE clauses from the label mapping
        # Each (type, property_expr) pair becomes a CONTAINS check
        where_clauses = []
        for type_name, expr_template in _LABEL_MAPPING:
            prop_expr = expr_template.format(n='n')
            where_clauses.append(
                f"('{type_name}' IN labels(n) AND toLower({prop_expr}) CONTAINS toLower($query))"
            )

        where_str = " OR ".join(where_clauses)

        type_expr = "[label IN labels(n) WHERE label <> 'Resource'][0]"
        label_case = cypher_label_case('n', type_expr)
        content_case = cypher_content_case('n', type_expr, primary=True)

        cypher = f"""
            MATCH (n)
            WHERE n.embedding IS NOT NULL AND ({where_str})
            WITH n,
                 elementId(n) as nodeId,
                 labels(n) as nodeLabels,
                 properties(n) as allNodeProperties,
                 [{type_expr}][0] as nodeType
            WITH nodeId, nodeLabels, allNodeProperties, nodeType,
                 {label_case} as displayLabel,
                 {content_case} as nodeContent
            RETURN {{
                content: nodeContent,
                metadata: {{
                    primarySource: {{
                        nodeId: nodeId,
                        nodeLabel: displayLabel,
                        nodeType: nodeType,
                        nodeContent: nodeContent,
                        initialScore: 1.0,
                        score: 1.0,
                        allProperties: allNodeProperties
                    }},
                    firstHopNeighbors: []
                }}
            }} as item
            LIMIT $limit
        """

        try:
            with self.driver.session() as session:
                result = session.run(cypher, {"query": query, "limit": limit})
                items = [record["item"] for record in result]
                logger.info("Entity name lookup found %d matches for query: '%s'", len(items), query[:60])
                return items
        except Exception as e:
            logger.warning("Entity name lookup failed: %s", e)
            return []
