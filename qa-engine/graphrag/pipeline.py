"""
GraphRAG Pipeline Orchestrator
Main class that coordinates all stages of the GraphRAG pipeline
"""

import logging
from typing import Dict, Any, List
from neo4j import GraphDatabase
from langchain_ollama import ChatOllama

logger = logging.getLogger(__name__)

# Import GraphRAG components
from .utils import GraphRAGConfig, RAGMode, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, normalize_retrieval_item
from .retrieval import GraphRetriever
from .retrieval import HybridRetriever
from .reranking import GraphReranker
from .reranking import CrossEncoderReranker
from .reranking import SubgraphPruner
from .generation import ContextFormatter, AnswerGenerator
from .retrieval import RelationshipRetriever


class GraphRAGSimilarity:
    """
    Main GraphRAG pipeline orchestrator

    Coordinates the 3-stage pipeline:
    - Stage 1-2: Retrieval (semantic search + graph traversal)
    - Stage 3: Reranking (two-pass graph-aware cross-encoder)
    - Stage 4: Generation (context formatting + LLM answer)
    """

    def __init__(self, graphrag_config: GraphRAGConfig = None):
        """
        Initialize the GraphRAG pipeline

        Args:
            graphrag_config: Configuration for pipeline stages (optional)
        """
        # Configuration
        self.config = graphrag_config or GraphRAGConfig()

        # Initialize Neo4j connection
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        # Initialize LLM
        self.llm = ChatOllama(model="llama3:8b", temperature=0.2)

        # Initialize core components
        # Create base vector retriever (always needed)
        self.vector_retriever = GraphRetriever(self.driver, self.config)
        
        # Initialize retriever (hybrid or vector-only)
        self._initialize_retriever()
        
        self.formatter = ContextFormatter()
        self.generator = AnswerGenerator(self.llm)
        self.subgraph_pruner = SubgraphPruner(self.config)

        # Initialize reranker (cross-encoder or legacy)
        self._initialize_reranker()

        # Initialize PPR (optional, replaces BFS neighbor selection)
        self.ppr_retriever = None
        if self.config.enable_ppr:
            self._initialize_ppr()

        # Initialize relationship retriever (optional)
        self.relationship_retriever = None
        if self.config.enable_relationship_retrieval:
            self._initialize_relationship_retriever()

    def _initialize_retriever(self):
        """Initialize retriever (hybrid BM25+Vector or vector-only)"""
        if self.config.enable_hybrid_retrieval:
            try:
                self.retriever = HybridRetriever(
                    self.driver,
                    self.config,
                    self.vector_retriever
                )
                logger.info("Hybrid retriever initialized (BM25 + Vector)")
            except Exception as e:
                logger.warning("Hybrid retrieval initialization failed: %s", e)
                logger.info("Falling back to vector-only retrieval")
                self.config.enable_hybrid_retrieval = False
                self.retriever = self.vector_retriever
        else:
            self.retriever = self.vector_retriever
            logger.info("Vector-only retriever initialized")

    def _initialize_reranker(self):
        """Initialize reranker (cross-encoder or legacy cosine similarity)"""
        if self.config.enable_cross_encoder:
            try:
                self.cross_encoder_reranker = CrossEncoderReranker(self.config)
                self.reranker = None  # Not used when cross-encoder is enabled
                logger.info("Cross-encoder reranker initialized")
            except Exception as e:
                logger.warning("Cross-encoder initialization failed: %s", e)
                logger.info("Falling back to legacy cosine similarity reranker")
                self.config.enable_cross_encoder = False
                self.cross_encoder_reranker = None
                self.reranker = GraphReranker(self.config)
        else:
            self.cross_encoder_reranker = None
            self.reranker = GraphReranker(self.config)
            logger.info("Legacy cosine similarity reranker initialized")

    def _initialize_relationship_retriever(self):
        """Initialize the relationship-level vector retriever."""
        try:
            self.relationship_retriever = RelationshipRetriever(self.driver, self.config)
            logger.info("Relationship retriever initialized")
        except Exception as e:
            logger.warning("Relationship retriever initialization failed: %s", e)
            self.config.enable_relationship_retrieval = False

    def _initialize_ppr(self):
        """Initialize PPR graph projection and retriever"""
        try:
            from .retrieval import PPRGraphProjection, PPRRetriever
            graph_projection = PPRGraphProjection(self.driver, self.config)
            if graph_projection.load_graph():
                self.ppr_retriever = PPRRetriever(graph_projection, self.config)
                logger.info("PPR retriever initialized")
            else:
                logger.warning("PPR graph projection failed to load, disabling PPR")
                self.config.enable_ppr = False
        except Exception as e:
            logger.warning("PPR initialization failed: %s", e)
            logger.info("Falling back to BFS neighbor selection")
            self.config.enable_ppr = False

    def _hyde_expand(self, query: str) -> str:
        """Generate a hypothetical document for query expansion (HyDE).

        Asks the LLM to write a short technical paragraph that would answer
        the query. The resulting text is embedded instead of the raw question,
        which often yields better vector similarity to relevant documents.
        """
        hyde_llm = ChatOllama(model=self.config.hyde_llm_model, temperature=0.3)
        prompt = (
            "Given this cybersecurity question, write a short technical paragraph "
            "that would answer it. Use specific technical terms, CVE/CWE/CAPEC identifiers, "
            "and ATT&CK technique names where relevant.\n\n"
            f"Question: {query}\n\nTechnical answer:"
        )
        try:
            response = hyde_llm.invoke(prompt)
            hyde_doc = response.content
            logger.info("HyDE expansion generated (%d chars)", len(hyde_doc))
            return hyde_doc
        except Exception as e:
            logger.warning("HyDE expansion failed, using original query: %s", e)
            return query

    def _execute_pipeline(self, query: str) -> Dict[str, Any]:
        """
        Execute pipeline stages 1-3 (retrieval, reranking).

        Shared by run() and extract_llm_context() to avoid duplication.

        Returns:
            Dictionary with items, hop_depth, and mode
        """
        mode = RAGMode.graphrag
        top_k = 5
        pruning_metadata = {
            "status": "not_applicable",
            "hop_depth": 0,
            "budget": None,
        }

        # Optional HyDE: embed a hypothetical answer instead of the raw question
        retrieval_query = query
        if self.config.enable_hyde:
            retrieval_query = self._hyde_expand(query)

        # STAGE 1-2: Retrieve (use retrieval_query for embedding, original query for reranking)
        if not self.config.enable_graph_traversal:
            hop_depth = 0
        elif self.config.enable_second_hop:
            hop_depth = 2
        else:
            hop_depth = 1

        # When PPR handles neighbor selection, retrieve in 0-hop mode (seeds only)
        use_ppr = self.config.enable_ppr and self.ppr_retriever and hop_depth > 0
        retrieval_hop_depth = 0 if use_ppr else hop_depth
        retrieval_top_k = max(top_k, self.config.zero_hop_top_k) if retrieval_hop_depth == 0 else top_k
        items = self.retriever.retrieve(retrieval_query, retrieval_top_k, retrieval_hop_depth)
        items = [normalize_retrieval_item(i) for i in items]

        # Inject relationship-level candidates into the pool (optional)
        if self.config.enable_relationship_retrieval and self.relationship_retriever:
            try:
                query_embedding = self.vector_retriever.embedder.embed_query(retrieval_query)
                rel_items = self.relationship_retriever.retrieve(
                    query_embedding,
                    self.config.relationship_retrieval_top_k,
                )
                if rel_items:
                    existing_ids = {i.get('primarySource', {}).get('nodeId') for i in items}
                    for rel_item in rel_items:
                        rid = rel_item.get('primarySource', {}).get('nodeId')
                        if rid and rid not in existing_ids:
                            items.append(rel_item)
                            existing_ids.add(rid)
                    logger.info(
                        "Relationship retrieval injected %d candidates", len(rel_items)
                    )
            except Exception as e:
                logger.warning("Relationship retrieval failed: %s", e)

        # Inject entity name matches into candidate pool before reranking
        if self.config.enable_entity_name_boosting and self.config.enable_graph_traversal:
            entity_matches = self.vector_retriever.entity_name_lookup(query)
            entity_matches = [normalize_retrieval_item(i) for i in entity_matches]
            existing_ids = {i.get('primarySource', {}).get('nodeId') for i in items}
            for match in entity_matches:
                mid = match.get('primarySource', {}).get('nodeId')
                if mid and mid not in existing_ids:
                    items.append(match)
                    existing_ids.add(mid)
            if entity_matches:
                logger.info("Entity name boosting injected %d new candidates", len(entity_matches))

        # PPR neighbor selection (replaces BFS traversal)
        if use_ppr:
            items = self.ppr_retriever.select_neighbors(items, hop_depth)

        # STAGE 3: Rerank (skip for 0-hop)
        if hop_depth == 0:
            logger.info("0-hop: Skipping reranking, returning top %d", self.config.zero_hop_top_k)
            items = self._format_zero_hop_results(items)
        else:
            if self.config.enable_cross_encoder and self.cross_encoder_reranker:
                logger.info("%d-hop: Applying cross-encoder reranking", hop_depth)
                items = self.cross_encoder_reranker.rerank(query, items, self.config.final_top_k)
            else:
                logger.info("%d-hop: Applying legacy reranking with graph context", hop_depth)
                query_embedding = self.vector_retriever.embedder.embed_query(query)
                items = self.reranker.rerank(items, query_embedding, self.config.final_top_k)

        # STAGE 3.5: Optional subgraph pruning (post-rerank, pre-generation)
        if hop_depth > 0:
            items, pruning_metadata = self.subgraph_pruner.prune(items, query, hop_depth)
        else:
            pruning_metadata = {
                "status": "bypassed_hop0",
                "hop_depth": hop_depth,
                "budget": None,
            }

        return {
            "items": items,
            "hop_depth": hop_depth,
            "mode": mode,
            "pruning_metadata": pruning_metadata,
        }

    def run(self, query: str) -> Dict[str, Any]:
        """
        Execute complete GraphRAG-Similarity pipeline

        Workflow:
        1-2. Retrieval (semantic + graph)
        3. Reranking (two-pass graph-aware cross-encoder)
        4. Generation

        Args:
            query: User query string

        Returns:
            Dictionary with answer, sources, context, and metadata
        """
        try:
            pipeline_result = self._execute_pipeline(query)
            items = pipeline_result["items"]
            mode = pipeline_result["mode"]
            pruning_metadata = pipeline_result.get("pruning_metadata", {})

            # STAGE 4: Generate
            context_info = self.formatter.format(items, mode)
            answer = self.generator.generate(query, context_info["formatted_text"], mode)

            enhanced_metadata = self.formatter.extract_enhanced_metadata(items, mode)
            key_entities = self._extract_visited_uris(items)

            return {
                "answer": answer,
                "mode": mode.value,
                "sources": items,
                "context": context_info["formatted_text"],
                "context_metadata": context_info["metadata"],
                "structured_context": context_info["structured_data"],
                "enhanced_metadata": enhanced_metadata,
                "key_entities": key_entities,
                "pruning_metadata": pruning_metadata,
            }

        except Exception as e:
            logger.error("Pipeline run failed: %s", e, exc_info=True)
            return {
                "answer": f"Error processing query: {str(e)}",
                "mode": "error",
                "sources": [],
                "context": "",
                "context_metadata": {},
                "structured_context": [],
                "enhanced_metadata": {},
                "key_entities": [],
                "pruning_metadata": {
                    "status": "bypassed_error",
                    "hop_depth": None,
                    "budget": None,
                    "error": str(e),
                },
            }

    def _format_zero_hop_results(self, items):
        """Format 0-hop results (semantic only, no graph neighbors)"""
        for item in items:
            item.get('primarySource', {}).pop('embedding', None)
        items.sort(key=lambda x: x.get('score', 0.0), reverse=True)
        return items[:self.config.zero_hop_top_k]

    def _extract_visited_uris(self, items: List[Dict]) -> List[str]:
        """
        Extract all visited node URIs from normalized retrieval results.
        
        Args:
            items: List of graph items in flat format (post-normalization)
            
        Returns:
            List of unique URIs for all visited nodes
        """
        uri_set = set()
        
        for item in items:
            primary = item.get("primarySource", {})
            neighbors = item.get("firstHopNeighbors", [])
            
            primary_uri = primary.get("allProperties", {}).get("uri")
            if primary_uri:
                uri_set.add(primary_uri)
            
            for neighbor in neighbors:
                neighbor_node = neighbor.get("primaryNode", {})
                neighbor_uri = neighbor_node.get("allProperties", {}).get("uri")
                if neighbor_uri:
                    uri_set.add(neighbor_uri)
                
                for second_hop in neighbor.get("secondHopNeighbors", []):
                    second_node = second_hop.get("relatedNode", {})
                    second_uri = second_node.get("allProperties", {}).get("uri")
                    if second_uri:
                        uri_set.add(second_uri)
        
        return list(uri_set)

    def extract_llm_context(self, query: str, save_to_file: bool = False, output_path: str = None) -> Dict[str, Any]:
        """
        Extract and return the exact context that will be provided to the LLM.
        Useful for debugging and analyzing what information the LLM receives.

        Args:
            query: User query string
            save_to_file: If True, save the context to a text file
            output_path: Path to save the context (defaults to 'llm_context_debug.txt')

        Returns:
            Dictionary with formatted_context, prompt_template, full_prompt, metadata, sources
        """
        try:
            pipeline_result = self._execute_pipeline(query)
            items = pipeline_result["items"]
            hop_depth = pipeline_result["hop_depth"]
            mode = pipeline_result["mode"]
            pruning_metadata = pipeline_result.get("pruning_metadata", {})

            context_info = self.formatter.format(items, mode)
            formatted_context = context_info["formatted_text"]

            prompt_template = self.generator.prompt_graphrag
            full_prompt = prompt_template.template.format(
                context=formatted_context,
                query_text=query
            )

            result = {
                "formatted_context": formatted_context,
                "prompt_template": prompt_template.template,
                "full_prompt": full_prompt,
                "metadata": {
                    "mode": mode.value,
                    "hop_depth": hop_depth,
                    "item_count": len(items),
                    "pruning_metadata": pruning_metadata,
                },
                "sources": items
            }

            if save_to_file:
                output_path = output_path or "llm_context_debug.txt"
                with open(output_path, 'w') as f:
                    f.write("=" * 80 + "\n")
                    f.write("LLM CONTEXT DEBUG OUTPUT\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Query: {query}\n\n")
                    f.write(f"Mode: {mode.value}\n")
                    f.write(f"Hop Depth: {hop_depth}\n")
                    f.write(f"Item Count: {len(items)}\n\n")
                    f.write("=" * 80 + "\n")
                    f.write("FULL PROMPT (TEMPLATE + CONTEXT)\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(full_prompt)
                    f.write("\n\n")
                    f.write("=" * 80 + "\n")
                    f.write("RAW CONTEXT ONLY\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(formatted_context)
                logger.info("Context saved to: %s", output_path)

            return result

        except Exception as e:
            logger.error("extract_llm_context failed: %s", e, exc_info=True)
            return {
                "formatted_context": "",
                "prompt_template": "",
                "full_prompt": "",
                "metadata": {},
                "sources": [],
                "error": str(e)
            }

    def close(self):
        """Close database connections"""
        if self.driver:
            self.driver.close()
