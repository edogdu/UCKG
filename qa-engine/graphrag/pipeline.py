"""
GraphRAG Pipeline Orchestrator
Main class that coordinates all stages of the GraphRAG pipeline
"""

import os
import sys
from typing import Dict, Any, Tuple
from neo4j import GraphDatabase
from langchain_ollama import ChatOllama

# Import GraphRAG components
from .utils import GraphRAGConfig, RAGMode, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from .retrieval import GraphRetriever
from .reranking import GraphReranker
from .generation import ContextFormatter, AnswerGenerator

# Import optional components from shared modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
try:
    from shared.hop_selector import HopSelector
except ImportError:
    HopSelector = None

try:
    from test_relationship_prediction import RelationshipPredictor
    from text2cypher.backend.ollama_llm import OllamaLLM
except ImportError:
    RelationshipPredictor = None
    OllamaLLM = None


class GraphRAGSimilarity:
    """
    Main GraphRAG pipeline orchestrator

    Coordinates the 4-stage pipeline:
    - Stage 0: Pre-processing (hop selection, relationship prediction)
    - Stage 1-2: Retrieval (semantic search + graph traversal)
    - Stage 3: Reranking (neighbor-aware scoring)
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

        # Initialize LLMs
        self.llm = ChatOllama(model="llama3:8b", temperature=0.2)
        self.router_llm = ChatOllama(model="llama3:8b", temperature=0)

        # Initialize core components
        self.retriever = GraphRetriever(self.driver, self.config)
        self.reranker = GraphReranker(self.config)
        self.formatter = ContextFormatter()
        self.generator = AnswerGenerator(self.llm)

        # Initialize optional components
        self._initialize_hop_selector()
        self._initialize_relationship_predictor()

    def _initialize_hop_selector(self):
        """Initialize hop selector if enabled"""
        if self.config.enable_dynamic_hop_selection and HopSelector:
            try:
                self.hop_selector = HopSelector(
                    llm=self.router_llm,
                    use_llm_threshold=self.config.hop_selection_llm_threshold,
                    enable_llm=self.config.hop_selection_enable_llm
                )
                print(f"[GraphRAG] Hop selector initialized (LLM: {self.config.hop_selection_enable_llm})")
            except Exception as e:
                print(f"WARNING: Hop selector initialization failed: {e}")
                self.config.enable_dynamic_hop_selection = False
                self.hop_selector = None
        else:
            self.hop_selector = None

    def _initialize_relationship_predictor(self):
        """Initialize relationship predictor if enabled"""
        if self.config.enable_relationship_prediction and RelationshipPredictor and OllamaLLM:
            try:
                llm = OllamaLLM(model=self.config.llm_model)
                self.relationship_predictor = RelationshipPredictor(
                    llm,
                    schema_file="shared/uckg_schema_llm.txt"
                )
                print(f"[GraphRAG] Relationship predictor initialized with model: {self.config.llm_model}")
            except Exception as e:
                print(f"WARNING: Relationship predictor initialization failed: {e}")
                self.config.enable_relationship_prediction = False
                self.relationship_predictor = None
        else:
            self.relationship_predictor = None

    def run(self, query: str) -> Dict[str, Any]:
        """
        Execute complete GraphRAG-Similarity pipeline

        Workflow:
        0. Dynamic hop selection & relationship prediction
        1-2. Retrieval (semantic + graph)
        3. Reranking
        4. Generation

        Args:
            query: User query string

        Returns:
            Dictionary with answer, sources, context, and metadata
        """
        try:
            # STAGE 0: Pre-processing
            hop_decision = self._select_hop_depth(query)
            predicted_relationships = self._predict_relationships(query)

            # Store predicted relationships in reranker
            if predicted_relationships:
                self.reranker.set_predicted_relationships(predicted_relationships)

            # Classify query (currently forced to graphrag mode)
            mode, top_k = self._classify_query(query)

            # STAGE 1-2: Retrieve
            hop_depth = hop_decision.hop_depth if hop_decision else (2 if self.config.enable_second_hop else 1)
            items = self.retriever.retrieve(query, top_k, hop_depth)

            # STAGE 3: Rerank (skip for 0-hop)
            if hop_depth == 0:
                print(f"[0-hop] Skipping reranking, using original vector scores (returning top {self.config.zero_hop_top_k})")
                # Format 0-hop results without reranking
                items = self._format_zero_hop_results(items)
            else:
                print(f"[{hop_depth}-hop] Applying reranking with graph context")
                query_embedding = self.retriever.embedder.embed_query(query)
                items = self.reranker.rerank(items, query_embedding, self.config.final_top_k)

            # STAGE 4: Generate
            context_info = self.formatter.format(items, mode)
            answer = self.generator.generate(query, context_info["formatted_text"], mode)

            # Extract enhanced metadata
            enhanced_metadata = self.formatter.extract_enhanced_metadata(items, mode)

            # Prepare result
            result = {
                "answer": answer,
                "mode": mode.value,
                "sources": items,
                "context": context_info["formatted_text"],
                "context_metadata": context_info["metadata"],
                "structured_context": context_info["structured_data"],
                "enhanced_metadata": enhanced_metadata
            }

            # Add hop selection metadata if available
            if hop_decision:
                result["hop_selection"] = {
                    "hop_depth": hop_decision.hop_depth,
                    "reasoning": hop_decision.reasoning,
                    "confidence": hop_decision.confidence,
                    "method": hop_decision.method
                }

            return result

        except Exception as e:
            import traceback
            print(f"ERROR in run: {str(e)}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return {
                "answer": f"Error processing query: {str(e)}",
                "mode": "error",
                "sources": [],
                "context": "",
                "context_metadata": {},
                "structured_context": [],
                "enhanced_metadata": {}
            }

    def _select_hop_depth(self, query: str):
        """Stage 0: Dynamic hop selection based on query complexity"""
        if self.config.enable_dynamic_hop_selection and self.hop_selector:
            try:
                hop_decision = self.hop_selector.select_hop_depth(query)
                print(f"[Hop Selection] Depth: {hop_decision.hop_depth}, "
                      f"Confidence: {hop_decision.confidence:.2f}, "
                      f"Method: {hop_decision.method}")
                print(f"[Hop Selection] Reasoning: {hop_decision.reasoning}")
                return hop_decision
            except Exception as e:
                print(f"WARNING: Hop selection failed: {e}")
                return None
        return None

    def _predict_relationships(self, query: str):
        """Stage 0: Predict relevant relationships using LLM"""
        if self.config.enable_relationship_prediction and hasattr(self, 'relationship_predictor') and self.relationship_predictor:
            try:
                prediction = self.relationship_predictor.predict_relationships(query)
                predicted_rels = prediction.get("primary_relationships", [])
                print(f"[Prediction] Identified {len(predicted_rels)} relevant relationship types")
                for i, rel in enumerate(predicted_rels, 1):
                    print(f"  {i}. ({rel.get('start')})-[{rel.get('relationship')}]->({rel.get('end')})")
                return predicted_rels
            except Exception as e:
                print(f"WARNING: Relationship prediction failed: {e}")
                return []
        return []

    def _classify_query(self, query: str) -> Tuple[RAGMode, int]:
        """Classify query to determine retrieval mode (currently forced to graphrag)"""
        # Force graphrag mode only
        return RAGMode.graphrag, 5

    def _format_zero_hop_results(self, items):
        """Format 0-hop results (semantic only, no graph neighbors)"""
        formatted_results = []
        for item in items:
            # Handle the nested metadata structure
            if isinstance(item, dict) and 'metadata' in item:
                primary = item.get('metadata', {}).get('primarySource', {})
                score = primary.get('score', 0.0)

                # Clean up embedding (too large for output)
                primary.pop("embedding", None)

                formatted_results.append({
                    "primarySource": primary,
                    "firstHopNeighbors": [],  # No neighbors in 0-hop
                    "score": score
                })

        # Sort by score and return top N for 0-hop
        formatted_results.sort(key=lambda x: x['score'], reverse=True)
        return formatted_results[:self.config.zero_hop_top_k]

    def extract_llm_context(self, query: str, save_to_file: bool = False, output_path: str = None) -> Dict[str, Any]:
        """
        Extract and return the exact context that will be provided to the LLM

        Useful for debugging and analyzing what information the LLM receives.

        Args:
            query: User query string
            save_to_file: If True, save the context to a text file
            output_path: Path to save the context (defaults to 'llm_context_debug.txt')

        Returns:
            Dictionary containing:
                - formatted_context: The exact text given to the LLM
                - prompt_template: The full prompt template used
                - full_prompt: The complete prompt sent to LLM (template + context)
                - metadata: Information about the retrieval (mode, hop depth, etc.)
                - sources: Raw source data before formatting
        """
        try:
            # Execute retrieval pipeline (same as run, but return context)
            hop_decision = self._select_hop_depth(query)
            predicted_relationships = self._predict_relationships(query)

            if predicted_relationships:
                self.reranker.set_predicted_relationships(predicted_relationships)

            mode, top_k = self._classify_query(query)
            hop_depth = hop_decision.hop_depth if hop_decision else (2 if self.config.enable_second_hop else 1)

            items = self.retriever.retrieve(query, top_k, hop_depth)

            if hop_depth == 0:
                items = self._format_zero_hop_results(items)
            else:
                query_embedding = self.retriever.embedder.embed_query(query)
                items = self.reranker.rerank(items, query_embedding, self.config.final_top_k)

            # Generate enhanced context
            context_info = self.formatter.format(items, mode)
            formatted_context = context_info["formatted_text"]

            # Get the prompt template
            prompt_template = self.generator.prompt_graphrag if mode == RAGMode.graphrag else self.generator.prompt_hybrid

            # Generate the full prompt
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
                    "hop_selection": hop_decision.__dict__ if hop_decision else None
                },
                "sources": items
            }

            # Save to file if requested
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
                print(f"[Debug] Context saved to: {output_path}")

            return result

        except Exception as e:
            import traceback
            print(f"ERROR in extract_llm_context: {str(e)}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
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
