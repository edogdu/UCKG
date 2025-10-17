"""
T2CSS Integration Module

Integrates the T2CSS (Text-to-Cypher Semantic Schema) pipeline
with the existing Text2Cypher system.
"""

import os
from typing import Optional
from t2css_pipeline import T2CSSPipeline
from text2cypher import Text2Cypher


class T2CypherWithT2CSS(Text2Cypher):
    """
    Enhanced Text2Cypher with T2CSS semantic schema filtering
    
    This class extends the base Text2Cypher with the T2CSS pipeline
    for improved semantic schema-based prompting.
    """
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm, use_t2css: bool = True, top_k_schema: int = 10):
        """
        Initialize enhanced Text2Cypher with T2CSS
        
        Args:
            llm: Language model instance
            use_t2css: Enable T2CSS semantic filtering (default: True)
            top_k_schema: Number of schema elements to include (default: 10)
        """
        super().__init__(neo4j_uri, neo4j_user, neo4j_password, llm)
        self.use_t2css = use_t2css
        self.top_k_schema = top_k_schema
        self.t2css_pipeline: Optional[T2CSSPipeline] = None
        
        if use_t2css:
            self._initialize_t2css()
    
    def _initialize_t2css(self):
        """Initialize T2CSS pipeline with embedded schema"""
        print("\n[T2CSS Integration] Initializing T2CSS pipeline...")
        
        # Initialize pipeline
        self.t2css_pipeline = T2CSSPipeline(
            embedding_model="nomic-embed-text",
            top_k=self.top_k_schema
        )
        
        # Check if pre-computed embeddings exist
        embeddings_path = os.path.join(os.path.dirname(__file__), 'schema_embeddings.json')
        
        if os.path.exists(embeddings_path):
            print("[T2CSS Integration] Loading pre-computed embeddings...")
            self.t2css_pipeline.load_embeddings(embeddings_path)
        else:
            print("[T2CSS Integration] Generating embeddings (this may take a moment)...")
            # Get schema
            schema_text = self.get_cybersecurity_schema()
            
            # Generate and embed semantic triples
            self.t2css_pipeline.generate_semantic_texts(schema_text)
            self.t2css_pipeline.embed_schema_triples()
            
            # Save for future use
            self.t2css_pipeline.save_embeddings(embeddings_path)
        
        print("[T2CSS Integration] T2CSS pipeline ready!")
    
    def _build_prompt(self, question: str, schema_block: str, examples: str) -> str:
        """
        Override prompt builder to use T2CSS semantic filtering
        
        Args:
            question: User's natural language question
            schema_block: Full schema (will be filtered if T2CSS is enabled)
            examples: Few-shot examples
            
        Returns:
            Assembled prompt string
        """
        if not self.use_t2css or self.t2css_pipeline is None:
            # Fall back to original prompt building
            return super()._build_prompt(question, schema_block, examples)
        
        # Use T2CSS pipeline for semantic filtering
        print(f"\n[T2CSS Integration] Using semantic schema filtering for: {question}")
        
        # Filter schema by similarity
        top_k_schema = self.t2css_pipeline.filter_schema_by_similarity(question)
        
        # Assemble prompt with filtered schema
        from config import PROMPT_RULES, PROMPT_GUIDE
        
        instruction = PROMPT_RULES + PROMPT_GUIDE
        final_prompt = self.t2css_pipeline.assemble_prompt(
            query=question,
            top_k_schema=top_k_schema,
            instruction=instruction,
            few_shot_examples=examples
        )
        
        return final_prompt
    
    def toggle_t2css(self, enabled: bool):
        """
        Enable or disable T2CSS semantic filtering
        
        Args:
            enabled: True to enable T2CSS, False to use standard schema
        """
        self.use_t2css = enabled
        print(f"[T2CSS Integration] T2CSS semantic filtering: {'ENABLED' if enabled else 'DISABLED'}")
        
        if enabled and self.t2css_pipeline is None:
            self._initialize_t2css()


def create_enhanced_text2cypher(neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm, use_t2css: bool = True, top_k_schema: int = 10):
    """
    Factory function to create an enhanced Text2Cypher instance with T2CSS
    
    Args:
        llm: Language model instance
        use_t2css: Enable T2CSS semantic filtering
        top_k_schema: Number of schema elements to include
        
    Returns:
        T2CypherWithT2CSS instance
    """
    return T2CypherWithT2CSS(neo4j_uri, neo4j_user, neo4j_password, llm, use_t2css, top_k_schema)


# Example usage
if __name__ == "__main__":
    from llm import OllamaLLM
    
    print("="*80)
    print("T2CSS Integration Example")
    print("="*80)
    
    # Create enhanced Text2Cypher with T2CSS
    llm = OllamaLLM()
    # Example Neo4j creds (replace when running standalone)
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
    t2c = create_enhanced_text2cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm, use_t2css=True, top_k_schema=10)
    
    # Test query
    test_question = "Find all CVEs related to Microsoft Windows products"
    
    print(f"\nTest Question: {test_question}")
    print("\nGenerating Cypher query with T2CSS semantic filtering...")
    
    try:
        result = t2c.text_to_cypher_with_fallback(test_question)
        print("\n" + "="*80)
        print("RESULT")
        print("="*80)
        print(f"Status: {result.get('status')}")
        print(f"Cypher: {result.get('cypher')}")
        if result.get('result'):
            print(f"Results: {len(result.get('result', []))} records found")
    except Exception as e:
        print(f"Error: {e}")
