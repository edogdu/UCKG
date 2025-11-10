"""
Text-to-Cypher Semantic Schema (T2CSS) Pipeline

Implementation of the T2CSS methodology from the 2025 DSS paper:
"Prompting large language models based on semantic schema for text-to-Cypher transformation"

This module provides semantic schema-based prompting for improved Text-to-Cypher generation
by filtering relevant schema elements using embedding similarity.
"""

import os
import sys
import json
import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import re

# Import from local config
try:
    from config import CYBERSECURITY_SEMANTICS
except ImportError:
    # Fallback if running as standalone
    CYBERSECURITY_SEMANTICS = {}


@dataclass
class SchemaTriple:
    """Represents a semantic schema triple with embedding"""
    subject: str
    predicate: str
    object: str
    text: str
    embedding: Optional[np.ndarray] = None
    semantic_description: str = ""
    properties: list = None  # For node properties
    
    def __post_init__(self):
        if self.properties is None:
            self.properties = []


class T2CSSPipeline:
    """
    Text-to-Cypher Semantic Schema Pipeline
    
    Implements the T2CSS methodology for semantic schema-based prompting:
    1. Semantic schema extraction from Neo4j
    2. Transformation into textual triples
    3. Embedding generation using sentence transformers
    4. Adaptive filtering via cosine similarity
    5. Prompt assembly for LLM
    6. Query validation
    """
    
    def __init__(self, embedding_model: str = "nomic-embed-text", top_k: int = 10):
        """
        Initialize T2CSS Pipeline
        
        Args:
            embedding_model: Name of the embedding model from Ollama (default: nomic-embed-text)
            top_k: Number of top similar schema triples to include (default: 10)
        """
        self.embedding_model = embedding_model
        self.top_k = top_k
        self.schema_triples: List[SchemaTriple] = []
        self.schema_embeddings: Optional[np.ndarray] = None
        
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"[T2CSS] Initialized pipeline with model={embedding_model}, top_k={top_k}")
    
    def generate_semantic_texts(self, schema_text: str) -> List[SchemaTriple]:
        """
        Step 1 & 2: Extract and transform schema into semantic textual triples
        
        Converts raw schema format into structured triples with semantic descriptions:
        - Node triples: (NodeLabel, "is a", "description") + properties
        - Relationship triples: (Source, RelationshipType, Target) + semantics
        
        Args:
            schema_text: Raw schema string from Neo4j
            
        Returns:
            List of SchemaTriple objects with textual representations
        """
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print("\n[T2CSS Step 1-2] Generating semantic texts from schema...")
        
        schema_triples = []
        lines = schema_text.split('\n')
        current_section = None
        
        for line in lines:
            line_stripped = line.strip()
            
            # Detect section headers
            if line_stripped.startswith('NODES:'):
                current_section = 'nodes'
                continue
            elif line_stripped.startswith('RELATIONSHIPS:'):
                current_section = 'relationships'
                continue
            elif not line_stripped:
                continue
            
            # Process node triples WITH properties
            if current_section == 'nodes' and '{' in line_stripped:
                node_label = line_stripped.split('{')[0].strip()
                
                # Extract properties
                properties_part = line_stripped.split('{')[1].split('}')[0].strip()
                properties = [p.strip() for p in properties_part.split(',')]
                
                # Get semantic description
                semantic_desc = CYBERSECURITY_SEMANTICS.get(
                    node_label, 
                    f"A {node_label} node in the cybersecurity knowledge graph"
                )
                
                # Create enriched semantic triple with properties
                property_summary = f"with properties: {', '.join(properties[:5])}"  # First 5 properties
                if len(properties) > 5:
                    property_summary += f" (and {len(properties) - 5} more)"
                
                triple_text = f"{node_label} is a {semantic_desc} {property_summary}"
                triple = SchemaTriple(
                    subject=node_label,
                    predicate="is_a",
                    object="node_type",
                    text=triple_text,
                    semantic_description=semantic_desc,
                    properties=properties
                )
                schema_triples.append(triple)
            
            # Process relationship triples (robustly handle spaces around '-[:')
            elif current_section == 'relationships':
                try:
                    # Pattern: (:Source) -[:RELATION]-> (:Target)
                    m = re.search(r"\(:\s*([A-Za-z0-9_]+)\)\s*-\s*\[:\s*([A-Z_]+)\s*\]->\s*\(:\s*([A-Za-z0-9_]+)\)", line_stripped)
                    if not m:
                        continue
                    source, relationship, target = m.group(1), m.group(2), m.group(3)

                    semantic_desc = CYBERSECURITY_SEMANTICS.get(
                        relationship,
                        f"{source} is related to {target} via {relationship}"
                    )

                    triple_text = f"{source} {relationship} {target}: {semantic_desc}"
                    triple = SchemaTriple(
                        subject=source,
                        predicate=relationship,
                        object=target,
                        text=triple_text,
                        semantic_description=semantic_desc
                    )
                    schema_triples.append(triple)
                except Exception as e:
                    print(f"[Warning] Failed to parse relationship: {line_stripped} - {e}")
                    continue
        
        self.schema_triples = schema_triples
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"[T2CSS] Generated {len(schema_triples)} semantic triples")
        return schema_triples
    
    def embed_schema_triples(self) -> np.ndarray:
        """
        Step 3: Generate embeddings for each schema triple using Ollama's nomic-embed-text
        
        Returns:
            Numpy array of embeddings (shape: [num_triples, embedding_dim])
        """
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print("\n[T2CSS Step 3] Embedding schema triples...")
        
        if not self.schema_triples:
            raise ValueError("No schema triples available. Call generate_semantic_texts() first.")
        
        import requests
        
        embeddings = []
        for i, triple in enumerate(self.schema_triples):
            try:
                # Call Ollama API for embedding
                response = requests.post(
                    'http://localhost:11434/api/embeddings',
                    json={
                        'model': self.embedding_model,
                        'prompt': triple.text
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    embedding = np.array(response.json()['embedding'])
                    triple.embedding = embedding
                    embeddings.append(embedding)
                else:
                    print(f"[Warning] Failed to embed triple {i}: {response.status_code}")
                    # Use zero vector as fallback
                    embeddings.append(np.zeros(768))  # nomic-embed-text dimension
                    
            except Exception as e:
                print(f"[Warning] Error embedding triple {i}: {e}")
                embeddings.append(np.zeros(768))
        
        self.schema_embeddings = np.array(embeddings)
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"[T2CSS] Embedded {len(embeddings)} triples with shape {self.schema_embeddings.shape}")
        return self.schema_embeddings
    
    def filter_schema_by_similarity(self, query: str) -> List[SchemaTriple]:
        """
        Step 4: Adaptive filtering using cosine similarity
        
        Filters schema triples based on semantic similarity to the user query.
        Returns top-k most relevant schema elements.
        
        Args:
            query: Natural language user question
            
        Returns:
            List of top-k most relevant SchemaTriple objects
        """
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"\n[T2CSS Step 4] Filtering schema by similarity to query: '{query}'")
        
        if self.schema_embeddings is None:
            raise ValueError("Schema embeddings not available. Call embed_schema_triples() first.")
        
        import requests
        
        # Get query embedding
        try:
            response = requests.post(
                'http://localhost:11434/api/embeddings',
                json={
                    'model': self.embedding_model,
                    'prompt': query
                },
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"[Error] Failed to embed query: {response.status_code}")
                # Fallback: return first top_k triples
                return self.schema_triples[:self.top_k]
            
            query_embedding = np.array(response.json()['embedding'])
            
        except Exception as e:
            print(f"[Error] Failed to get query embedding: {e}")
            return self.schema_triples[:self.top_k]
        
        # Calculate cosine similarity
        similarities = self._cosine_similarity(query_embedding, self.schema_embeddings)
        
        # Get top-k indices
        top_k_indices = np.argsort(similarities)[-self.top_k:][::-1]
        
        # Get top-k triples
        top_k_schema = [self.schema_triples[i] for i in top_k_indices]
        
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"[T2CSS] Selected top-{self.top_k} relevant schema triples:")
            for i, (idx, sim) in enumerate(zip(top_k_indices, similarities[top_k_indices]), 1):
                print(f"  {i}. [similarity={sim:.3f}] {self.schema_triples[idx].text[:80]}...")
        
        return top_k_schema
    
    def _cosine_similarity(self, query_vec: np.ndarray, schema_vecs: np.ndarray) -> np.ndarray:
        """
        Calculate cosine similarity between query and schema embeddings
        
        Args:
            query_vec: Query embedding vector
            schema_vecs: Matrix of schema embedding vectors
            
        Returns:
            Array of similarity scores
        """
        # Normalize vectors
        query_norm = query_vec / (np.linalg.norm(query_vec) + 1e-8)
        schema_norms = schema_vecs / (np.linalg.norm(schema_vecs, axis=1, keepdims=True) + 1e-8)
        
        # Calculate cosine similarity
        similarities = np.dot(schema_norms, query_norm)
        return similarities
    
    def assemble_prompt(
        self,
        query: str,
        top_k_schema: List[SchemaTriple],
        instruction: str = None,
        few_shot_examples: str = ""
    ) -> str:
        """
        Step 5: Assemble the final prompt for LLM
        
        Combines instruction, filtered semantic schema, and user question
        into a structured prompt optimized for Cypher generation.
        
        Args:
            query: User's natural language question
            top_k_schema: Filtered schema triples relevant to the query
            instruction: System instruction (optional, uses default if None)
            few_shot_examples: Few-shot examples (optional)
            
        Returns:
            Complete prompt string ready for LLM
        """
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print("\n[T2CSS Step 5] Assembling prompt...")
        
        # Default instruction if not provided
        if instruction is None:
            instruction = """You are a Neo4j Cypher expert for a Cybersecurity Knowledge Graph.

CRITICAL RULES:
1. Use EXACT labels and relationship types from the filtered schema below
2. Always specify node labels: (cve:UcoCVE) not (cve)
3. Always specify relationship types: -[:UCOEXHASCPE]-> not -[]->
4. Return ONLY the Cypher query - no markdown, no explanations
5. Add LIMIT 100 for large result sets"""
        
        # Build filtered schema section
        filtered_schema_text = "FILTERED SEMANTIC SCHEMA (relevant to your question):\n\n"
        
        # Group by nodes and relationships
        node_triples = [t for t in top_k_schema if t.predicate == "is_a"]
        rel_triples = [t for t in top_k_schema if t.predicate != "is_a"]
        
        if node_triples:
            filtered_schema_text += "Relevant Nodes:\n"
            for triple in node_triples:
                filtered_schema_text += f"  • {triple.subject}: {triple.semantic_description}\n"
            filtered_schema_text += "\n"
        
        if rel_triples:
            filtered_schema_text += "Relevant Relationships:\n"
            for triple in rel_triples:
                filtered_schema_text += f"  • ({triple.subject})-[:{triple.predicate}]->({triple.object})\n"
                filtered_schema_text += f"    Meaning: {triple.semantic_description}\n"
        
        # Assemble final prompt
        final_prompt = f"""[INSTRUCTION]
{instruction}

[{filtered_schema_text}]

{few_shot_examples}

[USER QUESTION]
{query}

Generate the Cypher query:
"""
        
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print(f"[T2CSS] Assembled prompt with {len(top_k_schema)} schema elements")
            print(f"[T2CSS] Prompt length: {len(final_prompt)} characters")
        
        return final_prompt
    
    def validate_generated_query(self, cypher_query: str, neo4j_driver) -> Tuple[bool, str]:
        """
        Step 6: Validate the generated Cypher query against Neo4j
        
        Args:
            cypher_query: Generated Cypher query
            neo4j_driver: Neo4j driver instance
            
        Returns:
            Tuple of (is_valid, message)
        """
        if os.getenv("T2CSS_VERBOSE", "0") == "1":
            print("\n[T2CSS Step 6] Validating generated query...")
        
        try:
            with neo4j_driver.session() as session:
                # Try to explain the query (doesn't execute it)
                result = session.run(f"EXPLAIN {cypher_query}")
                result.consume()
                print("[T2CSS] Query validation: PASSED")
                return True, "Query is syntactically valid"
        except Exception as e:
            print(f"[T2CSS] Query validation: FAILED - {e}")
            return False, str(e)
    
    def save_embeddings(self, filepath: str):
        """Save schema triples and embeddings to file"""
        if self.schema_embeddings is None:
            print("[Warning] No embeddings to save")
            return
        
        data = {
            'triples': [
                {
                    'subject': t.subject,
                    'predicate': t.predicate,
                    'object': t.object,
                    'text': t.text,
                    'semantic_description': t.semantic_description,
                    # Persist parsed properties so they are available after reloads
                    'properties': t.properties or []
                }
                for t in self.schema_triples
            ],
            'embeddings': self.schema_embeddings.tolist()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[T2CSS] Saved embeddings to {filepath}")
    
    def load_embeddings(self, filepath: str):
        """Load schema triples and embeddings from file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.schema_triples = [
            SchemaTriple(
                subject=t['subject'],
                predicate=t['predicate'],
                object=t['object'],
                text=t['text'],
                semantic_description=t['semantic_description'],
                # Restore properties if present (older files may not have them)
                properties=t.get('properties', []),
                embedding=None  # Will be set from embeddings array
            )
            for t in data['triples']
        ]
        
        self.schema_embeddings = np.array(data['embeddings'])
        
        # Assign embeddings to triples
        for i, triple in enumerate(self.schema_triples):
            triple.embedding = self.schema_embeddings[i]
        
        print(f"[T2CSS] Loaded {len(self.schema_triples)} triples with embeddings from {filepath}")


# Example workflow function
def run_t2css_example():
    """
    Example workflow demonstrating the complete T2CSS pipeline
    """
    print("="*80)
    print("T2CSS Pipeline Example Workflow")
    print("="*80)
    
    # Step 1: Load schema (from cache or generate)
    schema_cache_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'shared', 'schema_cache.txt'
    )
    
    if not os.path.exists(schema_cache_path):
        print("[Error] Schema cache not found. Please generate schema first.")
        return
    
    with open(schema_cache_path, 'r') as f:
        schema_text = f.read()
    
    print(f"\n[Step 1] Loaded schema from cache ({len(schema_text)} chars)")
    
    # Step 2: Initialize T2CSS pipeline
    pipeline = T2CSSPipeline(embedding_model="nomic-embed-text", top_k=10)
    
    # Step 3: Generate semantic triples
    schema_triples = pipeline.generate_semantic_texts(schema_text)
    
    # Step 4: Embed schema triples
    embeddings = pipeline.embed_schema_triples()
    
    # Optional: Save embeddings for future use
    embeddings_path = os.path.join(os.path.dirname(__file__), 'schema_embeddings.json')
    pipeline.save_embeddings(embeddings_path)
    
    # Step 5: Process a natural language query
    test_query = "Find all CVEs related to Microsoft Windows"
    print(f"\n[Test Query] {test_query}")
    
    # Step 6: Filter schema by similarity
    top_k_schema = pipeline.filter_schema_by_similarity(test_query)
    
    # Step 7: Assemble prompt
    few_shot_examples = """
EXAMPLES:
"Find all CVEs" → MATCH (cve:UcoCVE) RETURN cve LIMIT 100
"Show CVEs for Microsoft" → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft' RETURN cve
"""
    
    final_prompt = pipeline.assemble_prompt(
        query=test_query,
        top_k_schema=top_k_schema,
        few_shot_examples=few_shot_examples
    )
    
    # Step 8: Display the final prompt
    print("\n" + "="*80)
    print("FINAL PROMPT FOR LLM")
    print("="*80)
    print(final_prompt)
    print("="*80)
    
    return final_prompt


if __name__ == "__main__":
    # Run example workflow
    run_t2css_example()
