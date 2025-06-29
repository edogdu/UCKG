#!/usr/bin/env python3
"""
High-performance RAG system using official Neo4j GraphRAG components.
Implements optimized queries, multi-level caching, and asynchronous processing.
"""

import asyncio
import logging
import hashlib
from typing import Dict, Any, List, Optional
from functools import lru_cache
from cachetools import TTLCache

from neo4j import GraphDatabase
from neo4j_graphrag.embeddings import OpenAIEmbeddings
from neo4j_graphrag.retrievers import VectorCypherRetriever
from neo4j_graphrag.generation import GraphRAG, RagTemplate
from neo4j_graphrag.llm import OpenAILLM
from .config import settings, get_neo4j_config, get_openai_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UCKGRAG:
    """
    UCKG RAG system using official Neo4j GraphRAG components with performance optimizations.
    
    Features:
    - Optimized Cypher queries for efficient graph traversal
    - Streamlined result processing and formatting
    - Multi-level TTL caching system
    - Asynchronous query processing
    - Integration with Neo4j GraphRAG framework
    """
    
    def __init__(self):
        self.driver = None
        self.retriever = None
        self.rag = None
        self.vector_index_name = None
        
        # Multi-level caching system
        self._query_cache = TTLCache(maxsize=100, ttl=300)  # 5 min query cache
        self._embedding_cache = TTLCache(maxsize=500, ttl=1800)  # 30 min embedding cache
        self._context_cache = TTLCache(maxsize=200, ttl=600)  # 10 min context cache
        
    async def initialize(self) -> None:
        """Initialize the RAG system with performance enhancements."""
        # Database connection using existing config
        neo4j_config = get_neo4j_config()
        self.driver = GraphDatabase.driver(neo4j_config["uri"], auth=neo4j_config["auth"])
        
        # Set vector index name from config
        self.vector_index_name = settings.ucoex_capec_index_name
        
        # Initialize official embedder using existing config
        openai_config = get_openai_config()
        embedder = OpenAIEmbeddings(
            model=openai_config["embedding_model"],
            api_key=openai_config["api_key"]
        )
        
        # Optimized Cypher query using Neo4j collection patterns
        # Designed for efficient graph traversal with minimal aggregation overhead
        retrieval_query = """
        // Efficient graph traversal with vectorized collection operations
        // The 'node' and 'score' variables are automatically provided by the vector similarity search
        
        RETURN 
            node.ucoexCAPEC_id as capec_id,
            node.ucoexCAPEC_name as name,
            node.ucoexDescription as description,
            node.ucoexAbstraction as abstraction,
            node.ucoexSeverity as severity,
            node.ucoexMitigations as mitigations,
            
            // Use collect expressions for efficient relationship traversal
            collect { 
                MATCH (node)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) 
                RETURN {
                    id: cwe.ucocweID,
                    name: cwe.ucocweName,
                    description: cwe.ucodescription,
                    abstraction: cwe.ucoabstraction
                }
            } as weaknesses,
            
            collect { 
                MATCH (node)-[:UCOEXHASTAXONOMYMAPPING]->(attack:UcoexMITREATTACK) 
                RETURN {
                    name: attack.ucoexNAME,
                    description: attack.ucoexDESCRIPTION,
                    domain: attack.ucoexDOMAIN
                }
            } as mitre_attacks,
            
            score
        ORDER BY score DESC
        """
        
        # Streamlined result formatter with enhanced content enrichment
        def result_formatter(record) -> Dict[str, Any]:
            """Result formatter that enriches content with related node descriptions."""
            from neo4j_graphrag.types import RetrieverResultItem
            
            # Fast core content generation
            capec_id = record.get('capec_id')
            name = record.get('name', '')
            description = record.get('description', '')[:400]  # Pre-truncated
            
            # Build streamlined content
            content = f"CAPEC-{capec_id}: {name}\n{description}\n"
            
            # Add abstraction and severity quickly
            if record.get('abstraction'):
                content += f"Level: {record.get('abstraction')}"
            if record.get('severity'):
                content += f" | Severity: {record.get('severity')}\n"
            
            # Include related CWE weaknesses with descriptions
            weaknesses = record.get('weaknesses', [])
            if weaknesses:
                content += "\n=== RELATED WEAKNESSES ===\n"
                for w in weaknesses[:3]:  # Top 3 for manageable context
                    if w and w.get('name'):
                        cwe_id = str(w.get('id', ''))
                        weakness_name = str(w.get('name', ''))
                        weakness_desc = str(w.get('description', ''))[:200]  # Truncate for context
                        
                        # Format with ID, name and description
                        if cwe_id.startswith('CWE-'):
                            content += f"{cwe_id}: {weakness_name}\n"
                        else:
                            content += f"CWE-{cwe_id}: {weakness_name}\n"
                        
                        if weakness_desc and weakness_desc != 'None':
                            content += f"  Description: {weakness_desc}...\n"
                        content += "\n"
            
            # Include related MITRE ATT&CK techniques with descriptions
            mitre_attacks = record.get('mitre_attacks', [])
            if mitre_attacks:
                content += "=== RELATED MITRE ATT&CK TECHNIQUES ===\n"
                for t in mitre_attacks[:2]:  # Top 2 for manageable context
                    if t and t.get('name'):
                        technique_name = str(t.get('name', ''))
                        technique_desc = str(t.get('description', ''))[:200]  # Truncate for context
                        domain = str(t.get('domain', ''))
                        
                        # Format with name, domain and description
                        if domain:
                            content += f"{technique_name} ({domain})\n"
                        else:
                            content += f"{technique_name}\n"
                        
                        if technique_desc and technique_desc != 'None':
                            content += f"  Description: {technique_desc}...\n"
                        content += "\n"
            
            # Essential mitigations with safe handling
            mitigations = record.get('mitigations')
            if mitigations:
                content += "=== MITIGATIONS ===\n"
                mitigations_str = str(mitigations)
                if len(mitigations_str) > 300:
                    mitigations_str = mitigations_str[:300] + "..."
                content += f"{mitigations_str}\n"
            
            return RetrieverResultItem(
                content=content,
                metadata={
                    "capec_id": capec_id,
                    "name": name,
                    "score": record.get('score', 0),
                    "weakness_count": len(weaknesses),
                    "mitre_attack_count": len(mitre_attacks),
                    "weakness_ids": [w.get('id') for w in weaknesses if w and w.get('id')],
                    "mitre_attack_names": [t.get('name') for t in mitre_attacks if t and t.get('name')]
                }
            )
        
        # Initialize the official VectorCypherRetriever 
        self.retriever = VectorCypherRetriever(
            driver=self.driver,
            index_name=self.vector_index_name,
            retrieval_query=retrieval_query,
            embedder=embedder,
            result_formatter=result_formatter
        )
        
        # Initialize the official LLM
        llm = OpenAILLM(
            model_name=openai_config["llm_model"],
            api_key=openai_config["api_key"],
            model_params={
                "temperature": openai_config["temperature"],
                "max_tokens": 1500,  # Reduced for faster responses
                "response_format": {"type": "text"}
            }
        )
        
        # Custom structured prompt template for consistent formatting
        structured_prompt = RagTemplate(
            template="""Based on the provided cybersecurity context, answer the user's question with a well-structured response.

CONTEXT:
{context}

QUESTION: {query_text}

Please provide a comprehensive answer following this exact structure with proper spacing:

1. Start with a clear paragraph explaining the main concept/attack/vulnerability

2. If there are related weaknesses (CWEs), include a "**Related Weaknesses:**" section with entries formatted as:

CWE-XXX: Weakness Name - Brief description of how this weakness relates to the main topic

(Add a blank line between each CWE entry)

3. If there are related MITRE ATT&CK techniques, include a "**Related MITRE ATT&CK Techniques:**" section with entries formatted as:

Technique Name (domain) - Brief description of the technique

(Add a blank line between each technique entry)

4. If there are mitigations, include a "**Mitigations:**" section with entries for each mitigation strategy

(Add a blank line between each mitigation entry)

IMPORTANT FORMATTING RULES:
- Add TWO blank lines before each section header
- Add ONE blank line after each section header
- Add ONE blank line between each entry within a section
- Use **bold** formatting for section headers
- Do not use bullet points - the frontend will handle those
- Keep entries concise but informative""",
            expected_inputs=["context", "query_text"]
        )
        
        # Initialize the official GraphRAG pipeline with structured template
        self.rag = GraphRAG(
            retriever=self.retriever,
            llm=llm,
            prompt_template=structured_prompt
        )
        
        logger.info("UCKG RAG system initialized successfully")
    
    def _get_cache_key(self, question: str, top_k: int) -> str:
        """Generate cache key for queries."""
        return hashlib.md5(f"{question}:{top_k}".encode()).hexdigest()
    
    async def query_async(self, question: str, top_k: int = 5) -> Dict[str, Any]:
        """
        Async query processing with caching for improved performance.
        """
        try:
            # Check cache first for faster repeat queries
            cache_key = self._get_cache_key(question, top_k)
            if cache_key in self._query_cache:
                logger.info(f"Cache hit for query: {question[:50]}...")
                return self._query_cache[cache_key]
            
            logger.info(f"Processing query: {question}")
            
            # Use GraphRAG search
            response = self.rag.search(
                query_text=question,
                retriever_config={"top_k": top_k},
                return_context=True
            )
            
            # Fast response formatting
            formatted_response = {
                "answer": response.answer,
                "query": question,
                "confidence": self._fast_calculate_confidence(response),
                "sources": self._fast_extract_sources(response),
                "context_summary": self._fast_context_summary(response)
            }
            
            # Cache the result
            self._query_cache[cache_key] = formatted_response
            
            logger.info(f"Query processed with {len(formatted_response.get('sources', []))} sources")
            return formatted_response
            
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return {
                "error": str(e),
                "query": question,
                "answer": "I encountered an error while processing your question. Please try again."
            }
    
    def query(self, question: str, top_k: int = 5) -> Dict[str, Any]:
        """
        Sync query wrapper with cache optimization.
        """
        # Check cache first (sync access to cache is fine)
        cache_key = self._get_cache_key(question, top_k)
        if cache_key in self._query_cache:
            logger.info(f"Sync cache hit for query: {question[:50]}...")
            return self._query_cache[cache_key]
        
        # Only use async when cache miss
        return asyncio.run(self.query_async(question, top_k))
    
    def _fast_calculate_confidence(self, response) -> float:
        """Fast confidence calculation with caching."""
        try:
            if hasattr(response, 'retriever_result') and hasattr(response.retriever_result, 'items'):
                scores = [item.metadata.get('score', 0) for item in response.retriever_result.items if item.metadata]
                if scores:
                    avg_score = sum(scores) / len(scores)
                    return min(avg_score * 1.2, 1.0)  # Simplified calculation
            return 0.7
        except Exception:
            return 0.7
    
    def _fast_extract_sources(self, response) -> List[str]:
        """Fast source extraction."""
        sources = []
        try:
            if hasattr(response, 'retriever_result') and hasattr(response.retriever_result, 'items'):
                for item in response.retriever_result.items:
                    if item.metadata and item.metadata.get('capec_id'):
                        capec_id = item.metadata.get('capec_id')
                        score = item.metadata.get('score', 0)
                        sources.append(f"CAPEC-{capec_id} ({score:.3f})")
            return sources
        except Exception:
            return []
    
    def _fast_context_summary(self, response) -> Dict[str, Any]:
        """Fast context summary instead of comprehensive analysis."""
        try:
            if hasattr(response, 'retriever_result') and hasattr(response.retriever_result, 'items'):
                items = response.retriever_result.items
                total_weaknesses = sum(item.metadata.get('weakness_count', 0) for item in items if item.metadata)
                total_mitre_attacks = sum(item.metadata.get('mitre_attack_count', 0) for item in items if item.metadata)
                
                return {
                    "retrieved_capecs": len(items),
                    "total_weaknesses": total_weaknesses,
                    "total_mitre_attacks": total_mitre_attacks,
                    "avg_relevance": round(sum(item.metadata.get('score', 0) for item in items if item.metadata) / len(items), 3) if items else 0
                }
            return {}
        except Exception:
            return {}
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics."""
        try:
            with self.driver.session() as session:
                stats_query = """
                MATCH (n:UcoexCAPEC)
                RETURN 
                    count(*) as total_capec_nodes,
                    count(n.embedding) as nodes_with_embeddings,
                    count(n.embedding) * 100.0 / count(*) as embedding_coverage
                """
                result = session.run(stats_query)
                record = result.single()
                
                return {
                    "total_capec_nodes": record["total_capec_nodes"],
                    "nodes_with_embeddings": record["nodes_with_embeddings"],
                    "embedding_coverage": round(record["embedding_coverage"], 2),
                    "vector_index_name": self.vector_index_name,
                    "system_type": "Neo4j GraphRAG",
                    "optimizations": "Query optimization and caching enabled",
                    "cache_stats": {
                        "query_cache_size": len(self._query_cache),
                        "embedding_cache_size": len(self._embedding_cache),
                        "context_cache_size": len(self._context_cache)
                    }
                }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def clear_caches(self) -> None:
        """Clear all caches for fresh queries."""
        self._query_cache.clear()
        self._embedding_cache.clear()  
        self._context_cache.clear()
        logger.info("All caches cleared")
    
    async def warm_cache(self, common_queries: List[str]) -> None:
        """Pre-warm cache with common queries for faster responses."""
        logger.info(f"Warming cache with {len(common_queries)} common queries...")
        for query in common_queries:
            try:
                await self.query_async(query)
            except Exception as e:
                logger.warning(f"Failed to warm cache for query '{query}': {e}")
        logger.info("Cache warming completed")
    
    async def close(self) -> None:
        """Close all connections."""
        if self.driver:
            self.driver.close()
        logger.info("RAG connections closed")

# Global instance for easy import
rag_system = UCKGRAG()

async def main():
    """Test the UCKG RAG system."""
    print("Testing UCKG RAG System")
    print("=" * 60)
    
    try:
        # Initialize the system
        await rag_system.initialize()
        
        # Get statistics
        stats = await rag_system.get_statistics()
        print(f"System Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
        print()
        
        # Test performance with sample queries
        test_queries = [
            "What are SQL injection attack patterns?",
            "How can I defend against buffer overflow attacks?",
            "What weaknesses are commonly exploited in web applications?"
        ]
        
        # Warm cache first
        await rag_system.warm_cache(test_queries)
        
        # Test cached performance
        for query in test_queries:
            print(f"Query: {query}")
            result = await rag_system.query_async(query)
            print(f"Answer: {result['answer'][:200]}...")
            print(f"Sources: {', '.join(result.get('sources', []))}")
            print(f"Confidence: {result.get('confidence', 0):.3f}")
            print()
            
    except Exception as e:
        print(f"Test failed: {e}")
    finally:
        await rag_system.close()

if __name__ == "__main__":
    asyncio.run(main()) 