#!/usr/bin/env python3
"""
FIXED: Optimized embedding setup using official Neo4j GraphRAG package.
This fixes the upsert_vectors usage and ID matching issues.
"""

import asyncio
import logging
import os
import sys
from typing import List, Dict, Any, Optional

from neo4j import GraphDatabase
from neo4j_graphrag.embeddings import OpenAIEmbeddings
from neo4j_graphrag.indexes import create_vector_index, upsert_vectors
from neo4j_graphrag.types import EntityType
from core.config import settings, get_neo4j_config, get_openai_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FixedEmbeddingSetup:
    """
    FIXED: Corrected embedding setup using proper Neo4j GraphRAG API usage.
    
    Key fixes:
    - Use CAPEC IDs instead of internal node IDs for upsert_vectors
    - Correct parameter usage for matching nodes
    - Direct Cypher approach as fallback for better control
    """
    
    def __init__(self):
        self.driver = None
        self.embedder = None
        self.vector_index_name = "ucoex_capec_embeddings"
        self.embedding_dimension = settings.vector_dimension  # Use config value
        
    async def initialize(self):
        """Initialize with correct configuration."""
        # Database connection using existing config
        neo4j_config = get_neo4j_config()
        self.driver = GraphDatabase.driver(neo4j_config["uri"], auth=neo4j_config["auth"])
        
        # Initialize the official OpenAI embedder with correct model
        openai_config = get_openai_config()
        self.embedder = OpenAIEmbeddings(
            model=openai_config["embedding_model"],  # Uses text-embedding-3-small
            api_key=openai_config["api_key"]
        )
        
        logger.info(f"✅ Fixed embedding setup initialized:")
        logger.info(f"   Model: {openai_config['embedding_model']}")
        logger.info(f"   Dimensions: {self.embedding_dimension}")
    
    def create_vector_index(self):
        """Create vector index using official Neo4j GraphRAG function."""
        try:
            create_vector_index(
                driver=self.driver,
                name=self.vector_index_name,
                label="UcoexCAPEC",
                embedding_property="embedding",
                dimensions=self.embedding_dimension,
                similarity_fn="cosine",
                fail_if_exists=False
            )
            logger.info(f"✅ Created vector index: {self.vector_index_name}")
        except Exception as e:
            logger.info(f"Vector index may already exist: {e}")
    
    def get_capec_nodes_for_embedding(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get CAPEC nodes that need embeddings with FIXED query."""
        query = """
        MATCH (n:UcoexCAPEC)
        WHERE n.embedding IS NULL
        RETURN 
            n.ucoexCAPEC_id as capec_id,
            n.ucoexCAPEC_name as name,
            n.ucoexDescription as description,
            n.ucoexAbstraction as abstraction,
            n.ucoexSeverity as severity,
            n.ucoexLikelihood as likelihood,
            n.ucoexPrerequisites as prerequisites,
            n.ucoexSkills_Required as skills_required,
            n.ucoexConsequences as consequences,
            n.ucoexMitigations as mitigations
        ORDER BY toInteger(n.ucoexCAPEC_id)
        """
        
        if limit:
            query += f" LIMIT {limit}"
        
        with self.driver.session() as session:
            result = session.run(query)
            return [record.data() for record in result]
    
    def create_embedding_text(self, node: Dict[str, Any]) -> str:
        """Create comprehensive embedding text with all available CAPEC properties."""
        text_parts = []
        
        # Core identification - most important for search
        if node.get("capec_id"):
            text_parts.append(f"CAPEC-{node['capec_id']}")
        if node.get("name"):
            text_parts.append(f"Name: {node['name']}")
        
        # Primary content - description is crucial for semantic matching
        if node.get("description"):
            desc = node["description"]
            # Handle both string and list formats
            if isinstance(desc, list) and desc:
                desc_text = desc[0] if desc[0] else (desc[1] if len(desc) > 1 else "")
            else:
                desc_text = str(desc) if desc else ""
            
            if desc_text:
                text_parts.append(f"Description: {desc_text}")
        
        # Technical classification
        if node.get("abstraction"):
            text_parts.append(f"Abstraction: {node['abstraction']}")
        if node.get("severity"):
            text_parts.append(f"Severity: {node['severity']}")
        if node.get("likelihood"):
            text_parts.append(f"Likelihood: {node['likelihood']}")
        
        # Attack methodology
        if node.get("prerequisites"):
            prereq = node["prerequisites"]
            if isinstance(prereq, list) and prereq:
                text_parts.append(f"Prerequisites: {'; '.join(str(p) for p in prereq if p)}")
            elif prereq:
                text_parts.append(f"Prerequisites: {prereq}")
        
        if node.get("skills_required"):
            skills = node["skills_required"]
            if isinstance(skills, list) and skills:
                text_parts.append(f"Skills Required: {'; '.join(str(s) for s in skills if s)}")
            elif skills:
                text_parts.append(f"Skills Required: {skills}")
        
        # Impact and mitigation
        if node.get("consequences"):
            consequences = node["consequences"]
            if isinstance(consequences, list) and consequences:
                text_parts.append(f"Consequences: {'; '.join(str(c) for c in consequences if c)}")
            elif consequences:
                text_parts.append(f"Consequences: {consequences}")
        
        if node.get("mitigations"):
            mitigations = node["mitigations"]
            if isinstance(mitigations, list) and mitigations:
                text_parts.append(f"Mitigations: {'; '.join(str(m) for m in mitigations if m)}")
            elif mitigations:
                text_parts.append(f"Mitigations: {mitigations}")
        
        return " | ".join(text_parts)
    
    async def save_embeddings_direct_cypher(self, nodes_with_embeddings: List[Dict[str, Any]]):
        """
        FIXED: Save embeddings using direct Cypher for better control.
        This bypasses the upsert_vectors issues by using direct database operations.
        """
        logger.info(f"💾 Saving {len(nodes_with_embeddings)} embeddings using direct Cypher")
        
        with self.driver.session() as session:
            for i, item in enumerate(nodes_with_embeddings):
                capec_id = item["capec_id"]
                embedding = item["embedding"]
                
                try:
                    # Use parameterized query for safety
                    result = session.run("""
                    MATCH (n:UcoexCAPEC {ucoexCAPEC_id: $capec_id})
                    SET n.embedding = $embedding
                    RETURN n.ucoexCAPEC_id as id, n.ucoexCAPEC_name as name
                    """, capec_id=capec_id, embedding=embedding)
                    
                    record = result.single()
                    if record:
                        if (i + 1) % 10 == 0:  # Log every 10th save
                            logger.info(f"   ✅ {i+1}/{len(nodes_with_embeddings)}: CAPEC-{record['id']}")
                    else:
                        logger.warning(f"   ⚠️ Could not find CAPEC-{capec_id} to update")
                        
                except Exception as e:
                    logger.error(f"   ❌ Failed to save embedding for CAPEC-{capec_id}: {e}")
        
        logger.info(f"✅ Completed saving {len(nodes_with_embeddings)} embeddings")
    
    async def generate_and_save_embeddings(self, batch_size: int = 25):
        """
        FIXED: Generate embeddings and save them using the corrected approach.
        """
        # Get all nodes that need embeddings
        nodes = self.get_capec_nodes_for_embedding()
        total_nodes = len(nodes)
        
        if total_nodes == 0:
            logger.info("🎉 All UcoexCAPEC nodes already have embeddings!")
            return
        
        logger.info(f"🚀 Processing {total_nodes} CAPEC nodes in batches of {batch_size}")
        
        # Process in batches
        for i in range(0, total_nodes, batch_size):
            batch = nodes[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (total_nodes + batch_size - 1) // batch_size
            
            logger.info(f"⚡ Processing batch {batch_num}/{total_batches} ({len(batch)} nodes)")
            
            try:
                # Generate embeddings for this batch
                batch_with_embeddings = []
                
                for node in batch:
                    # Create embedding text
                    embedding_text = self.create_embedding_text(node)
                    
                    # Generate embedding
                    embedding = self.embedder.embed_query(embedding_text)
                    
                    batch_with_embeddings.append({
                        "capec_id": node["capec_id"],
                        "embedding": embedding,
                        "text_preview": embedding_text[:100] + "..."
                    })
                
                # Save embeddings using direct Cypher
                await self.save_embeddings_direct_cypher(batch_with_embeddings)
                
                logger.info(f"✅ Successfully processed batch {batch_num}/{total_batches}")
                
                # Small delay to respect API rate limits
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"❌ Failed to process batch {batch_num}: {e}")
                continue
    
    def get_embedding_statistics(self) -> Dict[str, Any]:
        """Get comprehensive embedding statistics."""
        query = """
        MATCH (n:UcoexCAPEC) 
        RETURN 
            count(*) as total_nodes,
            count(n.embedding) as nodes_with_embeddings,
            count(*) - count(n.embedding) as nodes_without_embeddings,
            count(n.embedding) * 100.0 / count(*) as coverage_percentage
        """
        
        with self.driver.session() as session:
            result = session.run(query)
            record = result.single()
            return record.data() if record else {
                "total_nodes": 0, 
                "nodes_without_embeddings": 0, 
                "nodes_with_embeddings": 0,
                "coverage_percentage": 0.0
            }
    
    async def run_fixed_embedding_setup(self, batch_size: int = 25):
        """
        Run the FIXED embedding setup with corrected API usage.
        """
        try:
            await self.initialize()
            
            # Create vector index
            self.create_vector_index()
            
            # Get initial statistics
            initial_stats = self.get_embedding_statistics()
            logger.info("=" * 70)
            logger.info("🚀 STARTING FIXED EMBEDDING GENERATION")
            logger.info("=" * 70)
            logger.info(f"📊 Total UcoexCAPEC nodes: {initial_stats['total_nodes']}")
            logger.info(f"✅ Nodes with embeddings: {initial_stats['nodes_with_embeddings']}")
            logger.info(f"⚠️ Nodes needing embeddings: {initial_stats['nodes_without_embeddings']}")
            logger.info(f"📈 Current coverage: {initial_stats['coverage_percentage']:.1f}%")
            
            # Generate and save embeddings
            await self.generate_and_save_embeddings(batch_size=batch_size)
            
            # Get final statistics
            final_stats = self.get_embedding_statistics()
            logger.info("=" * 70)
            logger.info("🎉 FIXED EMBEDDING GENERATION COMPLETED")
            logger.info("=" * 70)
            logger.info(f"📊 Final statistics:")
            logger.info(f"✅ Nodes with embeddings: {final_stats['nodes_with_embeddings']}")
            logger.info(f"⚠️ Remaining nodes: {final_stats['nodes_without_embeddings']}")
            logger.info(f"📈 Final coverage: {final_stats['coverage_percentage']:.1f}%")
            logger.info(f"🚀 Fixed API usage and direct Cypher saves")
            
        except Exception as e:
            logger.error(f"❌ Fixed embedding setup failed: {e}")
            raise
        finally:
            if self.driver:
                self.driver.close()

async def main():
    """Main function to run FIXED embedding setup."""
    logger.info("🚀 Starting FIXED CAPEC embedding generation...")
    
    setup = FixedEmbeddingSetup()
    await setup.run_fixed_embedding_setup(batch_size=25)
    
    logger.info("🎉 Fixed embedding setup completed!")

if __name__ == "__main__":
    asyncio.run(main()) 