#!/usr/bin/env python3
"""
UCKG Embedding Reset Tool

Utility to reset embeddings and searchContent properties for testing and development.
Allows you to start the embedding process from scratch.

Usage:
    python reset_embeddings.py --stats                    # Show current state
    python reset_embeddings.py --node-type UcoCVE         # Reset specific node type
    python reset_embeddings.py --all                      # Reset all node types
    python reset_embeddings.py --all --confirm            # Reset without confirmation
"""
import argparse
import logging
from typing import List, Dict, Optional
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EmbeddingReset:
    """Tool to reset embeddings and searchContent properties."""
    
    def __init__(self, 
                 neo4j_uri: str = "bolt://localhost:7687",
                 neo4j_auth: tuple = ("neo4j", "abcd90909090")):
        """
        Initialize the reset tool.
        
        Args:
            neo4j_uri: Neo4j database connection URI
            neo4j_auth: Neo4j authentication tuple (username, password)
        """
        self.neo4j_uri = neo4j_uri
        self.neo4j_auth = neo4j_auth
        
        # Connect to Neo4j
        self.driver = GraphDatabase.driver(neo4j_uri, auth=neo4j_auth)
        logger.info(f"✅ Connected to Neo4j at {neo4j_uri}")
    
    def get_embedding_stats(self) -> Dict:
        """Get current embedding statistics."""
        with self.driver.session() as session:
            stats = {}
            
            node_types = ["UcoCVE", "UcoVulnerability", "UcoexCPE", 
                         "UcoCWE", "UcoexMITREATTACK", "UcoexCAPEC"]
            
            total_nodes = 0
            total_embeddings = 0
            total_search_content = 0
            
            for node_type in node_types:
                result = session.run(f"""
                    MATCH (n:{node_type})
                    RETURN count(*) as total,
                           count(n.embedding) as with_embedding,
                           count(n.searchContent) as with_search_content
                """)
                
                record = result.single()
                node_stats = {
                    'total': record['total'],
                    'with_embedding': record['with_embedding'],
                    'with_search_content': record['with_search_content'],
                    'embedding_coverage': record['with_embedding'] / record['total'] * 100 if record['total'] > 0 else 0,
                    'search_content_coverage': record['with_search_content'] / record['total'] * 100 if record['total'] > 0 else 0
                }
                
                stats[node_type] = node_stats
                total_nodes += record['total']
                total_embeddings += record['with_embedding']
                total_search_content += record['with_search_content']
            
            stats['overall'] = {
                'total_nodes': total_nodes,
                'total_embeddings': total_embeddings,
                'total_search_content': total_search_content,
                'embedding_coverage': total_embeddings / total_nodes * 100 if total_nodes > 0 else 0,
                'search_content_coverage': total_search_content / total_nodes * 100 if total_nodes > 0 else 0
            }
            
            return stats
    
    def reset_node_type(self, node_type: str, confirm: bool = False) -> bool:
        """
        Reset embeddings and searchContent for a specific node type.
        
        Args:
            node_type: Type of cybersecurity node to reset
            confirm: Skip confirmation prompt if True
            
        Returns:
            True if reset was successful, False otherwise
        """
        # Get current stats
        with self.driver.session() as session:
            result = session.run(f"""
                MATCH (n:{node_type})
                RETURN count(*) as total,
                       count(n.embedding) as with_embedding,
                       count(n.searchContent) as with_search_content
            """)
            
            record = result.single()
            total = record['total']
            with_embedding = record['with_embedding']
            with_search_content = record['with_search_content']
        
        if total == 0:
            logger.error(f"❌ No nodes found for type: {node_type}")
            return False
        
        if with_embedding == 0 and with_search_content == 0:
            logger.info(f"✅ {node_type} already has no embeddings or searchContent")
            return True
        
        logger.info(f"🔍 {node_type} reset summary:")
        logger.info(f"   Total nodes: {total:,}")
        logger.info(f"   Nodes with embeddings: {with_embedding:,}")
        logger.info(f"   Nodes with searchContent: {with_search_content:,}")
        
        if not confirm:
            response = input(f"\n⚠️  Are you sure you want to reset {node_type} embeddings? (y/N): ")
            if response.lower() != 'y':
                logger.info("❌ Reset cancelled")
                return False
        
        try:
            with self.driver.session() as session:
                # Reset embeddings and searchContent
                result = session.run(f"""
                    MATCH (n:{node_type})
                    WHERE n.embedding IS NOT NULL OR n.searchContent IS NOT NULL
                    REMOVE n.embedding, n.searchContent
                    RETURN count(*) as reset_count
                """)
                
                reset_count = result.single()['reset_count']
                
                logger.info(f"✅ Successfully reset {reset_count:,} {node_type} nodes")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to reset {node_type}: {e}")
            return False
    
    def reset_all_types(self, confirm: bool = False) -> bool:
        """
        Reset embeddings and searchContent for all node types.
        
        Args:
            confirm: Skip confirmation prompt if True
            
        Returns:
            True if reset was successful, False otherwise
        """
        node_types = ["UcoCVE", "UcoVulnerability", "UcoexCPE", 
                     "UcoCWE", "UcoexMITREATTACK", "UcoexCAPEC"]
        
        # Get overall stats
        stats = self.get_embedding_stats()
        overall = stats['overall']
        
        if overall['total_embeddings'] == 0 and overall['total_search_content'] == 0:
            logger.info("✅ No embeddings or searchContent found to reset")
            return True
        
        logger.info("🔍 Overall reset summary:")
        logger.info(f"   Total nodes: {overall['total_nodes']:,}")
        logger.info(f"   Nodes with embeddings: {overall['total_embeddings']:,}")
        logger.info(f"   Nodes with searchContent: {overall['total_search_content']:,}")
        
        if not confirm:
            response = input(f"\n⚠️  Are you sure you want to reset ALL embeddings? (y/N): ")
            if response.lower() != 'y':
                logger.info("❌ Reset cancelled")
                return False
        
        success_count = 0
        for node_type in node_types:
            logger.info(f"🔄 Resetting {node_type}...")
            if self.reset_node_type(node_type, confirm=True):
                success_count += 1
            else:
                logger.error(f"❌ Failed to reset {node_type}")
        
        if success_count == len(node_types):
            logger.info("🎉 Successfully reset all node types!")
            return True
        else:
            logger.warning(f"⚠️  Reset completed with {len(node_types) - success_count} failures")
            return False
    
    def close(self):
        """Clean up resources and close database connection."""
        if self.driver:
            self.driver.close()
            logger.info("✅ Database connection closed")

def main():
    """Command line interface for embedding reset."""
    parser = argparse.ArgumentParser(description='UCKG Embedding Reset Tool - Reset embeddings and searchContent for testing')
    parser.add_argument('--stats', action='store_true', help='Display current embedding statistics')
    parser.add_argument('--node-type', help='Reset specific node type (e.g., UcoCVE, UcoCWE)')
    parser.add_argument('--all', action='store_true', help='Reset all node types')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompts')
    
    args = parser.parse_args()
    
    # Initialize reset tool
    reset_tool = EmbeddingReset()
    
    try:
        if args.stats:
            # Display current statistics
            stats = reset_tool.get_embedding_stats()
            print("\n📊 CURRENT EMBEDDING STATISTICS")
            print("=" * 50)
            
            for node_type, node_stats in stats.items():
                if node_type == 'overall':
                    continue
                print(f"{node_type:15} | Total: {node_stats['total']:7,} | "
                      f"Embeddings: {node_stats['with_embedding']:7,} ({node_stats['embedding_coverage']:5.1f}%) | "
                      f"SearchContent: {node_stats['with_search_content']:7,} ({node_stats['search_content_coverage']:5.1f}%)")
            
            overall = stats['overall']
            print("-" * 50)
            print(f"{'TOTAL':15} | Total: {overall['total_nodes']:7,} | "
                  f"Embeddings: {overall['total_embeddings']:7,} ({overall['embedding_coverage']:5.1f}%) | "
                  f"SearchContent: {overall['total_search_content']:7,} ({overall['search_content_coverage']:5.1f}%)")
            
        elif args.node_type:
            # Reset specific node type
            reset_tool.reset_node_type(args.node_type, args.confirm)
            
        elif args.all:
            # Reset all node types
            reset_tool.reset_all_types(args.confirm)
            
        else:
            parser.print_help()
            
    finally:
        reset_tool.close()

if __name__ == "__main__":
    main()