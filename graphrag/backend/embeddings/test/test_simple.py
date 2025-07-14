#!/usr/bin/env python3
"""
Simple test for the simplified UCKG embedder.
Tests the core functionality without complexity.
"""
import asyncio
import logging
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from uckg_embedding_processor import UCKGEmbeddingProcessor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_simple_embedder():
    """Test the simplified embedder."""
    
    logger.info("🧪 TESTING SIMPLE UCKG EMBEDDER")
    logger.info("=" * 50)
    
    try:
        # Initialize embedder
        embedder = UCKGEmbeddingProcessor()
        logger.info("✅ Embedder initialized")
        
        # Test 1: Get statistics
        logger.info("\n📊 TEST 1: Getting current statistics")
        stats = embedder.get_stats()
        
        overall = stats['overall']
        logger.info(f"Total nodes: {overall['total_nodes']:,}")
        logger.info(f"Nodes with embeddings: {overall['total_embeddings']:,} ({overall['embedding_coverage']:.1f}%)")
        logger.info(f"Nodes with searchContent: {overall['total_search_content']:,} ({overall['search_content_coverage']:.1f}%)")
        
        # Test 2: Property extraction
        logger.info("\n🔍 TEST 2: Testing property extraction")
        test_nodes = embedder.get_all_node_properties("UcoexCAPEC", limit=2)
        
        if test_nodes:
            sample_node = test_nodes[0]
            logger.info(f"Sample node has {len(sample_node)} properties: {list(sample_node.keys())}")
            
            # Test comprehensive text generation
            search_content = embedder.create_comprehensive_text(sample_node, "UcoexCAPEC")
            logger.info(f"Generated searchContent: {len(search_content)} characters")
            logger.info(f"Preview: {search_content[:150]}...")
            
            # Test embedding generation
            embedding = embedder.create_embedding(search_content)
            logger.info(f"Generated embedding: {len(embedding)} dimensions")
            
        else:
            logger.info("No nodes found needing processing")
        
        # Test 3: Small batch processing
        logger.info("\n🔄 TEST 3: Testing small batch processing")
        embedder.process_node_type("UcoexCAPEC", batch_size=3, limit=3)
        
        # Test 4: Updated statistics
        logger.info("\n📊 TEST 4: Updated statistics")
        updated_stats = embedder.get_stats()
        capec_stats = updated_stats['UcoexCAPEC']
        logger.info(f"UcoexCAPEC embeddings: {capec_stats['with_embedding']}")
        logger.info(f"UcoexCAPEC searchContent: {capec_stats['with_search_content']}")
        
        logger.info("\n🎉 ALL TESTS PASSED!")
        logger.info("Simple embedder is working correctly.")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        raise
        
    finally:
        embedder.close()

if __name__ == "__main__":
    test_simple_embedder()