#!/usr/bin/env python3
"""
Test script to verify we're accessing the correct CAPEC properties.
"""
import asyncio
from scripts.embedding_setup import FixedEmbeddingSetup

async def test_capec_properties():
    setup = FixedEmbeddingSetup()
    
    try:
        await setup.initialize()
        
        print("Testing corrected CAPEC property access...")
        
        # Get a few nodes to test
        nodes = setup.get_capec_nodes_for_embedding(limit=3)
        
        if nodes:
            print(f"Retrieved {len(nodes)} UcoexCAPEC nodes")
            
            for i, node in enumerate(nodes, 1):
                print(f"\n--- Node {i} ---")
                print(f"CAPEC ID: {node['capec_id']}")
                print(f"Name: {node['name']}")
                print(f"Abstraction: {node['abstraction']}")
                print(f"Description: {node['description'][:100]}..." if node['description'] else "No description")
                print(f"Likelihood: {node['likelihood']}")
                print(f"Severity: {node['severity']}")
                
                # Test embedding text creation
                embedding_text = setup.create_embedding_text(node)
                print(f"\nEmbedding text (first 200 chars): {embedding_text[:200]}...")
        else:
            print("No nodes found (this might mean all nodes already have embeddings)")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if setup.driver:
            setup.driver.close()

if __name__ == "__main__":
    asyncio.run(test_capec_properties()) 