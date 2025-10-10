#!/usr/bin/env python3
"""
Test script to verify all working queries included in the frontend.
This ensures all sample queries in the frontend actually work with the database.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from text2cypher import Text2Cypher
from ollama_llm import OllamaLLM

def test_working_queries():
    """Test all working queries that are included in the frontend"""
    print("🧪 Testing All Working Frontend Queries")
    print("=" * 60)
    
    # Initialize with real LLM
    llm = OllamaLLM(model="llama3")
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", llm)
    
    # All working queries from the frontend
    working_queries = [
        # Single Node Property Queries
        "Show all CVEs with HIGH severity",
        "Find CVEs with exploitability score greater than 8",
        "Show CVEs that require user interaction",
        "Find CWE weakness with ID CWE-1004",
        "Find CAPEC pattern with ID 1",
        "Show CWE weaknesses with Draft status",
        "Find CVEs with vector string containing 'AV:N'",
        "Show CAPEC patterns with High severity",
        "Find CPE entries for Microsoft products",
        "Find CVEs that can obtain all privileges",
        
        # Relationship-Based Queries
        "Find CAPEC patterns related to CWE-404",
        "Show CVEs that affect Microsoft Windows platforms",
        "Find groups using specific MITRE techniques",
        "Show software used by specific threat groups",
        "Find CVEs related to Adobe products"
    ]
    
    results = {
        'success': [],
        'failed': []
    }
    
    for i, question in enumerate(working_queries, 1):
        print(f"\n{i:2d}. Testing: {question}")
        try:
            cypher = t2c.text_to_cypher(question)
            print(f"    Generated Cypher: {cypher}")
            
            # Validate the generated Cypher
            is_valid, error_msg = t2c.validate_cypher(cypher)
            if is_valid:
                # Try to run the query
                result = t2c.run_cypher(cypher)
                result_count = len(result) if isinstance(result, list) else 1
                print(f"    Valid Cypher query - {result_count} results")
                results['success'].append({
                    'question': question,
                    'cypher': cypher,
                    'result_count': result_count
                })
            else:
                print(f"    Invalid: {error_msg}")
                results['failed'].append({
                    'question': question,
                    'error': error_msg
                })
                
        except Exception as e:
            print(f"    Error: {str(e)}")
            results['failed'].append({
                'question': question,
                'error': str(e)
            })
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Successful queries: {len(results['success'])}")
    print(f"Failed queries: {len(results['failed'])}")
    total_queries = len(results['success']) + len(results['failed'])
    success_rate = (len(results['success']) / total_queries * 100) if total_queries > 0 else 0
    print(f"📈 Success rate: {success_rate:.1f}%")
    
    if results['failed']:
        print("\nFAILED QUERIES:")
        for failed in results['failed']:
            print(f"  - {failed['question']}")
            print(f"    Error: {failed['error']}")
    
    print("\nSUCCESSFUL QUERIES:")
    for success in results['success']:
        print(f"  - {success['question']}")
        print(f"    Results: {success['result_count']}")
    
    return results

def test_specific_relationship_queries():
    """Test specific relationship queries that we know work"""
    print("\n🔗 Testing Specific Relationship Queries")
    print("=" * 60)
    
    llm = OllamaLLM(model="llama3")
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", llm)
    
    # Test the relationship query that we know works
    test_query = "Find CAPEC patterns related to CWE-404"
    print(f"Testing: {test_query}")
    
    try:
        cypher = t2c.text_to_cypher(test_query)
        print(f"Generated Cypher: {cypher}")
        
        result = t2c.run_cypher(cypher)
        print(f"Query returned {len(result)} results")
        
        if result:
            print("Sample results:")
            for i, res in enumerate(result[:3], 1):
                if 'capec' in res:
                    capec = res['capec']
                    print(f"  {i}. CAPEC-{capec.get('ucoexCAPEC_id', 'N/A')}: {capec.get('ucoexCAPEC_name', 'N/A')}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_working_queries()
    test_specific_relationship_queries() 