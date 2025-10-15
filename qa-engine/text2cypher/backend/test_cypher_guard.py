#!/usr/bin/env python3
"""
Test script for Cypher Guard integration in Text2Cypher V4
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from text2cypher import Text2Cypher
from ollama_llm import OllamaLLM

def test_cypher_guard_integration():
    """Test the Cypher Guard integration with various query types."""
    
    print("Testing Cypher Guard Integration for Text2Cypher V4")
    print("=" * 60)
    
    try:
        # Initialize Text2Cypher with Cypher Guard
        t2c = Text2Cypher(
            'bolt://localhost:7687',
            'neo4j',
            'abcd90909090',
            OllamaLLM(model='llama3:instruct')
        )
        
        print("✅ Text2Cypher initialized with Cypher Guard validator")
        
        # Test validation info
        validation_info = t2c.cypher_validator.get_validation_info()
        print(f"📊 Validation Info: {validation_info}")
        
        # Test various query types
        test_queries = [
            # Valid queries
            ("MATCH (cve:UcoCVE) RETURN cve LIMIT 5", "Valid basic query"),
            ("MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cve, cpe LIMIT 5", "Valid relationship query"),
            ("MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve LIMIT 5", "Valid filtered query"),
            
            # Invalid queries
            ("MATCH (cve:CVE) RETURN cve", "Invalid label (should be UcoCVE)"),
            ("MATCH (cve:UcoCVE)-[:INVALID_REL]->(cpe:UcoexCPE) RETURN cve, cpe", "Invalid relationship"),
            ("CREATE (cve:UcoCVE {label: 'test'})", "Write query (not allowed)"),
            ("MATCH (cve) RETURN cve", "Missing label"),
            ("INVALID SYNTAX", "Syntax error"),
        ]
        
        print("\n🧪 Testing Query Validation:")
        print("-" * 40)
        
        for query, description in test_queries:
            print(f"\nTest: {description}")
            print(f"Query: {query}")
            
            try:
                is_valid, message = t2c.validate_cypher(query)
                status = "✅ VALID" if is_valid else "❌ INVALID"
                print(f"Result: {status}")
                print(f"Message: {message}")
                
            except Exception as e:
                print(f"Result: ❌ ERROR")
                print(f"Error: {e}")
        
        # Test enhanced text2cypher with fallback
        print("\n🚀 Testing Enhanced Text2Cypher with Fallback:")
        print("-" * 50)
        
        test_questions = [
            "Show CVEs with high severity",
            "Find groups using specific techniques",
            "Show me all vulnerabilities from 2025",  # Should return no results
        ]
        
        for question in test_questions:
            print(f"\nQuestion: {question}")
            try:
                response = t2c.text_to_cypher_with_fallback(question)
                print(f"Status: {response['status']}")
                print(f"Message: {response['message']}")
                if response.get('cypher'):
                    print(f"Cypher: {response['cypher']}")
                if response.get('suggestions'):
                    print(f"Suggestions: {response['suggestions']}")
            except Exception as e:
                print(f"Error: {e}")
        
        print("\n✅ Cypher Guard integration test completed!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure to install cypher-guard: pip install cypher-guard")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_cypher_guard_integration()