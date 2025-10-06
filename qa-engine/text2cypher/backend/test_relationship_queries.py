#!/usr/bin/env python3
"""
Test script for relationship-based queries in the Text2Cypher implementation.
This tests the ability to generate Cypher queries that follow relationships between nodes.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from text2cypher import Text2Cypher
from ollama_llm import OllamaLLM

class MockLLM:
    """Mock LLM for testing relationship queries"""
    def __init__(self):
        self.relationship_responses = {
            "Find CAPEC patterns related to CWE-404": 
                "MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-404' RETURN capec",
            
            "Show CVEs that affect Microsoft Windows platforms": 
                "MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft:windows' RETURN cve",
            
            "Find groups using specific MITRE techniques": 
                "MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE technique.ucoexNAME CONTAINS 'T1078' RETURN group",
            
            "Show software used by specific threat groups": 
                "MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(software:UcoexSOFTWARE) WHERE group.ucoexNAME = 'Gallmaker' RETURN software",
            
            "Find CVEs related to Adobe products": 
                "MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'adobe' RETURN cve"
        }
    
    def invoke(self, prompt):
        # Extract the question from the prompt
        if "Question:" in prompt:
            question = prompt.split("Question:")[-1].strip()
            if question in self.relationship_responses:
                return self.relationship_responses[question]
        
        # Default response for other queries
        return "MATCH (n:UcoCVE) RETURN n LIMIT 5"

def test_relationship_queries():
    """Test relationship-based queries"""
    print("🧪 Testing Relationship-Based Queries")
    print("=" * 50)
    
    # Initialize with mock LLM
    llm = MockLLM()
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", llm)
    
    # Test questions that require relationship traversal
    test_questions = [
        "Find CAPEC patterns related to CWE-404",
        "Show CVEs that affect Microsoft Windows platforms", 
        "Find groups using specific MITRE techniques",
        "Show software used by specific threat groups",
        "Find CVEs related to Adobe products"
    ]
    
    for i, question in enumerate(test_questions, 1):
        print(f"\n{i}. Testing: {question}")
        try:
            cypher = t2c.text_to_cypher(question)
            print(f"   Generated Cypher: {cypher}")
            
            # Validate the generated Cypher
            is_valid, error_msg = t2c.validate_cypher(cypher)
            if is_valid:
                print(f"   Valid Cypher query")
            else:
                print(f"   Invalid: {error_msg}")
                
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("Relationship query testing completed!")

def test_real_neo4j_connection():
    """Test with real Neo4j connection if available"""
    print("\n🔗 Testing Real Neo4j Connection")
    print("=" * 50)
    
    try:
        # Try to connect to real Neo4j
        llm = OllamaLLM(model="llama3")
        t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", llm)
        
        # Test a simple relationship query
        question = "Find CAPEC patterns related to CWE-404"
        print(f"Testing: {question}")
        
        cypher = t2c.text_to_cypher(question)
        print(f"Generated Cypher: {cypher}")
        
        # Try to run the query
        result = t2c.run_cypher(cypher)
        print(f"Query returned {len(result)} results")
        
        if result:
            print("Sample result:", result[0])
        
    except Exception as e:
        print(f"Connection failed: {str(e)}")
        print("Make sure Neo4j is running and credentials are correct")

if __name__ == "__main__":
    test_relationship_queries()
    test_real_neo4j_connection() 