#!/usr/bin/env python3
"""
Test script for cybersecurity knowledge graph text-to-cypher functionality.
"""

from text2cypher import Text2Cypher
from neo4j import GraphDatabase

def test_cybersecurity_schema():
    """Test the cybersecurity schema extraction"""
    
    # Mock LLM for testing
    class MockLLM:
        def invoke(self, prompt):
            return "MATCH (cve:UcoCVE) RETURN cve LIMIT 10"
    
    # Initialize Text2Cypher
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", MockLLM())
    
    print("=== TESTING CYBERSECURITY SCHEMA ===")
    
    try:
        # Test the cybersecurity schema
        schema = t2c.get_cybersecurity_schema()
        print("Cybersecurity Schema:")
        print(schema)
        
        # Test the schema info
        schema_info = t2c.get_schema_info()
        print("\nSchema Info Keys:", list(schema_info.keys()))
        
    except Exception as e:
        print(f"Error testing cybersecurity schema: {e}")

def test_cybersecurity_queries():
    """Test various cybersecurity query examples"""
    
    # Mock LLM that returns different queries based on input
    class MockLLM:
        def invoke(self, prompt):
            if "HIGH severity" in prompt:
                return "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve LIMIT 10"
            elif "exploitability score" in prompt:
                return "MATCH (cve:UcoCVE) WHERE cve.ucoexploitabilityScore > 8.0 RETURN cve"
            elif "user interaction" in prompt:
                return "MATCH (cve:UcoCVE) WHERE cve.ucouserInteractionRequired = true RETURN cve"
            elif "CWE-13" in prompt:
                return "MATCH (cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-13' RETURN cwe"
            elif "CAPEC-16" in prompt or "CAPEC pattern with ID 16" in prompt:
                return "MATCH (capec:UcoexCAPEC) WHERE capec.ucoexCAPEC_id = '16' RETURN capec"
            elif "Gallmaker" in prompt:
                return "MATCH (group:UcoexGROUPS) WHERE group.ucoexNAME = 'Gallmaker' RETURN group"
            elif "Socksbot" in prompt:
                return "MATCH (software:UcoexSOFTWARE) WHERE software.ucoexNAME = 'Socksbot' RETURN software"
            elif "enterprise-attack" in prompt:
                return "MATCH (n) WHERE n.ucoexDOMAIN = 'enterprise-attack' RETURN n LIMIT 10"
            elif "Deferred" in prompt:
                return "MATCH (cve:UcoCVE) WHERE cve.ucovulnStatus = 'Deferred' RETURN cve"
            elif "Draft" in prompt:
                return "MATCH (cwe:UcoCWE) WHERE cwe.ucostatus = 'Draft' RETURN cwe"
            else:
                return "MATCH (cve:UcoCVE) RETURN cve LIMIT 5"
    
    # Initialize Text2Cypher
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", MockLLM())
    
    print("\n=== TESTING CYBERSECURITY QUERIES ===")
    
    # Test realistic questions based on actual properties
    test_questions = [
        "Show all CVEs with HIGH severity",
        "Find CVEs with exploitability score greater than 8", 
        "Show CVEs that require user interaction",
        "Find CWE weakness with ID CWE-13",
        "Find CAPEC pattern with ID 16",
        "Find threat group named Gallmaker",
        "Find software named Socksbot",
        "Show threat groups in enterprise-attack domain",
        "Show CVEs with Deferred status",
        "Show CWE weaknesses with Draft status"
    ]
    
    for question in test_questions:
        try:
            cypher = t2c.text_to_cypher(question)
            print(f"\nQuestion: {question}")
            print(f"Cypher: {cypher}")
            
            # Validate the generated Cypher
            is_valid, error_msg = t2c.validate_cypher(cypher)
            print(f"Valid: {is_valid}")
            if not is_valid:
                print(f"Error: {error_msg}")
                
        except Exception as e:
            print(f"Error processing question '{question}': {e}")

def test_cybersecurity_node_labels():
    """Test that we're focusing on the right node labels"""
    
    print("\n=== TESTING CYBERSECURITY NODE LABELS ===")
    
    # Mock LLM
    class MockLLM:
        def invoke(self, prompt):
            return "MATCH (cve:UcoCVE) RETURN cve LIMIT 10"
    
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", MockLLM())
    
    print("Cybersecurity Node Labels:")
    for label in sorted(t2c.cybersecurity_labels):
        print(f"  - {label}")
    
    print("\nCybersecurity Relationships:")
    for rel in sorted(t2c.cybersecurity_relationships):
        print(f"  - {rel}")

def test_real_cybersecurity_queries():
    """Test with real Neo4j connection"""
    
    print("\n=== TESTING REAL CYBERSECURITY QUERIES ===")
    
    try:
        # Connect to Neo4j
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "abcd90909090"))
        
        with driver.session() as session:
            # Test 1: Count cybersecurity nodes
            print("\n1. Counting cybersecurity nodes:")
            for label in ["UcoCVE", "UcoCWE", "UcoexCAPEC", "UcoexMITREATTACK"]:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                count = result.single()["count"]
                print(f"   {label}: {count:,} nodes")
            
            # Test 2: Sample properties
            print("\n2. Sample properties for cybersecurity nodes:")
            for label in ["UcoCVE", "UcoCWE", "UcoexCAPEC"]:
                result = session.run(f"MATCH (n:{label}) RETURN keys(n) as properties LIMIT 1")
                record = result.single()
                if record:
                    properties = record["properties"]
                    print(f"   {label}: {properties[:5]}...")  # Show first 5 properties
            
            # Test 3: Sample relationships
            print("\n3. Sample cybersecurity relationships:")
            for rel in ["UCOEXHASRELATEDWEAKNESS", "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE"]:
                result = session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) as count")
                count = result.single()["count"]
                print(f"   {rel}: {count:,} relationships")
                
    except Exception as e:
        print(f"Error testing real queries: {e}")

if __name__ == "__main__":
    test_cybersecurity_schema()
    test_cybersecurity_queries()
    test_cybersecurity_node_labels()
    test_real_cybersecurity_queries() 