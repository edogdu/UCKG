#!/usr/bin/env python3
"""
Test script to demonstrate the difference between original schema approach 
and the new distinct node types approach.
"""

from text2cypher import Text2Cypher
from neo4j import GraphDatabase

def test_schema_approaches():
    """Compare the original vs new distinct schema approaches"""
    
    # Initialize connection (adjust credentials as needed)
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "abcd90909090"))
    
    # Test 1: Show what the original db.schema.visualization() approach returns
    print("=== ORIGINAL APPROACH (with duplicates) ===")
    with driver.session() as session:
        try:
            # This is what was causing duplicates
            record = session.run("CALL db.schema.visualization()").single()
            if record:
                nodes = record.get("nodes", []) or []
                labels = sorted({lbl for node in nodes for lbl in node.labels})
                print(f"Total unique labels found: {len(labels)}")
                print("Labels:", labels)
        except Exception as e:
            print(f"Error with visualization approach: {e}")
    
    print("\n=== NEW DISTINCT APPROACH ===")
    with driver.session() as session:
        try:
            # This gets distinct labels without duplicates
            labels_result = session.run("CALL db.labels()")
            labels = sorted([record["label"] for record in labels_result])
            print(f"Total distinct labels found: {len(labels)}")
            print("Labels:", labels)
        except Exception as e:
            print(f"Error with distinct approach: {e}")
    
    print("\n=== COMPARISON ===")
    print("The original approach shows all label combinations for nodes with multiple labels.")
    print("The new approach shows only distinct labels, eliminating duplicates.")
    print("This is why you were seeing duplicates in your schema output.")

def test_text2cypher_methods():
    """Test the new Text2Cypher methods"""
    
    # Mock LLM for testing (you'd use your actual LLM)
    class MockLLM:
        def invoke(self, prompt):
            return "MATCH (n:UcoCVE) RETURN n LIMIT 10"
    
    # Initialize Text2Cypher
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "abcd90909090", MockLLM())
    
    print("\n=== TESTING NEW TEXT2CYPHER METHODS ===")
    
    try:
        # Test the new distinct method
        distinct_result = t2c.get_node_type_properties_distinct()
        print("Distinct node types and properties:")
        for node_type, properties in distinct_result.items():
            print(f"  {node_type}: {properties}")
        
        # Test the string version
        distinct_string = t2c.get_distinct_node_types_and_properties()
        print("\nDistinct node types (string format):")
        print(distinct_string)
        
    except Exception as e:
        print(f"Error testing Text2Cypher methods: {e}")

if __name__ == "__main__":
    test_schema_approaches()
    test_text2cypher_methods() 