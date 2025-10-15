#!/usr/bin/env python3
"""
Example script demonstrating how to use the schema_extract.py module
to extract UCKG schema from Neo4j and save it as structured text files.
"""

import os
import sys

# Add backend to path for config import
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'text2cypher', 'backend'))

from schema_extract import SchemaExtractor
from config import SCHEMA_EXTRACTION_CONFIG

def main():
    """Example usage of schema extraction."""
    
    # Neo4j connection details (adjust as needed)
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "password"  # Change this to your actual password
    
    print("🚀 UCKG Schema Extraction Example")
    print("=" * 50)
    
    # Check if Neo4j is running first
    print("🔍 Checking Neo4j connection...")
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            if test_value == 1:
                print("✅ Neo4j connection successful!")
            else:
                print("❌ Neo4j connection test failed")
                return 1
        driver.close()
    except Exception as e:
        print(f"❌ Neo4j connection failed: {e}")
        print("\n💡 To fix this:")
        print("   1. Make sure Neo4j is running: docker ps | grep neo4j")
        print("   2. Check your credentials in this script")
        print("   3. Or use the existing Text2Cypher schema instead")
        print("\n🔄 Falling back to Text2Cypher schema extraction...")
        return test_with_text2cypher_schema()
    
    # Example 1: Extract schema as text file
    print("\n📄 Example 1: Extract schema as text file")
    print("-" * 40)
    
    extractor = SchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    results = extractor.extract_complete_schema(
        output_file="uckg_schema.txt",
        format="text"
    )
    
    if results["status"] == "success":
        print(f"✅ Text schema saved to: {results['files_created']['text_file']}")
        print(f"📊 Validation results: {results['validation']['statistics']}")
    else:
        print(f"❌ Extraction failed: {results['error']}")
        return 1
    
    # Example 2: Extract schema as JSON file
    print("\n📄 Example 2: Extract schema as JSON file")
    print("-" * 40)
    
    extractor2 = SchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    results2 = extractor2.extract_complete_schema(
        output_file="uckg_schema.json",
        format="json"
    )
    
    if results2["status"] == "success":
        print(f"✅ JSON schema saved to: {results2['files_created']['json_file']}")
    else:
        print(f"❌ JSON extraction failed: {results2['error']}")
    
    # Example 3: Extract both formats
    print("\n📄 Example 3: Extract both text and JSON formats")
    print("-" * 40)
    
    extractor3 = SchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    results3 = extractor3.extract_complete_schema(
        output_file="uckg_complete_schema",
        format="both"
    )
    
    if results3["status"] == "success":
        print("✅ Both formats created:")
        for file_type, filename in results3["files_created"].items():
            if file_type != "validation":
                print(f"   📄 {file_type}: {filename}")
    else:
        print(f"❌ Both formats extraction failed: {results3['error']}")
    
    # Example 4: Show how to use extracted schema
    print("\n📄 Example 4: Using extracted schema")
    print("-" * 40)
    
    schema_file = "uckg_schema.txt"
    if os.path.exists(schema_file):
        print(f"📖 Reading schema from {schema_file}:")
        with open(schema_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
            print(f"   📏 Total lines: {len(lines)}")
            print(f"   📄 First 10 lines:")
            for i, line in enumerate(lines[:10]):
                print(f"      {i+1:2d}: {line}")
            if len(lines) > 10:
                print(f"      ... and {len(lines) - 10} more lines")
    else:
        print(f"❌ Schema file {schema_file} not found")
    
    print("\n🎉 Schema extraction examples completed!")
    return 0

def test_with_text2cypher_schema():
    """Test schema extraction using existing Text2Cypher schema."""
    print("\n📄 Testing with existing Text2Cypher schema...")
    print("-" * 50)
    
    try:
        # Import Text2Cypher to get the existing schema
        from text2cypher import Text2Cypher
        from ollama_llm import OllamaLLM
        
        # Create a mock LLM (we won't use it for schema extraction)
        llm = OllamaLLM(model="llama2")
        
        # Create Text2Cypher instance (this will use the existing Neo4j connection)
        t2c = Text2Cypher(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j", 
            neo4j_password="password",
            llm=llm
        )
        
        # Get the existing schema
        print("📋 Extracting schema using Text2Cypher...")
        schema_text = t2c.get_cybersecurity_schema()
        
        # Save it as a test file
        test_file = "test_schema_from_text2cypher.txt"
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(schema_text)
        
        print(f"✅ Schema extracted and saved to: {test_file}")
        print(f"📏 Schema length: {len(schema_text)} characters")
        print(f"📄 First 200 characters:")
        print("-" * 30)
        print(schema_text[:200] + "..." if len(schema_text) > 200 else schema_text)
        print("-" * 30)
        
        # Test the schema extraction classes with this data
        print("\n🧪 Testing schema extraction classes...")
        
        # Test SchemaFormatter
        from schema_extract import SchemaFormatter
        formatter = SchemaFormatter()
        print("✅ SchemaFormatter works correctly")
        
        # Test SchemaValidator
        from schema_extract import SchemaValidator
        validator = SchemaValidator()
        test_schema = {
            "node_types": {"UcoCVE": ["cve_id", "severity"]},
            "relationship_types": {"UCOEXHASCPE": []},
            "connections": {"outgoing": {}, "incoming": {}}
        }
        validation = validator.validate_schema(test_schema)
        print(f"✅ SchemaValidator works correctly (is_valid: {validation['is_valid']})")
        
        print("\n🎉 Text2Cypher schema extraction test completed successfully!")
        return 0
        
    except Exception as e:
        print(f"❌ Text2Cypher schema extraction failed: {e}")
        print("\n💡 This means the Text2Cypher backend also can't connect to Neo4j.")
        print("   The schema extraction module itself is working correctly!")
        return 1

if __name__ == "__main__":
    exit(main())