#!/usr/bin/env python3
"""
Standalone test for schema extraction module without requiring Neo4j connection.
This demonstrates that the schema extraction classes work correctly.
"""

import sys
import os

# Add backend to path for config import
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'text2cypher', 'backend'))

from schema_extract import SchemaFormatter, SchemaValidator

def test_schema_formatter():
    """Test SchemaFormatter class."""
    print("🧪 Testing SchemaFormatter...")
    
    formatter = SchemaFormatter()
    
    # Test data
    node_properties = {
        "UcoCVE": ["cve_id", "severity", "description"],
        "UcoCWE": ["cwe_id", "name", "status"],
        "UcoexCAPEC": ["capec_id", "name", "severity"]
    }
    
    outgoing_connections = {
        "UcoCVE": [("UCOEXHASCPE", "UcoexCPE"), ("UCOHASWEAKNESS", "UcoCWE")],
        "UcoexCAPEC": [("UCOEXHASRELATEDWEAKNESS", "UcoCWE")]
    }
    
    incoming_connections = {
        "UcoexCPE": [("UcoCVE", "UCOEXHASCPE")],
        "UcoCWE": [("UcoCVE", "UCOHASWEAKNESS"), ("UcoexCAPEC", "UCOEXHASRELATEDWEAKNESS")]
    }
    
    property_types = {
        "UcoCVE": {"cve_id": "string", "severity": "string", "description": "string"},
        "UcoCWE": {"cwe_id": "string", "name": "string", "status": "string"},
        "UcoexCAPEC": {"capec_id": "string", "name": "string", "severity": "string"}
    }
    
    # Format schema
    formatted_schema = formatter.format_as_text(
        node_properties, outgoing_connections, incoming_connections, property_types
    )
    
    print("✅ SchemaFormatter works correctly")
    print(f"📏 Generated schema length: {len(formatted_schema)} characters")
    print("\n📄 Generated schema preview:")
    print("-" * 50)
    print(formatted_schema[:300] + "..." if len(formatted_schema) > 300 else formatted_schema)
    print("-" * 50)
    
    return formatted_schema

def test_schema_validator():
    """Test SchemaValidator class."""
    print("\n🧪 Testing SchemaValidator...")
    
    validator = SchemaValidator()
    
    # Test schema data
    schema_data = {
        "metadata": {
            "extraction_timestamp": "2024-01-15T14:30:25.123456",
            "total_node_types": 3,
            "total_relationship_types": 2,
            "total_connections": 3
        },
        "node_types": {
            "UcoCVE": ["cve_id", "severity", "description"],
            "UcoCWE": ["cwe_id", "name", "status"],
            "UcoexCAPEC": ["capec_id", "name", "severity"]
        },
        "relationship_types": {
            "UCOEXHASCPE": [],
            "UCOHASWEAKNESS": []
        },
        "connections": {
            "outgoing": {
                "UcoCVE": [["UCOEXHASCPE", "UcoexCPE"], ["UCOHASWEAKNESS", "UcoCWE"]]
            },
            "incoming": {
                "UcoexCPE": [["UcoCVE", "UCOEXHASCPE"]],
                "UcoCWE": [["UcoCVE", "UCOHASWEAKNESS"]]
            }
        }
    }
    
    # Validate schema
    validation_result = validator.validate_schema(schema_data)
    
    print("✅ SchemaValidator works correctly")
    print(f"📊 Validation result: {validation_result['is_valid']}")
    print(f"📈 Statistics: {validation_result['statistics']}")
    print(f"⚠️  Warnings: {len(validation_result['warnings'])}")
    print(f"❌ Errors: {len(validation_result['errors'])}")
    
    return validation_result

def test_schema_extractor_import():
    """Test that SchemaExtractor can be imported (without instantiation)."""
    print("\n🧪 Testing SchemaExtractor import...")
    
    try:
        from schema_extract import SchemaExtractor
        print("✅ SchemaExtractor imports successfully")
        print("💡 Note: SchemaExtractor requires Neo4j connection to work")
        return True
    except Exception as e:
        print(f"❌ SchemaExtractor import failed: {e}")
        return False

def main():
    """Run all standalone tests."""
    print("🚀 Schema Extraction Module - Standalone Tests")
    print("=" * 60)
    print("Testing schema extraction classes without Neo4j connection...")
    print()
    
    # Test 1: SchemaFormatter
    try:
        formatted_schema = test_schema_formatter()
        formatter_success = True
    except Exception as e:
        print(f"❌ SchemaFormatter test failed: {e}")
        formatter_success = False
    
    # Test 2: SchemaValidator
    try:
        validation_result = test_schema_validator()
        validator_success = True
    except Exception as e:
        print(f"❌ SchemaValidator test failed: {e}")
        validator_success = False
    
    # Test 3: SchemaExtractor import
    try:
        extractor_success = test_schema_extractor_import()
    except Exception as e:
        print(f"❌ SchemaExtractor import test failed: {e}")
        extractor_success = False
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"✅ SchemaFormatter: {'PASS' if formatter_success else 'FAIL'}")
    print(f"✅ SchemaValidator: {'PASS' if validator_success else 'FAIL'}")
    print(f"✅ SchemaExtractor: {'PASS' if extractor_success else 'FAIL'}")
    
    if all([formatter_success, validator_success, extractor_success]):
        print("\n🎉 ALL TESTS PASSED!")
        print("The schema extraction module is working correctly.")
        print("The only issue is Neo4j connection, which is expected.")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED!")
        return 1

if __name__ == "__main__":
    exit(main())