#!/usr/bin/env python3
"""
Simple script to run schema extraction with proper Neo4j credentials.
Update the credentials below to match your Neo4j setup.
"""

import os
import sys

# Add backend to path for config import
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'text2cypher', 'backend'))

from schema_extract import SchemaExtractor

def main():
    """Run schema extraction with proper credentials."""
    
    # 🔧 UPDATE THESE CREDENTIALS TO MATCH YOUR NEO4J SETUP
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "password"  # ⚠️  CHANGE THIS TO YOUR ACTUAL PASSWORD
    
    print("🚀 UCKG Schema Extraction")
    print("=" * 40)
    print(f"🔗 Neo4j URI: {NEO4J_URI}")
    print(f"👤 Username: {NEO4J_USER}")
    print(f"🔑 Password: {'*' * len(NEO4J_PASSWORD)}")
    print()
    
    # Check if credentials are still default
    if NEO4J_PASSWORD == "password":
        print("⚠️  WARNING: You're using the default password!")
        print("   Please update the NEO4J_PASSWORD in this script.")
        print()
    
    try:
        # Create extractor
        print("🔍 Creating schema extractor...")
        extractor = SchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Extract schema
        print("📋 Extracting schema...")
        results = extractor.extract_complete_schema(
            output_file="uckg_schema",
            format="both"  # Both text and JSON
        )
        
        if results["status"] == "success":
            print("\n🎉 Schema extraction completed successfully!")
            print("📄 Files created:")
            for file_type, filename in results["files_created"].items():
                if file_type != "validation":
                    print(f"   📄 {file_type}: {filename}")
            
            print(f"\n📊 Statistics:")
            stats = results["validation"]["statistics"]
            print(f"   🏷️  Node types: {stats['total_node_types']}")
            print(f"   🔗 Relationship types: {stats['total_relationship_types']}")
            print(f"   📈 Total connections: {stats['total_connections']}")
            print(f"   🔍 Isolated nodes: {stats['isolated_nodes']}")
            
            return 0
        else:
            print(f"\n❌ Schema extraction failed: {results['error']}")
            return 1
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n💡 Troubleshooting:")
        print("   1. Make sure Neo4j is running: docker ps | grep neo4j")
        print("   2. Check your credentials in this script")
        print("   3. Verify Neo4j is accessible at the specified URI")
        print("   4. Check Neo4j logs for any issues")
        return 1

if __name__ == "__main__":
    print("🔧 To use this script:")
    print("   1. Update the NEO4J_PASSWORD variable with your actual password")
    print("   2. Make sure Neo4j is running")
    print("   3. Run: python3 run_schema_extraction.py")
    print()
    exit(main())