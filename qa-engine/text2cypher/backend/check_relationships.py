#!/usr/bin/env python3
"""
Script to check what relationships exist in the Neo4j database
"""

from neo4j import GraphDatabase

def check_relationships():
    """Check what relationships exist in the database"""
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "abcd90909090"))
    
    with driver.session() as session:
        # Check all relationship types
        print("Checking all relationship types:")
        result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType")
        for record in result:
            print(f"  - {record['relationshipType']}")
        
        print("\nChecking relationships between CWE and CAPEC:")
        # Check if there are any relationships between CWE and CAPEC
        result = session.run("""
            MATCH (cwe:UcoCWE)-[r]->(capec:UcoexCAPEC)
            RETURN type(r) as relationship_type, count(r) as count
            ORDER BY count DESC
        """)
        for record in result:
            print(f"  - {record['relationship_type']}: {record['count']} relationships")
        
        # Check reverse direction
        result = session.run("""
            MATCH (capec:UcoexCAPEC)-[r]->(cwe:UcoCWE)
            RETURN type(r) as relationship_type, count(r) as count
            ORDER BY count DESC
        """)
        for record in result:
            print(f"  - {record['relationship_type']}: {record['count']} relationships")
        
        print("\nChecking relationships from CWE to other nodes:")
        result = session.run("""
            MATCH (cwe:UcoCWE)-[r]->(other)
            RETURN type(r) as relationship_type, labels(other) as target_labels, count(r) as count
            ORDER BY count DESC
        """)
        for record in result:
            print(f"  - {record['relationship_type']} → {record['target_labels']}: {record['count']} relationships")
        
        print("\nChecking relationships to CAPEC from other nodes:")
        result = session.run("""
            MATCH (other)-[r]->(capec:UcoexCAPEC)
            RETURN labels(other) as source_labels, type(r) as relationship_type, count(r) as count
            ORDER BY count DESC
        """)
        for record in result:
            print(f"  - {record['source_labels']} → {record['relationship_type']}: {record['count']} relationships")
        
        print("\nChecking available CWE IDs:")
        result = session.run("MATCH (cwe:UcoCWE) RETURN cwe.ucocweID, cwe.ucocweName ORDER BY cwe.ucocweID LIMIT 15")
        for record in result:
            print(f"  - {record['cwe.ucocweID']}: {record['cwe.ucocweName']}")
        
        print("\nChecking available CAPEC IDs:")
        result = session.run("MATCH (capec:UcoexCAPEC) RETURN capec.ucoexCAPEC_id, capec.ucoexCAPEC_name ORDER BY capec.ucoexCAPEC_id LIMIT 10")
        for record in result:
            print(f"  - {record['capec.ucoexCAPEC_id']}: {record['capec.ucoexCAPEC_name']}")
        
        print("\nTesting a valid CWE query:")
        # Test with a valid CWE ID
        result = session.run("MATCH (cwe:UcoCWE {ucocweID: 'CWE-1004'}) RETURN cwe.ucocweID, cwe.ucocweName")
        for record in result:
            print(f"  - Found: {record['cwe.ucocweID']} - {record['cwe.ucocweName']}")
            
            # Check what relationships this CWE has
            rel_result = session.run("""
                MATCH (cwe:UcoCWE {ucocweID: 'CWE-1004'})-[r]->(other)
                RETURN type(r) as rel_type, labels(other) as target_labels, count(r) as count
            """)
            for rel_record in rel_result:
                print(f"    → {rel_record['rel_type']} → {rel_record['target_labels']}: {rel_record['count']}")
        
        print("\nTesting CAPEC to CWE relationship direction:")
        # Test the actual relationship direction
        result = session.run("""
            MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE)
            RETURN capec.ucoexCAPEC_id, capec.ucoexCAPEC_name, cwe.ucocweID, cwe.ucocweName
            LIMIT 5
        """)
        for record in result:
            print(f"  - CAPEC {record['capec.ucoexCAPEC_id']} → CWE {record['cwe.ucocweID']}")
        
        print("\nTesting CWE to CAPEC relationship direction:")
        # Test the reverse direction
        result = session.run("""
            MATCH (cwe:UcoCWE)-[:UCOEXHASRELATEDWEAKNESS]->(capec:UcoexCAPEC)
            RETURN cwe.ucocweID, cwe.ucocweName, capec.ucoexCAPEC_id, capec.ucoexCAPEC_name
            LIMIT 5
        """)
        for record in result:
            print(f"  - CWE {record['cwe.ucocweID']} → CAPEC {record['capec.ucoexCAPEC_id']}")
        
        print("\nTesting specific query with valid IDs:")
        # Test the actual query that should work
        result = session.run("""
            MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE {ucocweID: 'CWE-1004'})
            RETURN capec.ucoexCAPEC_id, capec.ucoexCAPEC_name
            LIMIT 5
        """)
        print(f"  - Found {result.peek() is not None and len(list(result))} CAPEC patterns related to CWE-1004")
        for record in result:
            print(f"    - CAPEC {record['capec.ucoexCAPEC_id']}: {record['capec.ucoexCAPEC_name']}")

if __name__ == "__main__":
    check_relationships() 