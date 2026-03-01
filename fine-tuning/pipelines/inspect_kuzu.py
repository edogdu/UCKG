import kuzu
import shutil
import os

DB_PATH = "cache/graph_kuzu"

def inspect_kuzu():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database path '{DB_PATH}' does not exist.")
        return

    print(f"Connecting to KuzuDB at {DB_PATH}...")
    try:
        db = kuzu.Database(DB_PATH)
        conn = kuzu.Connection(db)
        
        # 1. List Tables
        print("\n=== Tables ===")
        tables = conn.execute("CALL SHOW_TABLES() RETURN *").get_as_df()
        print(tables)
        
        # 2. Inspect Entity Table
        print("\n=== Sample Entity ===")
        # Check if Entity table exists first
        if "Entity" in tables["name"].values:
            result = conn.execute("MATCH (n:Entity) RETURN n.id, n.data LIMIT 1")
            if result.has_next():
                row = result.get_next()
                print(f"ID: {row[0]}")
                try:
                    data_obj = json.loads(row[1])
                    print(f"Data: {json.dumps(data_obj, indent=2)}")
                except:
                    print(f"Data: {row[1]}")
            else:
                print("Table 'Entity' is empty.")
        else:
            print("Table 'Entity' NOT found!")

        # 3. Inspect Relation Table
        print("\n=== Sample Relationship ===")
        if "Relation" in tables["name"].values:
            result = conn.execute("MATCH (a)-[r:Relation]->(b) RETURN a.id, b.id, r.data LIMIT 1")
            if result.has_next():
                row = result.get_next()
                print(f"From: {row[0]} -> To: {row[1]}")
                try:
                    data_obj = json.loads(row[2])
                    print(f"Rel Data: {json.dumps(data_obj, indent=2)}")
                except:
                    print(f"Rel Data: {row[2]}")
            
            # Verify Relation Types
            print("\n=== Relationship Types Count ===")
            # Use SQL-like query on the JSON property 'data' is hard in Kuzu, 
            # but we can scan a sample or just check count if we assume import worked.
            # Ideally we check the JSON, but for now let's just see total count
            count = conn.execute("MATCH ()-[r:Relation]->() RETURN count(r)").get_next()[0]
            print(f"Total Edges: {count}")
            
            # Check for UCOEXMITIGATES specifically (heuristic scan of first 100)
            print("Scanning first 100 edges for types...")
            rows = conn.execute("MATCH ()-[r:Relation]->() RETURN r.data LIMIT 100")
            types_found = set()
            while rows.has_next():
                import json
                data = json.loads(rows.get_next()[0])
                types_found.add(data.get("relation_type"))
            print(f"Found Types: {types_found}")

        else:
            print("Table 'Relation' NOT found!")

        # 4. Verify Full Chain (CAPEC -> ATT&CK <- MITIGATION)
        print("\n=== Verifying Incident Response Chain ===")
        # KuzuDB Cypher query to find the V-shape
        query = """
            MATCH (c:Entity)-[r1:Relation]->(a:Entity)<-[r2:Relation]-(m:Entity)
            WHERE c.data CONTAINS 'UcoexCAPEC' 
              AND a.data CONTAINS 'UcoexMITREATTACK'
              AND m.data CONTAINS 'UcoexMITIGATIONS'
            RETURN c.data, a.data, m.data
            LIMIT 1
        """
        # Note: KuzuDB filtering on JSON string is a bit hacky (CONTAINS), 
        # but since we stored 'entity_type' in the JSON, this works for inspection.
        
        result = conn.execute(query)
        if result.has_next():
            row = result.get_next()
            c_data = json.loads(row[0])
            a_data = json.loads(row[1])
            m_data = json.loads(row[2])
            
            print("[SUCCESS] Chain Found:")
            print(f"Chain: [CAPEC: {c_data.get('Name')}] --[IS_A]--> [ATT&CK: {a_data.get('Name')}] <--(MITIGATES)-- [MITIGATION: {m_data.get('Name')}]")
        else:
            print("[FAILURE] No complete CAPEC -> ATT&CK <- MITIGATION chain found.")

            
    except Exception as e:
        print(f"Error inspecting database: {e}")

if __name__ == "__main__":
    inspect_kuzu()
