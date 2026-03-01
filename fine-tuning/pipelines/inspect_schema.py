from neo4j import GraphDatabase
import json

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "abcd90909090")

def inspect_node():
    print(f"Connecting to {URI}...")
    try:
        driver = GraphDatabase.driver(URI, auth=AUTH)
        with driver.session() as session:
            # Fetch one UcoCWE node to inspect its JSON-like properties
            print("Fetching 1 UcoCWE node...")
            result = session.run("MATCH (n:UcoCWE) RETURN properties(n) as props LIMIT 1")
            record = result.single()
            
            if record:
                props = record["props"]
                print("\n=== Raw Node Properties ===")
                # Pretty print dictionary
                print(json.dumps(props, indent=2, default=str))
                
                print("\n=== Analysis ===")
                # Check for the JSON string fields you mentioned
                complex_fields = ["ucopotentialMitigations", "ucocommonConsequences", "ucodetectionMethods"]
                for field in complex_fields:
                    if field in props:
                        print(f"Found '{field}':")
                        print(f"  Type: {type(props[field])}")
                        print(f"  Value (First 100 chars): {str(props[field])[:100]}...")
                    else:
                        print(f"Field '{field}' NOT found.")
            else:
                print("No UcoCWE nodes found!")
                
        driver.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_node()
