import os
import json
from neo4j import GraphDatabase, exceptions

def test_cypher_queries(json_file_path):
    """
    Connects to a Neo4j database and executes all cypher queries
    from a JSONL file to validate their syntax and execution.

    Args:
        json_file_path (str): Path to the training data file (e.g., 'training_data.json').
    """
    # 1. Get Neo4j connection details from environment variables (with defaults)
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "abcd90909090")

    driver = None
    try:
        # 2. Establish a connection to the Neo4j database
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        print(f"✅ Successfully connected to Neo4j at {uri}\n")
    except exceptions.AuthError as e:
        print(f"❌ Authentication failed. Please check NEO4J_USER and NEO4J_PASSWORD. Details: {e}")
        return
    except exceptions.ServiceUnavailable as e:
        print(f"❌ Connection failed. Is Neo4j running and available at {uri}? Details: {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred during connection: {e}")
        return

    # 3. Read the training data and test each query
    successful_queries = 0
    failed_queries = 0

    try:
        with open(json_file_path, 'r') as f:
            for i, line in enumerate(f, 1):
                try:
                    data = json.loads(line)
                    question = data.get("question", "N/A")
                    cypher_query = data.get("cypher_query")

                    if not cypher_query:
                        print(f"⚠️ SKIPPED - Line {i}: No 'cypher_query' found.")
                        continue

                    # Execute the query in a session
                    with driver.session() as session:
                        # We run the query and consume the result to ensure it executes fully
                        session.run(cypher_query).consume()
                    
                    print(f"✅ PASSED - Line {i}: {question}")
                    successful_queries += 1

                except json.JSONDecodeError:
                    print(f"❌ FAILED - Line {i}: Invalid JSON format.")
                    failed_queries += 1
                except exceptions.CypherSyntaxError as e:
                    print(f"❌ FAILED - Line {i}: Cypher Syntax Error for question '{question}'")
                    print(f"   Query: {cypher_query}")
                    print(f"   Error: {e}")
                    failed_queries += 1
                except Exception as e:
                    print(f"❌ FAILED - Line {i}: An unexpected error occurred for question '{question}'")
                    print(f"   Query: {cypher_query}")
                    print(f"   Error: {e}")
                    failed_queries += 1
    except FileNotFoundError:
        print(f"❌ Error: The file '{json_file_path}' was not found.")
        return
    finally:
        if driver:
            driver.close()

    # 4. Print a final summary
    print("\n--- Test Summary ---")
    print(f"Total Queries Tested: {successful_queries + failed_queries}")
    print(f"✅ Successful: {successful_queries}")
    print(f"❌ Failed: {failed_queries}")
    print("--------------------")

# --- How to Use ---
# Set the name of your training data file
input_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\training_data.json'

# Run the test function
if __name__ == "__main__":
    test_cypher_queries(input_file)