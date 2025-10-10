import os
import json
import pandas as pd
from neo4j import GraphDatabase, exceptions

def test_cypher_queries(file_path):
    """
    Connects to a Neo4j database and executes all cypher queries
    from a JSONL, CSV, or Excel file to validate their syntax and execution.

    Args:
        file_path (str): Path to the training data file (e.g., 'data.json', 'data.csv', or 'data.xlsx').
    """
    # 1. Get Neo4j connection details from environment variables
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
    total_entries = 0

    try:
        # --- LOGIC TO HANDLE DIFFERENT FILE FORMATS ---
        file_ext = file_path.lower()
        
        if file_ext.endswith('.json'):
            print(f"Detected JSON file. Processing line by line...")
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    total_entries += 1
                    try:
                        data = json.loads(line)
                        is_success = process_entry(i, data, driver)
                        if is_success:
                            successful_queries += 1
                        else:
                            failed_queries += 1
                    except json.JSONDecodeError:
                        print(f"❌ FAILED - Line {i}: Invalid JSON format.")
                        failed_queries += 1

        elif file_ext.endswith('.csv'):
            print(f"Detected CSV file. Processing with pandas...")
            df = pd.read_csv(file_path)
            total_entries = len(df)
            for i, row in df.iterrows():
                data = row.to_dict()
                is_success = process_entry(i + 1, data, driver)
                if is_success:
                    successful_queries += 1
                else:
                    failed_queries += 1
        
        elif file_ext.endswith(('.xlsx', '.xls')):
            print(f"Detected Excel file. Processing with pandas...")
            df = pd.read_excel(file_path)
            total_entries = len(df)
            for i, row in df.iterrows():
                data = row.to_dict()
                is_success = process_entry(i + 1, data, driver)
                if is_success:
                    successful_queries += 1
                else:
                    failed_queries += 1
        else:
            print(f"❌ Error: Unsupported file format. Please provide a .json, .csv, or .xlsx file.")
            return

    except FileNotFoundError:
        print(f"❌ Error: The file '{file_path}' was not found.")
        return
    except Exception as e:
        print(f"❌ An error occurred while reading the file: {e}")
        return
    finally:
        if driver:
            driver.close()

    # 4. Print a final summary
    print("\n--- Test Summary ---")
    print(f"Total Entries Processed: {total_entries}")
    print(f"✅ Successful Queries: {successful_queries}")
    print(f"❌ Failed/Skipped Queries: {failed_queries}")
    print("--------------------")

def process_entry(line_num, data, driver):
    """
    Processes a single entry (from any file type) to validate its Cypher query.
    Returns True on success, False on failure.
    """
    question = data.get("question", "N/A")
    cypher_query = data.get("cypher_query")

    # Ensure cypher_query is a string, handle potential float NaN from pandas
    if not isinstance(cypher_query, str) or not cypher_query.strip():
        print(f"⚠️ SKIPPED - Line {line_num}: No 'cypher_query' found or query is empty.")
        return False

    try:
        with driver.session() as session:
            session.run(cypher_query).consume()
        print(f"✅ PASSED - Line {line_num}: {question}")
        return True

    except exceptions.CypherSyntaxError as e:
        print(f"❌ FAILED - Line {line_num}: Cypher Syntax Error for question '{question}'")
        print(f"   Query: {cypher_query}")
        print(f"   Error: {e}")
        return False
    except Exception as e:
        print(f"❌ FAILED - Line {line_num}: An unexpected error occurred for question '{question}'")
        print(f"   Query: {cypher_query}")
        print(f"   Error: {e}")
        return False

# --- How to Use ---
# Set the name of your training data file (can be .json, .csv, or .xlsx)
# input_file = r'C:\path\to\your\training_data.json'
# input_file = r'C:\path\to\your\training_data.csv'
input_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\Kibrom_eval_dataset.csv'


# Run the test function
if __name__ == "__main__":
    # You will need to install pandas and openpyxl:
    # pip install pandas openpyxl
    test_cypher_queries(input_file)