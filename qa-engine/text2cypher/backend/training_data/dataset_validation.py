import pandas as pd
import json
from neo4j import GraphDatabase, exceptions

# --- Neo4j Connection Details ---
# ⚠️ IMPORTANT: Replace these placeholder values with your actual database credentials.
# For better security, consider using environment variables instead of hardcoding them.
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "abcd90909090"


def load_jsonl_robustly(file_path):
    """
    Reads a JSONL file line-by-line to provide detailed error feedback.

    Args:
        file_path (str): The path to the .json file.

    Returns:
        pd.DataFrame or None: A DataFrame if successful, otherwise None.
    """
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                # Skip empty lines
                if not line.strip():
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"❌ Fatal Error: Failed to decode JSON on line {i + 1}.")
                    print(f"   - Error Details: {e}")
                    print(f"   - Problematic Text: {line.strip()}")
                    print("   - Common Fix: Check for unescaped quotes or backslashes (e.g., use '\\'' instead of '\\'').")
                    return None
        return pd.DataFrame(data)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        return None


def check_data_reliability(file_path):
    """
    Analyzes a CSV or JSONL file for duplicates and missing values.

    Args:
        file_path (str): The path to the .csv or .json file.
    """
    print(f"--- Starting reliability check for: {file_path} ---\n")

    # Load the data based on file extension
    if file_path.endswith('.csv'):
        df = pd.read_csv(file_path)
    elif file_path.endswith('.json'):
        df = load_jsonl_robustly(file_path)
    else:
        print("Error: Unsupported file format. Please provide a .csv or .json file.")
        return

    # If loading failed, df will be None
    if df is None:
        print("\n--- Reliability check aborted due to file reading error. ---")
        return

    # 1. Check for duplicate rows
    duplicate_count = df.duplicated().sum()
    if duplicate_count > 0:
        print(f"Found {duplicate_count} duplicate rows in the file.")
    else:
        print("✅ No duplicate rows found.")

    # 2. Check for missing (null) values in each column
    missing_values = df.isnull().sum()
    missing_columns = missing_values[missing_values > 0]

    if not missing_columns.empty:
        print("\nFound missing values in the following columns:")
        for col, count in missing_columns.items():
            print(f"  - Column '{col}': {count} missing value(s)")
    else:
        print("✅ No missing values found in any column.")

    print("\n--- Reliability check complete. ---")


def validate_cypher_queries(file_path, uri, user, password):
    """
    Validates that Cypher queries in a JSONL file return results from the database.

    Args:
        file_path (str): The path to the .json file.
        uri (str): The URI for the Neo4j database.
        user (str): The username for the Neo4j database.
        password (str): The password for the Neo4j database.
    """
    print(f"\n--- Starting Cypher query validation for: {file_path} ---\n")

    df = load_jsonl_robustly(file_path)
    if df is None:
        print("\n--- Cypher validation aborted due to file reading error. ---")
        return

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
    except exceptions.AuthError:
        print("❌ Error: Neo4j authentication failed. Please check your username and password.")
        return
    except Exception as e:
        print(f"An error occurred while connecting to Neo4j: {e}")
        return

    empty_queries = 0
    with driver.session() as session:
        for index, row in df.iterrows():
            question = row.get('question', 'N/A')
            query = row.get('cypher_query', None)
            line_num = index + 1 # Use index for accurate line number reference

            if not query:
                print(f"⚠️ Warning: Line {line_num} has no 'cypher_query' field.")
                continue

            try:
                # Use peek() to efficiently check for the existence of at least one record
                result = session.run(query)
                if result.peek() is None:
                    empty_queries += 1
                    print(f"❗ Line {line_num}: Query returned no results.")
                    print(f"   - Question: \"{question}\"")

            except exceptions.CypherSyntaxError as e:
                empty_queries += 1
                print(f"❌ Line {line_num}: Query has a syntax error.")
                print(f"   - Question: \"{question}\"")
                print(f"   - Error: {e.message}")
            except Exception as e:
                empty_queries += 1
                print(f"❌ Line {line_num}: Query failed to execute.")
                print(f"   - Question: \"{question}\"")
                print(f"   - Error: {e}")

    driver.close()
    
    if empty_queries == 0:
        print("✅ All Cypher queries returned results.")
    else:
        print(f"\nFound {empty_queries} total queries that were empty or failed.")
        
    print("\n--- Cypher query validation complete. ---")


# --- Example Usage ---
# 1. Define the path to your training data file.
file_to_check = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\training_data.json'

# 2. Run the original data reliability checks.
check_data_reliability(file_to_check)

# 3. Run the new Cypher query validation.
#    This function uses the credentials defined at the top of the script.
validate_cypher_queries(file_to_check, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)