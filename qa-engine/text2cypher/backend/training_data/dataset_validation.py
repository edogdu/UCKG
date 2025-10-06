import pandas as pd

def check_data_reliability(file_path):
    """
    Analyzes a CSV or JSONL file for duplicates and missing values.

    Args:
        file_path (str): The path to the .csv or .json file.
    """
    print(f"--- Starting reliability check for: {file_path} ---\n")

    # Load the data based on file extension
    try:
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.endswith('.json'):
            # Assuming JSONL format (one JSON object per line)
            df = pd.read_json(file_path, lines=True)
        else:
            print("Error: Unsupported file format. Please provide a .csv or .json file.")
            return
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
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


# --- Example Usage ---
# Replace 'your_file.csv' or 'your_file.json' with the actual path to your file.
check_data_reliability(r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\sorted_training_data.csv')
# check_data_reliability(r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\traning_data.json')