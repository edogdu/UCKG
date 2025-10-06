import pandas as pd

def compare_question_differences(csv_file_path, json_file_path):
    """
    Compares the 'question' column of a CSV and a JSONL file to find differences.

    Args:
        csv_file_path (str): The path to the .csv file.
        json_file_path (str): The path to the .json file.
    """
    print(f"--- Comparing '{csv_file_path}' and '{json_file_path}' ---\n")

    # Load both files into pandas DataFrames
    try:
        df_csv = pd.read_csv(csv_file_path)
        # Assuming JSONL format (one JSON object per line)
        df_json = pd.read_json(json_file_path, lines=True)
    except FileNotFoundError as e:
        print(f"Error: Could not find a file. Details: {e}")
        return
    except Exception as e:
        print(f"An error occurred while reading the files: {e}")
        return

    # Ensure the 'question' column exists in both files
    if 'question' not in df_csv.columns or 'question' not in df_json.columns:
        print("Error: The 'question' column must exist in both files.")
        return

    # Convert the 'question' columns to sets for efficient comparison
    questions_csv = set(df_csv['question'])
    questions_json = set(df_json['question'])

    # Find questions that are only in the CSV file
    only_in_csv = questions_csv - questions_json

    # Find questions that are only in the JSON file
    only_in_json = questions_json - questions_csv

    if not only_in_csv and not only_in_json:
        print("✅ The 'question' columns in both files are identical.")
    else:
        if only_in_csv:
            print(f"Found {len(only_in_csv)} question(s) ONLY in '{csv_file_path}':")
            for i, q in enumerate(only_in_csv, 1):
                print(f"  {i}. {q}")
            print("-" * 20)

        if only_in_json:
            print(f"Found {len(only_in_json)} question(s) ONLY in '{json_file_path}':")
            for i, q in enumerate(only_in_json, 1):
                print(f"  {i}. {q}")
            print("-" * 20)

    print("\n--- Comparison complete. ---")


# --- Example Usage ---
# Replace with the actual paths to your files.
compare_question_differences(r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\sorted_training_data.csv',
                             r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\traning_data.json')