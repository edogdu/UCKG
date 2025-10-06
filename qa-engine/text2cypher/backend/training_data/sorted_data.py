import pandas as pd

def sort_jsonl_to_csv(input_json_path, output_csv_path):
    """
    Reads a JSONL file, sorts it by 'difficulty_level', and saves it as a CSV file.

    Args:
        input_json_path (str): The path to the input .json file (JSONL format).
        output_csv_path (str): The path where the output .csv file will be saved.
    """
    try:
        # 1. Read the JSONL file into a pandas DataFrame
        # The 'lines=True' argument is essential for the JSONL format.
        print(f"Reading data from '{input_json_path}'...")
        df = pd.read_json(input_json_path, lines=True)

        # 2. Sort the DataFrame by the 'difficulty_level' column
        print("Sorting data by difficulty level...")
        sorted_df = df.sort_values(by='difficulty_level')
        
        # 3. Reorder columns for better readability (optional but recommended)
        if all(col in sorted_df.columns for col in ['difficulty_level', 'intent', 'question', 'cypher_query']):
            sorted_df = sorted_df[['difficulty_level', 'intent', 'question', 'cypher_query']]

        # 4. Save the sorted DataFrame to a CSV file
        # 'index=False' prevents pandas from writing row numbers into the file.
        sorted_df.to_csv(output_csv_path, index=False)
        
        print(f"✅ Success! Sorted data has been saved to '{output_csv_path}'")

    except FileNotFoundError:
        print(f"❌ Error: The file '{input_json_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# --- How to Use ---
# Define the names of your input and output files
input_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\traning_data.json'
output_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\training_data\sorted_training_data.csv'

# Call the function to perform the conversion and sorting
sort_jsonl_to_csv(input_file, output_file)