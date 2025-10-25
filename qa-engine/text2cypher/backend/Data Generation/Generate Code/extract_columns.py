import csv
from pathlib import Path

# === CONFIG ===
input_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\Data Generation\Dataset Generation Process\technical dataset\technical_dataset_COMPLETION.csv")
output_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\Data Generation\Dataset Generation Process\technical dataset\technical_dataset.csv")

# Columns you want to keep — just adjust this list later as needed
columns_to_keep = ["Category", "NaturalLanguageQuestion", "CypherQuery", "generated_question"]

# === STEP 1: Read input CSV ===
with input_csv_file.open("r", encoding="utf-8", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    # Filter only the columns that actually exist in the file
    valid_columns = [col for col in columns_to_keep if col in reader.fieldnames]

    if not valid_columns:
        raise ValueError("❌ None of the specified columns exist in the input file!")

    filtered_rows = [{col: row[col] for col in valid_columns} for row in reader]

# === STEP 2: Write filtered data to output CSV (overwrite mode) ===
with output_csv_file.open("w", encoding="utf-8", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=valid_columns)
    writer.writeheader()
    writer.writerows(filtered_rows)

print(f"✅ Extracted {len(valid_columns)} columns: {', '.join(valid_columns)}")
print(f"💾 Output saved to: {output_csv_file}")
