import csv
from pathlib import Path

# === CONFIG ===
input_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\Data Generation\Dataset Generation Process\technical dataset\technical_dataset_sample.csv")
output_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\Data Generation\Dataset Generation Process\technical dataset\technical_dataset_cleaned.csv")

column_to_clear = "generated_question"  # column name to delete values from

# === STEP 1: Read input CSV ===
with input_csv_file.open("r", encoding="utf-8", newline="") as csvfile:
    reader = list(csv.DictReader(csvfile))
    fieldnames = reader[0].keys()

# === STEP 2: Clear the target column ===
for row in reader:
    if column_to_clear in row:
        row[column_to_clear] = ""

# === STEP 3: Write output CSV ===
with output_csv_file.open("w", encoding="utf-8", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(reader)

print(f"✅ Cleared all values in column '{column_to_clear}'.")
print(f"💾 Cleaned CSV saved at: {output_csv_file}")
