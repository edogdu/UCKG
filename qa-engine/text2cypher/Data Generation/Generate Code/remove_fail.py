import csv
import re
from pathlib import Path

# === CONFIG ===
input_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\technical_dataset_gen_question.csv")
log_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\validation_log\sub-dataset logs\schema_check.txt")
output_csv_file = input_csv_file  # overwrite same file — change if you want to save elsewhere

# === STEP 1: Parse log file and extract failed entry numbers ===
fail_pattern = re.compile(r"Entry\s+#(\d+):\s+FAIL", re.IGNORECASE)
failed_entries = set()

with log_file.open("r", encoding="utf-8") as f:
    for line in f:
        match = fail_pattern.search(line)
        if match:
            failed_entries.add(int(match.group(1)))

print(f"🔍 Found {len(failed_entries)} failed entries: {sorted(failed_entries)}")

# === STEP 2: Read input CSV ===
with input_csv_file.open("r", encoding="utf-8", newline="") as csvfile:
    reader = list(csv.DictReader(csvfile))
    fieldnames = reader[0].keys()

# === STEP 3: Filter out failed rows ===
cleaned_rows = [
    row for idx, row in enumerate(reader, start=1)
    if idx not in failed_entries
]

removed_count = len(reader) - len(cleaned_rows)
print(f"🧹 Removing {removed_count} failed rows from CSV...")

# === STEP 4: Write back to same CSV ===
with output_csv_file.open("w", encoding="utf-8", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(cleaned_rows)

print(f"✅ Cleaned CSV saved at: {output_csv_file}")
print(f"📊 Total rows before: {len(reader)}, after cleanup: {len(cleaned_rows)}")
