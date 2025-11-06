import csv
from pathlib import Path
import re

# === CONFIG ===
input_text_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\column_append.txt")
target_csv_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\technical_dataset_gen_question.csv")

# === STEP 1: Read, clean, and overwrite input file with one question per line ===
text = input_text_file.read_text(encoding="utf-8")

# Extract quoted questions (anything between double quotes)
cleaned_lines = re.findall(r'"(.*?)"', text)
cleaned_lines = [q.strip() for q in cleaned_lines if q.strip()]

# Overwrite the same input file — each question on a new line
input_text_file.write_text("\n".join(cleaned_lines), encoding="utf-8")

print(f"✅ Step 1 done — cleaned file overwritten with {len(cleaned_lines)} questions at:")
print(f"   {input_text_file}")

# === STEP 2: Append missing 'CypherToQuestion' entries in target CSV ===
with target_csv_file.open("r", encoding="utf-8", newline="") as csvfile:
    reader = list(csv.DictReader(csvfile))
    fieldnames = reader[0].keys()

# Ensure column exists
if "CypherToQuestion" not in fieldnames:
    raise ValueError("❌ 'CypherToQuestion' column not found in target CSV!")

# Fill missing rows with questions (in order)
clean_index = 0
for row in reader:
    if (not row["CypherToQuestion"]) and clean_index < len(cleaned_lines):
        row["CypherToQuestion"] = cleaned_lines[clean_index]
        clean_index += 1

# Write back to same CSV
with target_csv_file.open("w", encoding="utf-8", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(reader)

print(f"✅ Step 2 done — updated CSV saved at: {target_csv_file}")
print(f"ℹ️ {clean_index} new questions appended.")
if clean_index < len(cleaned_lines):
    print(f"⚠️ {len(cleaned_lines) - clean_index} extra questions not used (CSV has fewer empty slots).")
