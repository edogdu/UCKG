import csv
import os
from pathlib import Path

# === CONFIGURATION ===
input_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset.csv")   # Change to your actual file path
output_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_appending_evaluation_dataset.csv")

# === Process file ===
with input_file.open("r", encoding="utf-8", newline="") as inf, \
     output_file.open("w", encoding="utf-8", newline="") as outf:

    reader = csv.reader(inf)  # robust parsing of the input CSV
    for row in reader:
        quoted_fields = []
        for field in row:
            # Escape any existing double-quotes inside the field by doubling them
            safe = field.replace('"', '""')
            # Wrap the field with a double-quote
            quoted_fields.append(f'"{safe}"')
        # Join with comma and write the finished line
        outf.write(",".join(quoted_fields) + "\n")

print(f"✅ Done — quoted CSV written to: {output_file}")