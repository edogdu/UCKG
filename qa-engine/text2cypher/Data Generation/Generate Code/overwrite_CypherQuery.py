import pandas as pd
from pathlib import Path

# === CONFIG ===
source_csv = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset.csv")      # File that contains the updated CypherQuery column
target_csv = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_NaturalLanguageQuestion_ADJUSTED.csv")      # File you want to overwrite the CypherQuery column in
output_csv = target_csv                          # Overwrite the target file directly
# If you want to keep both, change it to:
# output_csv = Path(r"C:\path\to\target_updated.csv")

# === READ FILES ===
source_df = pd.read_csv(source_csv)
target_df = pd.read_csv(target_csv)

# === VALIDATE COLUMN EXISTENCE ===
if "CypherQuery" not in source_df.columns:
    raise ValueError(f"'CypherQuery' column not found in {source_csv}")
if "CypherQuery" not in target_df.columns:
    raise ValueError(f"'CypherQuery' column not found in {target_csv}")

# === OVERWRITE THE COLUMN ===
target_df["CypherQuery"] = source_df["CypherQuery"]

# === SAVE TO OUTPUT ===
target_df.to_csv(output_csv, index=False, encoding="utf-8")

print(f"✅ 'CypherQuery' column successfully overwritten in: {output_csv}")
