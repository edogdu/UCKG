from pathlib import Path
import re

# === CONFIG ===
input_csv = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\hundred_question_cypher.txt")

# === READ FILE ===
text = input_csv.read_text(encoding="utf-8")

# === FIX FORMAT ===
# The pattern: after each closing quote followed by a space and another opening quote,
# insert a newline
fixed_text = re.sub(r'"\s+"', '"\n"', text)

# === OVERWRITE FILE ===
input_csv.write_text(fixed_text, encoding="utf-8")

print(f"✅ Added newlines between CSV rows in: {input_csv}")
