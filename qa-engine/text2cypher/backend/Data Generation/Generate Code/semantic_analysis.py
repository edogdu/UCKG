import re
from pathlib import Path
import statistics

# === CONFIG ===
input_file = Path(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\validation_log\question_cypher_relevance.txt")

# === READ FILE ===
text = input_file.read_text(encoding="utf-8")

# === EXTRACT NUMBERS AND STATUSES ===
pattern = re.compile(r"(PASS|FAIL)[^\d]*([\d.]+)")
matches = pattern.findall(text)

similarities = [float(m[1]) for m in matches]
statuses = [m[0] for m in matches]

# === CALCULATE OVERALL STATS ===
count = len(similarities)
avg_similarity = statistics.mean(similarities) if count else 0
max_similarity = max(similarities) if count else None
min_similarity = min(similarities) if count else None
pass_count = statuses.count("PASS")
fail_count = statuses.count("FAIL")
pass_rate = (pass_count / count * 100) if count else 0

# === SPLIT PASS AND FAIL DATA ===
pass_similarities = [float(m[1]) for m in matches if m[0] == "PASS"]
fail_similarities = [float(m[1]) for m in matches if m[0] == "FAIL"]

# === CALCULATE PASS STATS ===
if pass_similarities:
    avg_pass = statistics.mean(pass_similarities)
    max_pass = max(pass_similarities)
    min_pass = min(pass_similarities)
else:
    avg_pass = max_pass = min_pass = 0

# === CALCULATE FAIL STATS ===
if fail_similarities:
    avg_fail = statistics.mean(fail_similarities)
    max_fail = max(fail_similarities)
    min_fail = min(fail_similarities)
else:
    avg_fail = max_fail = min_fail = 0

# === BUILD REPORT ===
report_lines = [
    "📊 Question–Cypher Relevance Summary",
    "-" * 50,
    f"Total Entries:           {count}",
    f"PASS Count:              {pass_count}",
    f"FAIL Count:              {fail_count}",
    f"Pass Rate:               {pass_rate:.2f}%",
    "",
    "=== OVERALL SIMILARITY STATS ===",
    f"Average Similarity:      {avg_similarity:.4f}",
    f"Highest Similarity:      {max_similarity:.4f}",
    f"Lowest Similarity:       {min_similarity:.4f}",
    "",
    "=== PASS STATS ===",
    f"PASS Count:              {pass_count}",
    f"Average PASS Similarity: {avg_pass:.4f}",
    f"Highest PASS Similarity: {max_pass:.4f}",
    f"Lowest PASS Similarity:  {min_pass:.4f}",
    "",
    "=== FAIL STATS ===",
    f"FAIL Count:              {fail_count}",
    f"Average FAIL Similarity: {avg_fail:.4f}",
    f"Highest FAIL Similarity: {max_fail:.4f}",
    f"Lowest FAIL Similarity:  {min_fail:.4f}",
    "",
    "All Similarity Values:",
    ", ".join(f"{s:.4f}" for s in similarities),
]

# === WRITE TO .TXT FILE ===
output_txt = input_file.with_name(input_file.stem + "_summary.txt")
output_txt.write_text("\n".join(report_lines), encoding="utf-8")

print(f"✅ Summary saved to: {output_txt}")
