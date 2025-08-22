import json
import os
import matplotlib.pyplot as plt
from tabulate import tabulate

dir = "cti-analysis/extracted_triples"

# Step 1: Collect metrics from all chunk_data_*.json files
metrics = []
for filename in os.listdir(dir):
    if filename.startswith("chunk_data_") and filename.endswith(".json"):
        with open(os.path.join(dir, filename), "r", encoding="utf-8") as f:
            content = json.load(f)
            if "metrics" in content:
                metrics.append(content["metrics"])

# Step 2: Sort metrics by model name
metrics.sort(key=lambda m: m["model_used"])

# Step 3: Extract plotting data
models = [m["model_used"] for m in metrics]
valid_triples = [m["num_valid_triples"] for m in metrics]
suspicious_triples = [m["num_suspicious_triples"] for m in metrics]
avg_triples = [m["avg_triples_per_sentence"] for m in metrics]
runtime = [m["runtime_seconds"] for m in metrics]
efficiency = [v / r if r > 0 else 0 for v, r in zip(valid_triples, runtime)]

# Step 4: Plot 1 – Valid vs Suspicious Triples
plt.figure(figsize=(10, 6))
plt.bar(models, valid_triples, label="Valid", color="green")
plt.bar(models, suspicious_triples, bottom=valid_triples, label="Invalid", color="red", alpha=.9)
plt.ylabel("Triple Count")
plt.title("Valid vs Invalid Triples by Model")
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()
plt.savefig("chart_valid_vs_Invalid.png")
plt.show()

print("\nValid vs Invalid Triples by Model:")
print(tabulate(zip(models, valid_triples, suspicious_triples), headers=["Model", "Valid", "Invalid"]))

# Step 5: Plot 2 – Runtime by Model
plt.figure(figsize=(10, 6))
plt.bar(models, runtime, color="orange")
plt.ylabel("Runtime (seconds)")
plt.title("Runtime by Model")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("chart_runtime.png")
plt.show()

print("\nRuntime by Model:")
print(tabulate(zip(models, runtime), headers=["Model", "Runtime (sec)"]))

# Step 6: Plot 3 – Efficiency (Valid Triples per Second)
plt.figure(figsize=(10, 6))
plt.bar(models, efficiency, color="blue")
plt.ylabel("Valid Triples per Second")
plt.title("Extraction Efficiency by Model")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("chart_efficiency.png")
plt.show()

print("\nExtraction Efficiency by Model:")
print(tabulate(zip(models, efficiency), headers=["Model", "Valid Triples/sec"]))

# Step 7: Tabular chart of metrics
fig, ax = plt.subplots(figsize=(12, 2 + 0.5 * len(models)))
ax.set_axis_off()

# Build table data
table_data = [["Model", "Valid", "Invalid", "Avg/Sent", "Runtime (s)", "Efficiency"]]
for i in range(len(models)):
    table_data.append([
        models[i],
        valid_triples[i],
        suspicious_triples[i],
        f"{avg_triples[i]:.2f}",
        f"{runtime[i]:.2f}",
        f"{efficiency[i]:.3f}"
    ])

# Render table
table = ax.table(cellText=table_data, cellLoc="center", loc="center")
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1.2, 1.2)

plt.tight_layout()
plt.savefig("chart_metrics_table.png")
plt.show()