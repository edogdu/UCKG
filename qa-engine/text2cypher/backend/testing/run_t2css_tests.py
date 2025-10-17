import os
import json
import time
import pathlib

# Ensure backend package on path
BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
import sys
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from llm import OllamaLLM
from t2css_integration import create_enhanced_text2cypher


def main():
    # Force filtered mode
    os.environ["USE_T2CSS"] = "true"

    # Config
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
    T2CSS_TOP_K = int(os.getenv("T2CSS_TOP_K", "10"))

    # Initialize LLM and Text2Cypher (filtered)
    llm = OllamaLLM()
    t2c = create_enhanced_text2cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm, use_t2css=True, top_k_schema=T2CSS_TOP_K)

    # Load test dataset
    dataset_path = BACKEND_DIR / "testing" / "t2css_test_queries.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    results = {}

    for category, questions in test_data.items():
        cat_results = []
        for q in questions:
            t0 = time.time()
            try:
                resp = t2c.text_to_cypher_with_fallback(q)
                elapsed = time.time() - t0
                cat_results.append({
                    "question": q,
                    "status": resp.get("status"),
                    "cypher": resp.get("cypher"),
                    "count": len(resp.get("result", [])),
                    "elapsed_sec": round(elapsed, 3)
                })
            except Exception as e:
                elapsed = time.time() - t0
                cat_results.append({
                    "question": q,
                    "status": "error",
                    "error": str(e),
                    "elapsed_sec": round(elapsed, 3)
                })
        results[category] = cat_results

    # Write JSON report
    out_dir = BACKEND_DIR / "testing"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "t2css_test_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Write Markdown summary
    md_lines = ["# T2CSS Test Report", "", f"Top-K: {T2CSS_TOP_K}", ""]
    for category, cat_results in results.items():
        md_lines.append(f"## {category}")
        for item in cat_results:
            line = f"- Q: {item['question']} | status={item['status']} | count={item.get('count', 0)} | {item['elapsed_sec']}s"
            md_lines.append(line)
        md_lines.append("")
    md_path = out_dir / "t2css_test_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()

