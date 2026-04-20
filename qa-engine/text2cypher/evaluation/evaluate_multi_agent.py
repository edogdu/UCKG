"""
Multi-Agent Text2Cypher Pipeline Evaluation

Evaluates the Multi-Agent pipeline (inspired by Multi-Agent GraphRAG, Gusarov et al. 2025)
against the same dataset used for Enhanced T2CSS evaluation.

Runs both pipelines on each question and compares:
  - Pass@1, KG Valid Rate, Output Jaccard, JaRou, LLMetric  (same metrics)
  - Multi-Agent–specific: iterations used, grade distribution, verification triggers

Usage:
    python evaluation/evaluate_multi_agent.py
"""

import csv
import json
import math
import os
import re
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tqdm import tqdm
from neo4j import GraphDatabase

parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))
sys.path.insert(0, str(parent_dir / "core"))
sys.path.insert(0, str(parent_dir / "llm"))
sys.path.insert(0, str(parent_dir / "validation"))

from multi_agent_t2c import MultiAgentText2Cypher
from t2css_enhanced import EnhancedT2CSSPipeline
from ollama_llm import OllamaLLM
from noexec_validator import validate_cypher_noexec

# ========== CONFIGURATION ==========

CSV_PATH = Path(__file__).resolve().parent.parent / "dataset" / "technical_dataset_COMPLETION_clean.csv"

OUTPUT_CSV = Path(__file__).resolve().parent / "results_multi_agent.csv"
REPORT_MD = Path(__file__).resolve().parent / "report_multi_agent.md"

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "abcd90909090")

MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1:70b")
TOP_K_SCHEMA = int(os.getenv("T2CSS_TOP_K", "12"))
FEWSHOT_K = int(os.getenv("FEWSHOT_K", "3"))
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "4"))

QUERY_TIMEOUT = 30

# Also run the single-pass Enhanced T2CSS for A/B comparison
RUN_BASELINE = True

# ========== TEXT SIMILARITY METRICS ==========

def tokenize(s: str) -> List[str]:
    return [t for t in re.split(r"[^A-Za-z0-9_]+", s.lower()) if t]


def jaro_winkler(s1: str, s2: str, scaling: float = 0.1) -> float:
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    match_window = max(len(s1), len(s2)) // 2 - 1
    s1_matches = [False] * len(s1)
    s2_matches = [False] * len(s2)
    matches = 0
    transpositions = 0
    for i, c1 in enumerate(s1):
        start = max(0, i - match_window)
        end = min(i + match_window + 1, len(s2))
        for j in range(start, end):
            if s2_matches[j] or c1 != s2[j]:
                continue
            s1_matches[i] = s2_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    k = 0
    for i, c1 in enumerate(s1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if c1 != s2[k]:
            transpositions += 1
        k += 1
    jaro = (matches / len(s1) + matches / len(s2) + (matches - transpositions / 2) / matches) / 3
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4]):
        if c1 == c2:
            prefix += 1
        else:
            break
    return jaro + prefix * scaling * (1 - jaro)


def jaccard_tokens(a: str, b: str) -> float:
    ta, tb = set(tokenize(a)), set(tokenize(b))
    if not ta and not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def lcs_len(a_tokens: List[str], b_tokens: List[str]) -> int:
    n, m = len(a_tokens), len(b_tokens)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if a_tokens[i - 1] == b_tokens[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[n][m]


def rouge_l_f1(a: str, b: str) -> float:
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return 0.0
    lcs = lcs_len(ta, tb)
    p = lcs / len(ta)
    r = lcs / len(tb)
    if p == 0 and r == 0:
        return 0.0
    return 2 * p * r / (p + r)


def precision_recall_f1_tokens(a: str, b: str) -> Tuple[float, float, float]:
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return 0.0, 0.0, 0.0
    set_a, set_b = set(ta), set(tb)
    tp = len(set_a & set_b)
    p = tp / len(set_a) if set_a else 0.0
    r = tp / len(set_b) if set_b else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return p, r, f1


def bleu_4(reference: str, candidate: str) -> float:
    ref_tokens = tokenize(reference)
    cand_tokens = tokenize(candidate)
    if not ref_tokens or not cand_tokens:
        return 0.0
    bp = 1.0 if len(cand_tokens) >= len(ref_tokens) else math.exp(1 - len(ref_tokens) / len(cand_tokens))
    precisions = []
    for n in range(1, 5):
        if len(cand_tokens) < n:
            precisions.append(0.0)
            continue
        ref_ngrams = [tuple(ref_tokens[i:i + n]) for i in range(len(ref_tokens) - n + 1)]
        cand_ngrams = [tuple(cand_tokens[i:i + n]) for i in range(len(cand_tokens) - n + 1)]
        ref_counts = {}
        for ng in ref_ngrams:
            ref_counts[ng] = ref_counts.get(ng, 0) + 1
        mat = 0
        for ng in cand_ngrams:
            if ng in ref_counts and ref_counts[ng] > 0:
                mat += 1
                ref_counts[ng] -= 1
        precisions.append(mat / len(cand_ngrams) if cand_ngrams else 0.0)
    if all(p > 0 for p in precisions):
        return bp * math.exp(sum(math.log(p) for p in precisions) / 4)
    return 0.0


# ========== NEO4J EXECUTION ==========

def execute_cypher_with_timeout(driver, cypher: str, timeout: int = QUERY_TIMEOUT) -> Tuple[Optional[List], Optional[str]]:
    result_container = {"records": None, "error": None}

    def run_query():
        try:
            with driver.session() as session:
                result = session.run(cypher)
                result_container["records"] = [dict(record) for record in result]
        except Exception as e:
            result_container["error"] = str(e)

    thread = threading.Thread(target=run_query)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        return None, f"Query timeout after {timeout}s"
    if result_container["error"]:
        return None, result_container["error"]
    return result_container["records"], None


def results_jaccard(r1: Optional[List], r2: Optional[List]) -> float:
    if r1 is None or r2 is None:
        return 0.0

    def normalize_result(records):
        normalised = []
        for record in records:
            sorted_items = tuple(sorted((k, str(v)) for k, v in record.items()))
            normalised.append(sorted_items)
        return set(normalised)

    set1 = normalize_result(r1)
    set2 = normalize_result(r2)
    if not set1 and not set2:
        return 1.0
    inter = len(set1 & set2)
    union = len(set1 | set2)
    return inter / union if union else 0.0


# ========== ROW-LEVEL SCORING ==========

def score_row(gold_cypher: str, gen_cypher: str, gold_results, gen_results) -> Dict:
    """Compute all similarity / correctness metrics for a single row."""
    pass_at_1 = 1 if (gold_results is not None and gen_results is not None and gold_results == gen_results) else 0
    output_jac = results_jaccard(gold_results, gen_results)
    jw = jaro_winkler(gold_cypher, gen_cypher)
    jacc = jaccard_tokens(gold_cypher, gen_cypher)
    rouge = rouge_l_f1(gold_cypher, gen_cypher)
    _, _, f1_tok = precision_recall_f1_tokens(gold_cypher, gen_cypher)
    bleu = bleu_4(gold_cypher, gen_cypher)
    jarou = (rouge + f1_tok + jw) / 3
    return {
        "pass_at_1": pass_at_1,
        "output_jaccard": output_jac,
        "jaro_winkler": jw,
        "token_jaccard": jacc,
        "rouge_l": rouge,
        "token_f1": f1_tok,
        "bleu_4": bleu,
        "jarou_factor": jarou,
    }


# ========== MAIN EVALUATION ==========

def evaluate():
    print("=" * 80)
    print("MULTI-AGENT TEXT2CYPHER EVALUATION")
    print("=" * 80)
    print(f"\nDataset:        {CSV_PATH}")
    print(f"Model:          {MODEL_NAME}")
    print(f"Top-K Schema:   {TOP_K_SCHEMA}")
    print(f"Few-Shot K:     {FEWSHOT_K}")
    print(f"Max Iterations: {MAX_ITERATIONS}")
    print(f"Run Baseline:   {RUN_BASELINE}")
    print(f"Output CSV:     {OUTPUT_CSV}")
    print("=" * 80)

    if not CSV_PATH.exists():
        print(f"\nError: dataset not found at {CSV_PATH}")
        return

    with CSV_PATH.open("r", encoding="utf-8") as f:
        dataset = list(csv.DictReader(f))

    print(f"\nLoaded {len(dataset)} questions")

    # --- Neo4j ---
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # --- LLM ---
    llm = OllamaLLM(model=MODEL_NAME)

    # --- Enhanced T2CSS (shared by both pipelines) ---
    print("\nInitialising Enhanced T2CSS pipeline...")
    pipeline = EnhancedT2CSSPipeline(
        top_k=TOP_K_SCHEMA,
        fewshot_k=FEWSHOT_K,
        auto_load_fewshot=True,
    )

    # --- Multi-Agent pipeline ---
    print("Initialising Multi-Agent pipeline...")
    multi_agent = MultiAgentText2Cypher(
        neo4j_driver=driver,
        llm=llm,
        enhanced_pipeline=pipeline,
        max_iterations=MAX_ITERATIONS,
        verbose=False,
    )

    # --- Evaluate ---
    print(f"\nStarting evaluation on {len(dataset)} questions...\n")

    results = []

    for i, row in enumerate(tqdm(dataset, desc="Evaluating")):
        nl_question = row.get("NaturalLanguageQuestion", "")
        gold_cypher = row.get("CypherQuery", "")
        category = row.get("Category", "Unknown")

        # ------ Multi-Agent ------
        t0 = time.time()
        try:
            ma_out = multi_agent.invoke(nl_question)
        except Exception as e:
            ma_out = {"cypher": "", "status": "error", "message": str(e), "iterations": 0, "eval_grade": "", "trace": []}
        ma_time = time.time() - t0

        ma_cypher = ma_out.get("cypher", "") or ""
        ma_status = ma_out.get("status", "error")
        ma_iters = ma_out.get("iterations", 0)
        ma_grade = ma_out.get("eval_grade", "")

        ma_kg_valid = 0
        if ma_cypher:
            is_valid, _ = validate_cypher_noexec(driver, ma_cypher)
            ma_kg_valid = 1 if is_valid else 0

        gold_results, gold_error = execute_cypher_with_timeout(driver, gold_cypher)
        ma_results, ma_error = execute_cypher_with_timeout(driver, ma_cypher) if ma_cypher else (None, "No query")

        ma_scores = score_row(gold_cypher, ma_cypher, gold_results, ma_results)

        # ------ Baseline (single-pass Enhanced T2CSS) ------
        bl_cypher = ""
        bl_kg_valid = 0
        bl_scores = {}
        bl_time = 0.0
        if RUN_BASELINE:
            t0 = time.time()
            try:
                bl_cypher = pipeline.generate_cypher(nl_question, llm=llm)
            except Exception:
                bl_cypher = ""
            bl_time = time.time() - t0

            if bl_cypher:
                is_valid, _ = validate_cypher_noexec(driver, bl_cypher)
                bl_kg_valid = 1 if is_valid else 0

            bl_results, bl_error = execute_cypher_with_timeout(driver, bl_cypher) if bl_cypher else (None, "No query")
            bl_scores = score_row(gold_cypher, bl_cypher, gold_results, bl_results)

        entry = {
            "question": nl_question,
            "category": category,
            "gold_cypher": gold_cypher,
            # Multi-Agent
            "ma_cypher": ma_cypher,
            "ma_kg_valid": ma_kg_valid,
            "ma_status": ma_status,
            "ma_iterations": ma_iters,
            "ma_grade": ma_grade,
            "ma_time_s": round(ma_time, 2),
            "ma_pass_at_1": ma_scores.get("pass_at_1", 0),
            "ma_output_jaccard": ma_scores.get("output_jaccard", 0),
            "ma_jarou_factor": ma_scores.get("jarou_factor", 0),
            "ma_jaro_winkler": ma_scores.get("jaro_winkler", 0),
            "ma_token_jaccard": ma_scores.get("token_jaccard", 0),
            "ma_rouge_l": ma_scores.get("rouge_l", 0),
            "ma_token_f1": ma_scores.get("token_f1", 0),
            "ma_bleu_4": ma_scores.get("bleu_4", 0),
        }
        if RUN_BASELINE:
            entry.update({
                "bl_cypher": bl_cypher,
                "bl_kg_valid": bl_kg_valid,
                "bl_time_s": round(bl_time, 2),
                "bl_pass_at_1": bl_scores.get("pass_at_1", 0),
                "bl_output_jaccard": bl_scores.get("output_jaccard", 0),
                "bl_jarou_factor": bl_scores.get("jarou_factor", 0),
                "bl_jaro_winkler": bl_scores.get("jaro_winkler", 0),
                "bl_token_jaccard": bl_scores.get("token_jaccard", 0),
                "bl_rouge_l": bl_scores.get("rouge_l", 0),
                "bl_token_f1": bl_scores.get("token_f1", 0),
                "bl_bleu_4": bl_scores.get("bleu_4", 0),
            })
        results.append(entry)

    driver.close()

    # ------ Save CSV ------
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved detailed results to {OUTPUT_CSV}")

    # ------ Aggregate & report ------
    _print_and_save_report(results)


def _print_and_save_report(results: List[Dict]):
    n = len(results)
    if n == 0:
        return

    def avg(key):
        return sum(r.get(key, 0) for r in results) / n

    # Multi-Agent aggregates
    ma_pass1 = avg("ma_pass_at_1") * 100
    ma_kg = avg("ma_kg_valid") * 100
    ma_oj = avg("ma_output_jaccard") * 100
    ma_jarou = avg("ma_jarou_factor") * 100
    ma_llm = 0.3 * ma_pass1 + 0.4 * ma_kg + 0.2 * ma_oj + 0.1 * ma_jarou
    ma_avg_iter = avg("ma_iterations")
    ma_avg_time = avg("ma_time_s")

    # Grade distribution
    grade_counts = defaultdict(int)
    for r in results:
        grade_counts[r.get("ma_grade", "unknown")] += 1

    # Baseline aggregates (if run)
    has_bl = "bl_pass_at_1" in results[0]
    bl_pass1 = bl_kg = bl_oj = bl_jarou = bl_llm = bl_avg_time = 0.0
    if has_bl:
        bl_pass1 = avg("bl_pass_at_1") * 100
        bl_kg = avg("bl_kg_valid") * 100
        bl_oj = avg("bl_output_jaccard") * 100
        bl_jarou = avg("bl_jarou_factor") * 100
        bl_llm = 0.3 * bl_pass1 + 0.4 * bl_kg + 0.2 * bl_oj + 0.1 * bl_jarou
        bl_avg_time = avg("bl_time_s")

    # Per-category
    cats = defaultdict(list)
    for r in results:
        cats[r["category"]].append(r)

    # Console
    print("\n" + "=" * 80)
    print("EVALUATION RESULTS")
    print("=" * 80)
    print(f"\n{'Metric':<25} {'Multi-Agent':>15}", end="")
    if has_bl:
        print(f" {'Baseline (T2CSS)':>18} {'Delta':>10}", end="")
    print()
    print("-" * (25 + 15 + (28 if has_bl else 0)))

    def line(label, ma_val, bl_val=None, fmt=".1f", suffix="%"):
        s = f"{label:<25} {ma_val:{fmt}}{suffix:>2}"
        if bl_val is not None:
            delta = ma_val - bl_val
            sign = "+" if delta >= 0 else ""
            s += f" {bl_val:{fmt}}{suffix:>2}     {sign}{delta:{fmt}}{suffix}"
        print(s)

    line("Pass@1", ma_pass1, bl_pass1 if has_bl else None)
    line("KG Valid Rate", ma_kg, bl_kg if has_bl else None)
    line("Output Jaccard", ma_oj, bl_oj if has_bl else None)
    line("JaRou Factor", ma_jarou, bl_jarou if has_bl else None)
    line("LLMetric", ma_llm, bl_llm if has_bl else None)
    line("Avg Time (s)", ma_avg_time, bl_avg_time if has_bl else None, fmt=".2f", suffix="s")
    print(f"{'Avg Iterations':<25} {ma_avg_iter:>15.2f}")
    print(f"\nGrade distribution: {dict(grade_counts)}")

    # Markdown report
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_MD.open("w", encoding="utf-8") as md:
        md.write("# Multi-Agent Text2Cypher Evaluation Report\n\n")
        md.write(f"**Dataset**: `{CSV_PATH.name}` ({n} questions)\n\n")
        md.write(f"**Model**: {MODEL_NAME}\n\n")
        md.write(f"**Config**: top_k={TOP_K_SCHEMA}, fewshot_k={FEWSHOT_K}, max_iter={MAX_ITERATIONS}\n\n")
        md.write("---\n\n")

        md.write("## Head-to-Head Comparison\n\n")
        md.write("| Metric | Multi-Agent | Baseline (T2CSS) | Delta |\n")
        md.write("|--------|:-----------:|:----------------:|:-----:|\n")

        def md_row(label, ma_v, bl_v):
            delta = ma_v - bl_v
            sign = "+" if delta >= 0 else ""
            md.write(f"| {label} | {ma_v:.1f}% | {bl_v:.1f}% | {sign}{delta:.1f}% |\n")

        if has_bl:
            md_row("Pass@1", ma_pass1, bl_pass1)
            md_row("KG Valid Rate", ma_kg, bl_kg)
            md_row("Output Jaccard", ma_oj, bl_oj)
            md_row("JaRou Factor", ma_jarou, bl_jarou)
            md_row("LLMetric", ma_llm, bl_llm)
        else:
            md.write(f"| Pass@1 | {ma_pass1:.1f}% | — | — |\n")
            md.write(f"| KG Valid Rate | {ma_kg:.1f}% | — | — |\n")
            md.write(f"| Output Jaccard | {ma_oj:.1f}% | — | — |\n")
            md.write(f"| JaRou Factor | {ma_jarou:.1f}% | — | — |\n")
            md.write(f"| LLMetric | {ma_llm:.1f} | — | — |\n")

        md.write(f"\n**Multi-Agent**: avg {ma_avg_iter:.1f} iterations, {ma_avg_time:.1f}s per question\n\n")
        if has_bl:
            md.write(f"**Baseline**: single-pass, {bl_avg_time:.1f}s per question\n\n")

        md.write(f"\n**Grade distribution**: {dict(grade_counts)}\n\n")

        md.write("---\n\n## Per-Category Comparison\n\n")
        md.write("| Category | n | MA Pass@1 | BL Pass@1 | MA KG | BL KG | MA LLMetric | BL LLMetric |\n")
        md.write("|----------|---|:---------:|:---------:|:-----:|:-----:|:-----------:|:-----------:|\n")

        for cat in sorted(cats.keys()):
            cr = cats[cat]
            nc = len(cr)

            def cavg(key):
                return sum(r.get(key, 0) for r in cr) / nc * 100

            cp1 = cavg("ma_pass_at_1")
            ckg = cavg("ma_kg_valid")
            coj = cavg("ma_output_jaccard")
            cjr = cavg("ma_jarou_factor")
            cll = 0.3 * cp1 + 0.4 * ckg + 0.2 * coj + 0.1 * cjr

            if has_bl:
                bp1 = cavg("bl_pass_at_1")
                bkg = cavg("bl_kg_valid")
                boj = cavg("bl_output_jaccard")
                bjr = cavg("bl_jarou_factor")
                bll = 0.3 * bp1 + 0.4 * bkg + 0.2 * boj + 0.1 * bjr
                md.write(f"| {cat} | {nc} | {cp1:.1f}% | {bp1:.1f}% | {ckg:.1f}% | {bkg:.1f}% | {cll:.1f} | {bll:.1f} |\n")
            else:
                md.write(f"| {cat} | {nc} | {cp1:.1f}% | — | {ckg:.1f}% | — | {cll:.1f} | — |\n")

        md.write("\n---\n\n")
        md.write("## Methodology\n\n")
        md.write("The Multi-Agent pipeline implements Algorithm 1 from *Multi-Agent GraphRAG* ")
        md.write("(Gusarov et al., 2025) adapted to the UCKG cybersecurity knowledge graph:\n\n")
        md.write("1. **Query Generator** — Enhanced T2CSS (semantic schema slices + dynamic few-shots)\n")
        md.write("2. **Graph DB Executor** — Neo4j execution\n")
        md.write("3. **Query Evaluator** — LLM critic (Accept / Incorrect / Error-or-Empty)\n")
        md.write("4. **Named Entity Extractor** — LLM extracts labels, properties, relationships\n")
        md.write("5. **Verification Module** — checks entities against the live graph with Levenshtein correction\n")
        md.write("6. **Instructions Generator** — correction instructions from verification\n")
        md.write("7. **Feedback Aggregator** — merges evaluator + verification feedback\n")
        md.write("8. **Interpreter** — natural-language answer from accepted results\n\n")
        md.write(f"Max self-correction iterations: **{MAX_ITERATIONS}**\n\n")
        md.write("---\n\n*Generated by evaluate_multi_agent.py*\n")

    print(f"\nReport saved to {REPORT_MD}")


if __name__ == "__main__":
    evaluate()
