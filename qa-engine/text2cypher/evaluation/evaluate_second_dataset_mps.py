import csv
import os
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
from neo4j import GraphDatabase
import time

import sys, pathlib

# Get the correct paths
EVAL_DIR = pathlib.Path(__file__).resolve().parent
TEXT2CYPHER_DIR = EVAL_DIR.parent

# Add both core and llm directories to path
CORE_DIR = TEXT2CYPHER_DIR / 'core'
LLM_DIR = TEXT2CYPHER_DIR / 'llm'

for dir_path in [CORE_DIR, LLM_DIR, TEXT2CYPHER_DIR]:
    if str(dir_path) not in sys.path:
        sys.path.insert(0, str(dir_path))

from text2cypher import Text2Cypher
from t2css_integration import create_enhanced_text2cypher
from ollama_llm import OllamaLLM

# Import validation module for non-execution validation
sys.path.insert(0, str(TEXT2CYPHER_DIR / 'validation'))
from noexec_validator import validate_cypher_noexec

# Use the NEW second technical dataset
CSV_PATH = TEXT2CYPHER_DIR / "dataset" / "technical_dataset_Second_COMPLETION.csv"
REPORT_MD = EVAL_DIR / "report_second_dataset_mps.md"
RESULTS_CSV = EVAL_DIR / "results_second_dataset_mps.csv"

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "abcd90909090"

print("="*80)
print("INITIALIZING EVALUATION WITH MPS GPU ACCELERATION")
print("="*80)
print(f"Dataset: {CSV_PATH.name}")
print(f"Dataset path: {CSV_PATH}")
print(f"Core directory: {CORE_DIR}")
print(f"Dataset exists: {CSV_PATH.exists()}")

# Initialize LLM with Ollama (MPS GPU acceleration happens automatically on Mac)
print("\n🚀 Initializing Ollama LLM (MPS GPU will be used automatically)...")
llama_llm = OllamaLLM(model="llama3:instruct", base_url="http://localhost:11434")

print("📊 Initializing Full Schema pipeline...")
llama_full = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASS, llama_llm)

print("🔍 Initializing T2CSS Semantic Schema pipeline (with embeddings)...")
print("   Note: Embeddings will use Ollama's nomic-embed-text model")
llama_semantic = create_enhanced_text2cypher(
    NEO4J_URI, NEO4J_USER, NEO4J_PASS, llama_llm, 
    use_t2css=True, 
    top_k_schema=10
)

print("✅ Both pipelines initialized!\n")

############################
# Text similarity metrics
############################
import re

def tokenize(s: str) -> List[str]:
    return [t for t in re.split(r"[^A-Za-z0-9_]+", s.lower()) if t]


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


def precision_recall_f1_tokens(a: str, b: str) -> tuple[float, float, float]:
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return 0.0, 0.0, 0.0
    set_a, set_b = set(ta), set(tb)
    tp = len(set_a & set_b)
    p = tp / len(set_a) if set_a else 0.0
    r = tp / len(set_b) if set_b else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return p, r, f1


def jaro_winkler(s1: str, s2: str) -> float:
    # Jaro distance
    s1, s2 = s1.lower(), s2.lower()
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    match_dist = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    # count matches
    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0

    # count transpositions
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    transpositions //= 2

    jaro = (
        (matches / len1) + (matches / len2) + ((matches - transpositions) / matches)
    ) / 3.0

    # Winkler adjustment (common prefix up to 4)
    prefix = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return jaro + 0.1 * prefix * (1 - jaro)


def ngram_counts(tokens: List[str], n: int) -> Dict[tuple[str, ...], int]:
    counts: Dict[tuple[str, ...], int] = {}
    if len(tokens) < n:
        return counts
    for i in range(len(tokens) - n + 1):
        ng = tuple(tokens[i : i + n])
        counts[ng] = counts.get(ng, 0) + 1
    return counts


def clipped_precision(candidate: List[str], reference: List[str], n: int) -> float:
    cand_counts = ngram_counts(candidate, n)
    ref_counts = ngram_counts(reference, n)
    if not cand_counts:
        return 0.0
    overlap = 0
    total = 0
    for ng, c in cand_counts.items():
        total += c
        overlap += min(c, ref_counts.get(ng, 0))
    return overlap / total if total else 0.0


def bleu4(candidate_text: str, reference_text: str) -> float:
    c = tokenize(candidate_text)
    r = tokenize(reference_text)
    if not c or not r:
        return 0.0
    ps = [clipped_precision(c, r, n) for n in range(1, 4 + 1)]
    if any(p == 0 for p in ps):
        geo = 0.0
    else:
        geo = math.exp(sum(math.log(p) for p in ps) / 4.0)
    len_c, len_r = len(c), len(r)
    bp = 1.0 if len_c > len_r else math.exp(1 - (len_r / max(len_c, 1)))
    return bp * geo


# helper to catch generation errors
def safe_generate(t2c: Text2Cypher, question: str) -> str:
    """
    Generate Cypher query WITHOUT validation.
    Validation happens later during evaluation to measure KG Valid Rate.
    """
    try:
        schema = t2c.get_schema()
        
        # Get few-shot examples from config (it's already a formatted string)
        from config import FEW_SHOT_EXAMPLES
        
        # Build prompt with all required parameters
        prompt = t2c._build_prompt(question, schema, FEW_SHOT_EXAMPLES)
        
        # Generate without validation - just get raw LLM output
        cypher = t2c.llm.invoke(prompt)
        
        # Clean up the response
        if cypher:
            cypher = cypher.strip()
            # Remove markdown code blocks if present
            if cypher.startswith('```'):
                lines = cypher.split('\n')
                cypher = '\n'.join(lines[1:-1]) if len(lines) > 2 else cypher
            cypher = cypher.replace('```cypher', '').replace('```', '').strip()
        return cypher if cypher else ""
    except Exception as e:
        print(f"[Generation Error]: {str(e)[:100]}")
        import traceback
        traceback.print_exc()
        return ""


############################
# Output execution helpers
############################

def run_and_fetch_set(driver, query: str, timeout_seconds: int = 30) -> Optional[set]:
    """Execute query with timeout protection"""
    if not query or not query.strip():
        return None
    
    import threading
    result_container = {'result': None, 'error': None}
    
    def execute_query():
        try:
            with driver.session() as sess:
                result = sess.run(query)
                rows = []
                for rec in result:
                    data = rec.data()
                    items = tuple(sorted((k, str(v)) for k, v in data.items()))
                    rows.append(items)
                    if len(rows) > 10000:  # Prevent memory issues
                        break
                result_container['result'] = set(rows) if rows else set()
        except Exception as e:
            result_container['error'] = str(e)
    
    # Run query in separate thread with timeout
    thread = threading.Thread(target=execute_query)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout_seconds)
    
    if thread.is_alive():
        # Query timed out
        print(f"[Timeout] Query exceeded {timeout_seconds}s limit")
        return None
    
    if result_container['error']:
        # Query execution failed
        return None
    
    return result_container['result']


def jaccard_sets(a: Optional[set], b: Optional[set]) -> float:
    if a is None or b is None:
        return 0.0
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {CSV_PATH}")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    rows: List[Dict] = []
    limit_env = os.getenv("EVAL_LIMIT")
    limit = int(limit_env) if limit_env else None
    seen = 0
    
    start_time = time.time()
    
    print("="*80)
    print("STARTING EVALUATION")
    print("="*80)
    if limit:
        print(f"Evaluating first {limit} queries...")
    else:
        print(f"Evaluating all queries in dataset...")
    print()
    print("📝 Evaluation Strategy:")
    print("   1. Generate Cypher (NO validation - raw LLM output)")
    print("   2. Validate WITHOUT execution (syntax + schema checks)")
    print("      → This measures KG Valid Rate")
    print("   3. Execute valid queries only")
    print("      → This measures Pass@1 and Output Jaccard")
    print("   4. Compute text similarity metrics (BLEU, ROUGE-L, etc.)")
    print()
    
    with CSV_PATH.open() as f:
        reader = csv.DictReader(f)
        for row in tqdm(reader, desc="Evaluating (Llama3 Full vs T2CSS Semantic)", unit="query"):
            # Adapt to new dataset columns
            question = row.get("NaturalLanguageQuestion", "")
            gold = row.get("CypherQuery", "").strip()
            category = row.get("Category", "Unknown")
            hops = row.get("Hops", "")
            
            # Skip queries with unbounded variable-length paths (too expensive)
            if re.search(r'\[\*\d+\.\.\]', gold):
                print(f"\n⚠️  Skipping unbounded path query: {question[:60]}...")
                continue

            # Generate with both pipelines (NO validation - just raw LLM output)
            llama_full_pred = safe_generate(llama_full, question)
            llama_sem_pred = safe_generate(llama_semantic, question)

            # STEP 1: Validate WITHOUT execution (syntax + schema checks)
            # This measures KG Valid Rate = syntactically correct + schema-aware
            full_kg_ok, full_errors = validate_cypher_noexec(driver, llama_full_pred)
            sem_kg_ok, sem_errors = validate_cypher_noexec(driver, llama_sem_pred)
            
            # STEP 2: Execute queries (only if they passed validation)
            # This measures Pass@1 and Output Jaccard
            full_set = None
            sem_set = None
            
            if full_kg_ok:
                try:
                    full_set = run_and_fetch_set(driver, llama_full_pred)
                except Exception as e:
                    print(f"[Full] Execution failed despite validation: {str(e)[:100]}")
            
            if sem_kg_ok:
                try:
                    sem_set = run_and_fetch_set(driver, llama_sem_pred)
                except Exception as e:
                    print(f"[Semantic] Execution failed despite validation: {str(e)[:100]}")

            # Execute gold query
            gold_set = run_and_fetch_set(driver, gold)

            # Pass@1 (exact output match)
            full_pass = 1 if (full_set is not None and gold_set is not None and full_set == gold_set) else 0
            sem_pass = 1 if (sem_set is not None and gold_set is not None and sem_set == gold_set) else 0

            # Output Jaccard
            full_out_jacc = jaccard_sets(full_set, gold_set)
            sem_out_jacc = jaccard_sets(sem_set, gold_set)

            # Cypher text metrics
            jw_full = jaro_winkler(llama_full_pred, gold)
            jw_sem = jaro_winkler(llama_sem_pred, gold)
            jac_full = jaccard_tokens(llama_full_pred, gold)
            jac_sem = jaccard_tokens(llama_sem_pred, gold)
            rouge_full = rouge_l_f1(llama_full_pred, gold)
            rouge_sem = rouge_l_f1(llama_sem_pred, gold)
            _, _, f1_full = precision_recall_f1_tokens(llama_full_pred, gold)
            _, _, f1_sem = precision_recall_f1_tokens(llama_sem_pred, gold)
            bleu_full = bleu4(llama_full_pred, gold)
            bleu_sem = bleu4(llama_sem_pred, gold)

            # LLMetric = (ROUGE-L + Token F1 + Jaro-Winkler) / 3
            llmetric_full = (rouge_full + f1_full + jw_full) / 3.0
            llmetric_sem = (rouge_sem + f1_sem + jw_sem) / 3.0

            rows.append({
                "question": question,
                "gold": gold,
                "category": category,
                "hops": hops,
                # predictions
                "llama_full": llama_full_pred,
                "llama_semantic": llama_sem_pred,
                # KG validity
                "llama_full_kg_valid": 1 if full_kg_ok else 0,
                "llama_sem_kg_valid": 1 if sem_kg_ok else 0,
                # outputs
                "llama_full_pass": full_pass,
                "llama_sem_pass": sem_pass,
                "llama_full_out_jacc": full_out_jacc,
                "llama_sem_out_jacc": sem_out_jacc,
                # cypher metrics
                "llama_full_jw": jw_full,
                "llama_sem_jw": jw_sem,
                "llama_full_jacc": jac_full,
                "llama_sem_jacc": jac_sem,
                "llama_full_rougeL": rouge_full,
                "llama_sem_rougeL": rouge_sem,
                "llama_full_bleu": bleu_full,
                "llama_sem_bleu": bleu_sem,
                "llama_full_f1": f1_full,
                "llama_sem_f1": f1_sem,
                "llama_full_llmetric": llmetric_full,
                "llama_sem_llmetric": llmetric_sem,
            })
            seen += 1
            if limit and seen >= limit:
                break

    elapsed_time = time.time() - start_time
    
    print(f"\n✅ Evaluation complete!")
    print(f"   Total queries evaluated: {len(rows)}")
    print(f"   Total time: {elapsed_time:.1f} seconds")
    print(f"   Average time per query: {elapsed_time/len(rows):.2f} seconds")

    # Aggregations per pipeline
    def avg(key: str) -> float:
        return sum(r[key] for r in rows) / len(rows) if rows else 0.0

    # KG Valid Query Rate
    full_kg_valid = avg("llama_full_kg_valid") * 100
    sem_kg_valid = avg("llama_sem_kg_valid") * 100

    # Pass@1 (exact output match)
    full_pass1 = avg("llama_full_pass") * 100
    sem_pass1 = avg("llama_sem_pass") * 100

    # Output Jaccard (average)
    full_out_jacc_avg = avg("llama_full_out_jacc") * 100
    sem_out_jacc_avg = avg("llama_sem_out_jacc") * 100

    # Cypher metrics (averages)
    full_jw = avg("llama_full_jw") * 100
    sem_jw = avg("llama_sem_jw") * 100
    full_jacc = avg("llama_full_jacc") * 100
    sem_jacc = avg("llama_sem_jacc") * 100
    full_rouge = avg("llama_full_rougeL") * 100
    sem_rouge = avg("llama_sem_rougeL") * 100
    full_bleu = avg("llama_full_bleu") * 100
    sem_bleu = avg("llama_sem_bleu") * 100
    full_f1 = avg("llama_full_f1") * 100
    sem_f1 = avg("llama_sem_f1") * 100

    # LLMetric
    full_llmetric = avg("llama_full_llmetric") * 100
    sem_llmetric = avg("llama_sem_llmetric") * 100

    # Per-category aggregation
    from collections import defaultdict
    category_rows = defaultdict(list)
    for r in rows:
        category_rows[r["category"]].append(r)
    
    # Helper to compute metrics for a subset of rows
    def compute_metrics(subset: List[Dict]) -> Dict:
        if not subset:
            return {}
        n = len(subset)
        
        def avg_cat(key: str) -> float:
            return sum(r[key] for r in subset) / n
        
        full_kg = avg_cat("llama_full_kg_valid") * 100
        sem_kg = avg_cat("llama_sem_kg_valid") * 100
        full_p1 = avg_cat("llama_full_pass") * 100
        sem_p1 = avg_cat("llama_sem_pass") * 100
        full_oj = avg_cat("llama_full_out_jacc") * 100
        sem_oj = avg_cat("llama_sem_out_jacc") * 100
        full_llm = avg_cat("llama_full_llmetric") * 100
        sem_llm = avg_cat("llama_sem_llmetric") * 100
        
        return {
            "count": n,
            "full_kg": full_kg,
            "sem_kg": sem_kg,
            "full_pass1": full_p1,
            "sem_pass1": sem_p1,
            "full_out_jacc": full_oj,
            "sem_out_jacc": sem_oj,
            "full_llmetric": full_llm,
            "sem_llmetric": sem_llm,
            "full_jw": avg_cat("llama_full_jw") * 100,
            "sem_jw": avg_cat("llama_sem_jw") * 100,
            "full_jacc": avg_cat("llama_full_jacc") * 100,
            "sem_jacc": avg_cat("llama_sem_jacc") * 100,
            "full_rouge": avg_cat("llama_full_rougeL") * 100,
            "sem_rouge": avg_cat("llama_sem_rougeL") * 100,
            "full_bleu": avg_cat("llama_full_bleu") * 100,
            "sem_bleu": avg_cat("llama_sem_bleu") * 100,
            "full_f1": avg_cat("llama_full_f1") * 100,
            "sem_f1": avg_cat("llama_sem_f1") * 100,
        }

    # Save detailed results to CSV
    RESULTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_CSV.open("w", newline="") as csvfile:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n📄 Detailed results saved to: {RESULTS_CSV}")

    # Generate markdown report
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_MD.open("w") as md:
        md.write("# Text-to-Cypher Evaluation - Second Technical Dataset\n\n")
        md.write("## Llama3: Full Schema vs T2CSS Semantic Schema (with MPS GPU)\n\n")
        md.write(f"**Dataset**: `{CSV_PATH.name}`\n\n")
        md.write(f"**Total Queries**: {len(rows)}\n\n")
        md.write(f"**Evaluation Time**: {elapsed_time:.1f} seconds ({elapsed_time/len(rows):.2f}s per query)\n\n")
        md.write(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        md.write(f"**GPU Acceleration**: MPS (Metal Performance Shaders) on macOS\n\n")

        md.write("---\n\n")
        md.write("## Evaluation Methodology\n\n")
        md.write("1. **Generation**: Raw LLM output (no validation)\n")
        md.write("2. **Validation**: Non-execution validation using:\n")
        md.write("   - Syntax check via `EXPLAIN`\n")
        md.write("   - Schema validation (labels & relationship types)\n")
        md.write("   - Property existence checks\n")
        md.write("3. **Execution**: Only valid queries are executed\n")
        md.write("4. **Metrics**: Text similarity + execution results\n\n")
        md.write("**KG Valid Rate** = % of queries that pass validation (syntax + schema)\n\n")
        md.write("**Pass@1** = % of queries that produce exact match with gold standard\n\n")
        md.write("**LLMetric** = 0.3×Pass@1 + 0.4×KG_Valid + 0.2×Output_Jaccard + 0.1×Text_Similarity\n\n")
        
        md.write("---\n\n")
        md.write("## Overall Aggregated Metrics\n\n")
        md.write("| Pipeline | Pass@1 | KG Valid Rate | Output Jaccard | LLMetric |\n")
        md.write("|----------|-------:|-------------:|---------------:|---------:|\n")
        md.write(f"| **Full Schema** | {full_pass1:.1f}% | {full_kg_valid:.1f}% | {full_out_jacc_avg:.1f}% | {full_llmetric:.1f}% |\n")
        md.write(f"| **T2CSS Semantic** | {sem_pass1:.1f}% | {sem_kg_valid:.1f}% | {sem_out_jacc_avg:.1f}% | {sem_llmetric:.1f}% |\n\n")

        # Determine winner
        winner = "**Full Schema**" if full_llmetric > sem_llmetric else "**T2CSS Semantic**"
        margin = abs(full_llmetric - sem_llmetric)
        md.write(f"**Overall Winner**: {winner} (margin: {margin:.1f}%)\n\n")

        md.write("---\n\n")
        md.write("## Cypher Text Similarity Metrics\n\n")
        md.write("| Pipeline | Jaro-Winkler | Token Jaccard | ROUGE-L | Token F1 | BLEU-4 |\n")
        md.write("|----------|-------------:|--------------:|--------:|---------:|-------:|\n")
        md.write(f"| **Full Schema** | {full_jw:.1f}% | {full_jacc:.1f}% | {full_rouge:.1f}% | {full_f1:.1f}% | {full_bleu:.1f}% |\n")
        md.write(f"| **T2CSS Semantic** | {sem_jw:.1f}% | {sem_jacc:.1f}% | {sem_rouge:.1f}% | {sem_f1:.1f}% | {sem_bleu:.1f}% |\n\n")

        # Per-category breakdown
        md.write("---\n\n")
        md.write("## Performance by Question Category\n\n")
        
        # Sort categories for consistent reporting
        sorted_categories = sorted(category_rows.keys())
        
        # Summary table
        md.write("| Category | Count | Full Pass@1 | Sem Pass@1 | Full KG Valid | Sem KG Valid | Full LLMetric | Sem LLMetric | Winner |\n")
        md.write("|----------|------:|------------:|-----------:|--------------:|-------------:|--------------:|-------------:|--------|\n")
        
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            winner = "Full" if cat_metrics['full_llmetric'] > cat_metrics['sem_llmetric'] else "Semantic"
            md.write(f"| {cat} | {cat_metrics['count']} | {cat_metrics['full_pass1']:.1f}% | {cat_metrics['sem_pass1']:.1f}% | ")
            md.write(f"{cat_metrics['full_kg']:.1f}% | {cat_metrics['sem_kg']:.1f}% | ")
            md.write(f"{cat_metrics['full_llmetric']:.1f}% | {cat_metrics['sem_llmetric']:.1f}% | **{winner}** |\n")
        
        md.write("\n")
        
        # Detailed per-category breakdown
        md.write("---\n\n")
        md.write("## Detailed Category Analysis\n\n")
        
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            
            md.write(f"### {cat}\n\n")
            md.write(f"**Sample Size**: {cat_metrics['count']} queries\n\n")
            
            md.write("**Key Metrics:**\n\n")
            md.write("| Pipeline | Pass@1 | KG Valid | Output Jaccard | LLMetric |\n")
            md.write("|----------|-------:|---------:|---------------:|---------:|\n")
            md.write(f"| Full Schema | {cat_metrics['full_pass1']:.1f}% | {cat_metrics['full_kg']:.1f}% | {cat_metrics['full_out_jacc']:.1f}% | {cat_metrics['full_llmetric']:.1f}% |\n")
            md.write(f"| T2CSS Semantic | {cat_metrics['sem_pass1']:.1f}% | {cat_metrics['sem_kg']:.1f}% | {cat_metrics['sem_out_jacc']:.1f}% | {cat_metrics['sem_llmetric']:.1f}% |\n\n")
            
            md.write("**Text Similarity:**\n\n")
            md.write("| Pipeline | Jaro-Winkler | Token Jaccard | ROUGE-L | Token F1 | BLEU-4 |\n")
            md.write("|----------|-------------:|--------------:|--------:|---------:|-------:|\n")
            md.write(f"| Full Schema | {cat_metrics['full_jw']:.1f}% | {cat_metrics['full_jacc']:.1f}% | {cat_metrics['full_rouge']:.1f}% | {cat_metrics['full_f1']:.1f}% | {cat_metrics['full_bleu']:.1f}% |\n")
            md.write(f"| T2CSS Semantic | {cat_metrics['sem_jw']:.1f}% | {cat_metrics['sem_jacc']:.1f}% | {cat_metrics['sem_rouge']:.1f}% | {cat_metrics['sem_f1']:.1f}% | {cat_metrics['sem_bleu']:.1f}% |\n\n")
        
        # Key insights
        md.write("---\n\n")
        md.write("## Key Insights\n\n")
        
        md.write("### Winner by Category (based on LLMetric)\n\n")
        full_wins = 0
        sem_wins = 0
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            if cat_metrics['full_llmetric'] > cat_metrics['sem_llmetric']:
                winner = "**Full Schema**"
                full_wins += 1
            else:
                winner = "**T2CSS Semantic**"
                sem_wins += 1
            diff = abs(cat_metrics['full_llmetric'] - cat_metrics['sem_llmetric'])
            md.write(f"- **{cat}**: {winner} wins by {diff:.1f}%\n")
        
        md.write(f"\n**Category Win Summary**: Full Schema: {full_wins} | T2CSS Semantic: {sem_wins}\n\n")
        
        md.write("### Performance Observations\n\n")
        md.write(f"1. **Pass@1 Rate**: ")
        if full_pass1 > sem_pass1:
            md.write(f"Full Schema achieves {full_pass1 - sem_pass1:.1f}% higher exact match rate\n")
        else:
            md.write(f"T2CSS Semantic achieves {sem_pass1 - full_pass1:.1f}% higher exact match rate\n")
        
        md.write(f"2. **KG Valid Rate**: ")
        if full_kg_valid > sem_kg_valid:
            md.write(f"Full Schema generates {full_kg_valid - sem_kg_valid:.1f}% more executable queries\n")
        else:
            md.write(f"T2CSS Semantic generates {sem_kg_valid - full_kg_valid:.1f}% more executable queries\n")
        
        md.write(f"3. **Output Similarity**: ")
        if full_out_jacc_avg > sem_out_jacc_avg:
            md.write(f"Full Schema produces {full_out_jacc_avg - sem_out_jacc_avg:.1f}% more similar results\n")
        else:
            md.write(f"T2CSS Semantic produces {sem_out_jacc_avg - full_out_jacc_avg:.1f}% more similar results\n")
        
        md.write("\n")

    print(f"📊 Markdown report saved to: {REPORT_MD}")
    print("\n" + "="*80)
    print("EVALUATION COMPLETE!")
    print("="*80)

if __name__ == "__main__":
    main()

