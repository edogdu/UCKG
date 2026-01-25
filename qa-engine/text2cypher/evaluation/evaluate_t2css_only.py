"""
Enhanced T2CSS Pipeline Evaluation (T2CSS ONLY)

This script evaluates ONLY the Enhanced T2CSS pipeline on the technical dataset.
Use this if you already have Full Schema results and want to compare with T2CSS results.

Metrics computed:
- Pass@1 (exact match)
- KG Valid Rate (schema adherence)
- Output Jaccard (result similarity)
- Cypher text similarity (Jaro-Winkler, Token Jaccard, ROUGE-L, Token F1, BLEU-4)
- JaRou Factor (composite similarity metric)
- LLMetric (weighted composite: 0.3*Pass@1 + 0.4*KG_Valid + 0.2*OutputJaccard + 0.1*JaRou)

Uses MPS GPU acceleration for faster evaluation.
"""

import csv
import os
import math
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
from neo4j import GraphDatabase

import sys
# Add parent directory and core directory to path
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))
sys.path.insert(0, str(parent_dir / "core"))
sys.path.insert(0, str(parent_dir / "llm"))
sys.path.insert(0, str(parent_dir / "validation"))

from t2css_enhanced import EnhancedT2CSSPipeline
from ollama_llm import OllamaLLM
from noexec_validator import validate_cypher_noexec

# ========== CONFIGURATION ==========

# Dataset path - UPDATE THIS if using a different dataset
CSV_PATH = Path(__file__).resolve().parent.parent / "dataset" / "technical_dataset_COMPLETION_clean.csv"

# Output path - results will be saved here
OUTPUT_CSV = Path(__file__).resolve().parent / "results_t2css_enhanced.csv"
REPORT_MD = Path(__file__).resolve().parent / "report_t2css_enhanced.md"

# Neo4j connection
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "abcd90909090"

# Model configuration
MODEL_NAME = "llama3.1:70b"  # Ollama model to use
TOP_K_SCHEMA = 10  # Number of schema elements to retrieve
FEWSHOT_K = 5  # Number of few-shot examples

# Query timeout (seconds)
QUERY_TIMEOUT = 30

# Schema for validation
LABELS = [
    "UcoCVE", "UcoVulnerability", "UcoexCPE", "UcoCWE", "UcoexCAPEC",
    "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS",
    "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS", "UcoexObservedExample",
    "UcoExploitTarget"
]
RELS = [
    "UCOHASWEAKNESS", "UCOHASCVE_ID", "UCOHASVULNERABILITY", "UCOEXHASCPE",
    "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE", "UCOEXCAMPAIGNUSESTECHNIQUE",
    "UCOEXSOFTWAREUSESTECHNIQUE", "UCOEXMITIGATES", "UCOEXGROUPUSESSOFTWARE",
    "UCOEXCAMPAIGNUSESSOFTWARE", "UCOEXATTRIBUTEDTO", "UCOEXHASRELATEDWEAKNESS",
    "UCOEXHASTAXONOMYMAPPING", "UCOHASOBSERVEDEXAMPLE",
]
SCHEMA_STR = " ".join([f"(:{l})" for l in LABELS] + [f"-[:{r}]->" for r in RELS])

# ========== TEXT SIMILARITY METRICS ==========

import re

def tokenize(s: str) -> List[str]:
    """Tokenize string into alphanumeric tokens"""
    return [t for t in re.split(r"[^A-Za-z0-9_]+", s.lower()) if t]


def jaro_winkler(s1: str, s2: str, scaling: float = 0.1) -> float:
    """Compute Jaro-Winkler similarity"""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    
    # Jaro similarity
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
    
    # Winkler modification
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4]):
        if c1 == c2:
            prefix += 1
        else:
            break
    
    return jaro + prefix * scaling * (1 - jaro)


def jaccard_tokens(a: str, b: str) -> float:
    """Token-based Jaccard similarity"""
    ta, tb = set(tokenize(a)), set(tokenize(b))
    if not ta and not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def lcs_len(a_tokens: List[str], b_tokens: List[str]) -> int:
    """Longest common subsequence length"""
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
    """ROUGE-L F1 score"""
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
    """Token-based precision, recall, F1"""
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
    """Simplified BLEU-4 score"""
    ref_tokens = tokenize(reference)
    cand_tokens = tokenize(candidate)
    
    if not ref_tokens or not cand_tokens:
        return 0.0
    
    # Brevity penalty
    bp = 1.0 if len(cand_tokens) >= len(ref_tokens) else math.exp(1 - len(ref_tokens) / len(cand_tokens))
    
    # n-gram precisions (1 to 4)
    precisions = []
    for n in range(1, 5):
        if len(cand_tokens) < n:
            precisions.append(0.0)
            continue
        
        ref_ngrams = [tuple(ref_tokens[i:i+n]) for i in range(len(ref_tokens) - n + 1)]
        cand_ngrams = [tuple(cand_tokens[i:i+n]) for i in range(len(cand_tokens) - n + 1)]
        
        ref_counts = {}
        for ng in ref_ngrams:
            ref_counts[ng] = ref_counts.get(ng, 0) + 1
        
        matches = 0
        for ng in cand_ngrams:
            if ng in ref_counts and ref_counts[ng] > 0:
                matches += 1
                ref_counts[ng] -= 1
        
        precisions.append(matches / len(cand_ngrams) if cand_ngrams else 0.0)
    
    # Geometric mean
    if all(p > 0 for p in precisions):
        geo_mean = math.exp(sum(math.log(p) for p in precisions) / 4)
        return bp * geo_mean
    else:
        return 0.0


# ========== NEO4J EXECUTION WITH TIMEOUT ==========

def execute_cypher_with_timeout(driver, cypher: str, timeout: int = QUERY_TIMEOUT) -> Tuple[Optional[List], Optional[str]]:
    """Execute Cypher query with timeout"""
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
    """Compute Jaccard similarity between two result sets"""
    if r1 is None or r2 is None:
        return 0.0
    
    def normalize_result(records):
        normalized = []
        for record in records:
            sorted_items = tuple(sorted((k, str(v)) for k, v in record.items()))
            normalized.append(sorted_items)
        return set(normalized)
    
    set1 = normalize_result(r1)
    set2 = normalize_result(r2)
    
    if not set1 and not set2:
        return 1.0
    
    inter = len(set1 & set2)
    union = len(set1 | set2)
    return inter / union if union else 0.0


# ========== MAIN EVALUATION PIPELINE ==========

def evaluate_t2css():
    """Evaluate Enhanced T2CSS pipeline on the dataset"""
    
    print("="*80)
    print("ENHANCED T2CSS PIPELINE EVALUATION (T2CSS ONLY)")
    print("="*80)
    print(f"\nDataset: {CSV_PATH}")
    print(f"Model: {MODEL_NAME}")
    print(f"Top-K Schema: {TOP_K_SCHEMA}")
    print(f"Few-Shot K: {FEWSHOT_K}")
    print(f"Query Timeout: {QUERY_TIMEOUT}s")
    print(f"\nOutput CSV: {OUTPUT_CSV}")
    print(f"Output Report: {REPORT_MD}")
    print("="*80)
    
    # Load dataset
    if not CSV_PATH.exists():
        print(f"\n❌ Error: Dataset not found at {CSV_PATH}")
        return
    
    with CSV_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        dataset = list(reader)
    
    print(f"\n✅ Loaded {len(dataset)} questions from dataset")
    
    # Initialize Neo4j driver
    print(f"\n🔌 Connecting to Neo4j at {NEO4J_URI}...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    
    # Initialize Enhanced T2CSS pipeline
    print(f"\n🚀 Initializing Enhanced T2CSS Pipeline...")
    llm = OllamaLLM(model=MODEL_NAME)
    pipeline = EnhancedT2CSSPipeline(
        top_k=TOP_K_SCHEMA,
        fewshot_k=FEWSHOT_K,
        auto_load_fewshot=True
    )
    print(f"✅ Pipeline initialized")
    print(f"✅ Few-shot store loaded with {len(pipeline.fewshot_store.examples) if pipeline.fewshot_store else 0} examples")
    
    # Evaluate each question
    print(f"\n📊 Starting evaluation...\n")
    
    results = []
    
    for i, row in enumerate(tqdm(dataset, desc="Evaluating")):
        nl_question = row.get("NaturalLanguageQuestion", "")
        gold_cypher = row.get("CypherQuery", "")
        category = row.get("Category", "Unknown")
        
        # Generate Cypher with T2CSS
        try:
            generated_cypher = pipeline.generate_cypher(nl_question, llm=llm)
        except Exception as e:
            generated_cypher = ""
            print(f"\n⚠️ Error generating Cypher for question {i+1}: {e}")
        
        # Validate generated Cypher
        kg_valid = 0
        if generated_cypher:
            is_valid, errors = validate_cypher_noexec(driver, generated_cypher)
            kg_valid = 1 if is_valid else 0
        
        # Execute both queries
        gold_results, gold_error = execute_cypher_with_timeout(driver, gold_cypher)
        gen_results, gen_error = execute_cypher_with_timeout(driver, generated_cypher) if generated_cypher else (None, "No query generated")
        
        # Pass@1: exact match of results
        pass_at_1 = 1 if (gold_results is not None and gen_results is not None and gold_results == gen_results) else 0
        
        # Output Jaccard
        output_jaccard = results_jaccard(gold_results, gen_results)
        
        # Cypher text similarity
        jw = jaro_winkler(gold_cypher, generated_cypher)
        jacc = jaccard_tokens(gold_cypher, generated_cypher)
        rouge = rouge_l_f1(gold_cypher, generated_cypher)
        _, _, f1_tok = precision_recall_f1_tokens(gold_cypher, generated_cypher)
        bleu = bleu_4(gold_cypher, generated_cypher)
        
        # JaRou Factor: average of ROUGE-L, token F1, and Jaro-Winkler
        jarou = (rouge + f1_tok + jw) / 3
        
        # Store results
        results.append({
            "question": nl_question,
            "category": category,
            "gold_cypher": gold_cypher,
            "generated_cypher": generated_cypher,
            "kg_valid": kg_valid,
            "pass_at_1": pass_at_1,
            "output_jaccard": output_jaccard,
            "jaro_winkler": jw,
            "token_jaccard": jacc,
            "rouge_l": rouge,
            "token_f1": f1_tok,
            "bleu_4": bleu,
            "jarou_factor": jarou,
            "gold_error": gold_error if gold_error else "",
            "gen_error": gen_error if gen_error else ""
        })
    
    driver.close()
    
    # Save detailed results to CSV
    print(f"\n💾 Saving detailed results to {OUTPUT_CSV}...")
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "question", "category", "gold_cypher", "generated_cypher",
            "kg_valid", "pass_at_1", "output_jaccard",
            "jaro_winkler", "token_jaccard", "rouge_l", "token_f1", "bleu_4", "jarou_factor",
            "gold_error", "gen_error"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"✅ Detailed results saved")
    
    # Compute aggregate metrics
    print(f"\n📈 Computing aggregate metrics...\n")
    
    n = len(results)
    
    def avg(key: str) -> float:
        return sum(r[key] for r in results) / n if n > 0 else 0.0
    
    overall_pass1 = avg("pass_at_1") * 100
    overall_kg_valid = avg("kg_valid") * 100
    overall_output_jacc = avg("output_jaccard") * 100
    overall_jw = avg("jaro_winkler") * 100
    overall_jacc = avg("token_jaccard") * 100
    overall_rouge = avg("rouge_l") * 100
    overall_f1 = avg("token_f1") * 100
    overall_bleu = avg("bleu_4") * 100
    overall_jarou = avg("jarou_factor") * 100
    
    # LLMetric = 0.3*Pass@1 + 0.4*KG_Valid + 0.2*OutputJaccard + 0.1*JaRou
    overall_llmetric = 0.3 * overall_pass1 + 0.4 * overall_kg_valid + 0.2 * overall_output_jacc + 0.1 * overall_jarou
    
    # Per-category metrics
    from collections import defaultdict
    category_results = defaultdict(list)
    for r in results:
        category_results[r["category"]].append(r)
    
    def compute_category_metrics(cat_results: List[Dict]) -> Dict:
        n_cat = len(cat_results)
        if n_cat == 0:
            return {}
        
        def avg_cat(key: str) -> float:
            return sum(r[key] for r in cat_results) / n_cat
        
        cat_pass1 = avg_cat("pass_at_1") * 100
        cat_kg = avg_cat("kg_valid") * 100
        cat_out_jacc = avg_cat("output_jaccard") * 100
        cat_jarou = avg_cat("jarou_factor") * 100
        cat_llmetric = 0.3 * cat_pass1 + 0.4 * cat_kg + 0.2 * cat_out_jacc + 0.1 * cat_jarou
        
        return {
            "count": n_cat,
            "pass1": cat_pass1,
            "kg_valid": cat_kg,
            "output_jaccard": cat_out_jacc,
            "jw": avg_cat("jaro_winkler") * 100,
            "jacc": avg_cat("token_jaccard") * 100,
            "rouge": avg_cat("rouge_l") * 100,
            "f1": avg_cat("token_f1") * 100,
            "bleu": avg_cat("bleu_4") * 100,
            "jarou": cat_jarou,
            "llmetric": cat_llmetric
        }
    
    # Generate markdown report
    print(f"📝 Generating markdown report...\n")
    
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    
    with REPORT_MD.open("w", encoding="utf-8") as md:
        md.write("# Enhanced T2CSS Pipeline Evaluation Report\n\n")
        md.write(f"**Dataset**: `{CSV_PATH.name}`\n\n")
        md.write(f"**Total Questions**: {n}\n\n")
        md.write(f"**Model**: {MODEL_NAME}\n\n")
        md.write(f"**Configuration**:\n")
        md.write(f"- Top-K Schema Elements: {TOP_K_SCHEMA}\n")
        md.write(f"- Few-Shot Examples: {FEWSHOT_K}\n")
        md.write(f"- Query Timeout: {QUERY_TIMEOUT}s\n\n")
        md.write("---\n\n")
        
        md.write("## Overall Metrics\n\n")
        md.write("### Key Performance Indicators\n\n")
        md.write("| Metric | Score |\n")
        md.write("|--------|-------|\n")
        md.write(f"| **Pass@1** (exact match) | {overall_pass1:.1f}% |\n")
        md.write(f"| **KG Valid Rate** (schema adherence) | {overall_kg_valid:.1f}% |\n")
        md.write(f"| **Output Jaccard** (result similarity) | {overall_output_jacc:.1f}% |\n")
        md.write(f"| **JaRou Factor** (composite text similarity) | {overall_jarou:.1f}% |\n")
        md.write(f"| **LLMetric** (composite score) | {overall_llmetric:.1f} |\n\n")
        
        md.write("### Cypher Text Similarity\n\n")
        md.write("| Metric | Score |\n")
        md.write("|--------|-------|\n")
        md.write(f"| Jaro-Winkler | {overall_jw:.1f}% |\n")
        md.write(f"| Token Jaccard | {overall_jacc:.1f}% |\n")
        md.write(f"| ROUGE-L (F1) | {overall_rouge:.1f}% |\n")
        md.write(f"| Token F1 | {overall_f1:.1f}% |\n")
        md.write(f"| BLEU-4 | {overall_bleu:.1f}% |\n\n")
        
        md.write("---\n\n")
        md.write("## Performance by Category\n\n")
        
        sorted_categories = sorted(category_results.keys())
        
        for cat in sorted_categories:
            cat_metrics = compute_category_metrics(category_results[cat])
            if not cat_metrics:
                continue
            
            md.write(f"### {cat} (n={cat_metrics['count']})\n\n")
            
            md.write("**Key Metrics:**\n\n")
            md.write("| Metric | Score |\n")
            md.write("|--------|-------|\n")
            md.write(f"| Pass@1 | {cat_metrics['pass1']:.1f}% |\n")
            md.write(f"| KG Valid Rate | {cat_metrics['kg_valid']:.1f}% |\n")
            md.write(f"| Output Jaccard | {cat_metrics['output_jaccard']:.1f}% |\n")
            md.write(f"| JaRou Factor | {cat_metrics['jarou']:.1f}% |\n")
            md.write(f"| LLMetric | {cat_metrics['llmetric']:.1f} |\n\n")
            
            md.write("**Cypher Text Similarity:**\n\n")
            md.write("| Metric | Score |\n")
            md.write("|--------|-------|\n")
            md.write(f"| Jaro-Winkler | {cat_metrics['jw']:.1f}% |\n")
            md.write(f"| Token Jaccard | {cat_metrics['jacc']:.1f}% |\n")
            md.write(f"| ROUGE-L | {cat_metrics['rouge']:.1f}% |\n")
            md.write(f"| Token F1 | {cat_metrics['f1']:.1f}% |\n")
            md.write(f"| BLEU-4 | {cat_metrics['bleu']:.1f}% |\n\n")
        
        md.write("---\n\n")
        md.write("## Category Summary Table\n\n")
        md.write("| Category | Count | Pass@1 | KG Valid | Output Jaccard | LLMetric |\n")
        md.write("|----------|-------|--------|----------|----------------|----------|\n")
        
        for cat in sorted_categories:
            cat_metrics = compute_category_metrics(category_results[cat])
            if not cat_metrics:
                continue
            md.write(f"| {cat} | {cat_metrics['count']} | {cat_metrics['pass1']:.1f}% | ")
            md.write(f"{cat_metrics['kg_valid']:.1f}% | {cat_metrics['output_jaccard']:.1f}% | ")
            md.write(f"{cat_metrics['llmetric']:.1f} |\n")
        
        md.write("\n---\n\n")
        md.write("## Methodology\n\n")
        md.write("**LLMetric Formula**:\n")
        md.write("```\n")
        md.write("LLMetric = 0.3 × Pass@1 + 0.4 × KG_Valid + 0.2 × OutputJaccard + 0.1 × JaRou\n")
        md.write("```\n\n")
        md.write("**JaRou Factor**:\n")
        md.write("```\n")
        md.write("JaRou = (ROUGE-L + Token_F1 + Jaro-Winkler) / 3\n")
        md.write("```\n\n")
        md.write("**Pass@1**: Exact match between generated and gold query results\n\n")
        md.write("**KG Valid Rate**: Percentage of queries that pass schema validation\n\n")
        md.write("**Output Jaccard**: Jaccard similarity between result sets\n\n")
        
        md.write("---\n\n")
        md.write(f"*Report generated: {Path(__file__).name}*\n")
    
    print(f"✅ Report saved to {REPORT_MD}")
    
    # Print summary to console
    print("\n" + "="*80)
    print("EVALUATION COMPLETE")
    print("="*80)
    print(f"\n📊 Overall Results:")
    print(f"   Pass@1:          {overall_pass1:.1f}%")
    print(f"   KG Valid Rate:   {overall_kg_valid:.1f}%")
    print(f"   Output Jaccard:  {overall_output_jacc:.1f}%")
    print(f"   JaRou Factor:    {overall_jarou:.1f}%")
    print(f"   LLMetric:        {overall_llmetric:.1f}")
    print(f"\n📁 Files saved:")
    print(f"   {OUTPUT_CSV}")
    print(f"   {REPORT_MD}")
    print("="*80)


if __name__ == "__main__":
    evaluate_t2css()

