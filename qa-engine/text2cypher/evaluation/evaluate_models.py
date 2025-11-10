import csv
import os
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
from neo4j import GraphDatabase

import sys, pathlib
BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.text2cypher import Text2Cypher
from core.t2css_integration import create_enhanced_text2cypher
from validation.noexec_validator import validate_cypher_noexec
from llm.ollama_llm import OllamaLLM

# Use the attached technical dataset (COMPLETION)
CSV_PATH = BACKEND_DIR / "dataset" / "technical_dataset_COMPLETION.csv"
REPORT_MD = BACKEND_DIR / "evaluation" / "report_llama3_full_vs_semantic.md"

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "abcd90909090"

llama_llm = OllamaLLM(model="llama3:instruct")
llama_full = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASS, llama_llm)
llama_semantic = create_enhanced_text2cypher(
    NEO4J_URI, NEO4J_USER, NEO4J_PASS, llama_llm, use_t2css=True, top_k_schema=10
)

# build concise schema string (labels + relationship types)
LABELS = [
    "UcoCVE", "UcoVulnerability", "UcoexCPE", "UcoCWE", "UcoexCAPEC",
    "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS",
    "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS", "UcoexObservedExample",
]
RELS = [
    "UCOHASWEAKNESS", "UCOHASCVE_ID", "UCOHASVULNERABILITY", "UCOEXHASCPE",
    "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE", "UCOEXCAMPAIGNUSESTECHNIQUE",
    "UCOEXSOFTWAREUSESTECHNIQUE", "UCOEXMITIGATES", "UCOEXGROUPUSESSOFTWARE",
    "UCOEXCAMPAIGNUSESSOFTWARE", "UCOEXATTRIBUTEDTO", "UCOEXHASRELATEDWEAKNESS",
    "UCOEXHASTAXONOMYMAPPING", "UCOHASOBSERVEDEXAMPLE",
]
SCHEMA_STR = " ".join([f"(:{l})" for l in LABELS] + [f"-[:{r}]->" for r in RELS])

# Helper functions for dynamic properties
import re
############################
# Text similarity metrics
############################

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

def first_label(cypher: str) -> Optional[str]:
    m = re.search(r":`?([A-Za-z0-9_]+)`?", cypher)
    return m.group(1) if m else None

def props_for(label: str, driver) -> str:
    try:
        with driver.session() as sess:
            rec = sess.run(f"MATCH (n:`{label}`) RETURN keys(n) AS k LIMIT 1").single()
            props = rec["k"] if rec else []
            return ", ".join(props[:60])
    except Exception:
        return ""

PROPS = {
    "UcoCVE": ["ucobaseSeverity", "ucoexploitabilityScore", "ucouserInteractionRequired", "ucovulnStatus"],
    "UcoCWE": ["ucocweID", "ucocweName", "ucostatus"],
    "UcoexCAPEC": ["ucoexCAPEC_id", "ucoexSeverity", "ucoexNAME"],
    "UcoexCPE": ["cpeName"],
    "UcoexGROUPS": ["ucoexNAME"],
    "UcoexMITREATTACK": ["ucoexNAME"],
}

PROPS_STR = "\n".join(f"{lbl}: {', '.join(props)}" for lbl, props in PROPS.items())


def validate_cypher(driver, query: str) -> bool:
    # Non-executing validation first (guard -> EXPLAIN -> schema/property checks)
    ok, _errors = validate_cypher_noexec(driver, query)
    if not ok:
        return False
    # Optionally still attempt to run the query for strictness
    try:
        with driver.session() as sess:
            sess.run(query).consume()
        return True
    except Exception:
        return False

# helper to catch generation errors
def safe_generate(t2c: Text2Cypher, question: str) -> str:
    """
    Generate Cypher query WITHOUT validation.
    This allows us to measure raw LLM quality via KG Valid Query Rate.
    """
    try:
        return t2c.text_to_cypher(question, skip_validation=True)
    except Exception as _:
        return ""

############################
# Output execution helpers
############################

def run_and_fetch_set(driver, query: str, timeout_seconds: int = 30) -> Optional[set]:
    """Execute query with timeout protection"""
    import signal
    
    def timeout_handler(signum, frame):
        raise TimeoutError("Query execution exceeded timeout")
    
    try:
        # Set alarm for timeout (Unix only)
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)
        
        with driver.session() as sess:
            result = sess.run(query)
            rows = []
            for rec in result:
                data = rec.data()
                items = tuple(sorted((k, str(v)) for k, v in data.items()))
                rows.append(items)
                if len(rows) > 10000:  # Prevent memory issues
                    break
            
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(0)  # Cancel alarm
            
            return set(rows)
    except (Exception, TimeoutError) as e:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)  # Cancel alarm
        print(f"Query execution failed or timed out: {str(e)[:100]}")
        return None


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
    with CSV_PATH.open() as f:
        reader = csv.DictReader(f)
        for row in tqdm(reader, desc="Evaluating (Llama3 Full vs Semantic)"):
            # Adapt to attached dataset columns
            question = row.get("NaturalLanguageQuestion") or row.get("nl_question")
            gold     = (row.get("CypherQuery") or row.get("cypher_query") or "").strip()
            category = row.get("Category", "Unknown")

            # Generate with both pipelines
            llama_full_pred = safe_generate(llama_full, question)
            llama_sem_pred = safe_generate(llama_semantic, question)

            # KG validity (syntax + schema/property) using non-exec validator only
            full_kg_ok, _ = validate_cypher_noexec(driver, llama_full_pred)
            sem_kg_ok, _ = validate_cypher_noexec(driver, llama_sem_pred)

            # Execute outputs and compute Pass@1 and Jaccard output
            gold_set = run_and_fetch_set(driver, gold)
            full_set = run_and_fetch_set(driver, llama_full_pred)
            sem_set = run_and_fetch_set(driver, llama_sem_pred)

            full_pass = 1 if (full_set is not None and gold_set is not None and full_set == gold_set) else 0
            sem_pass = 1 if (sem_set is not None and gold_set is not None and sem_set == gold_set) else 0

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

            jarou_full = (rouge_full + f1_full + jw_full) / 3.0
            jarou_sem = (rouge_sem + f1_sem + jw_sem) / 3.0

            rows.append({
                "question": question,
                "gold": gold,
                "category": category,
                # predictions
                "llama_full": llama_full_pred,
                "llama_semantic": llama_sem_pred,
                # KG validity (no-exec)
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
                "llama_full_jarou": jarou_full,
                "llama_sem_jarou": jarou_sem,
            })
            seen += 1
            if limit and seen >= limit:
                break

    def relaxed_norm(q:str)->str:
        import re
        q=re.sub(r"LIMIT \d+","LIMIT",q,flags=re.I)
        return "".join(q.lower().split())

    # Aggregations per pipeline
    def avg(key: str) -> float:
        return sum(r[key] for r in rows) / len(rows) if rows else 0.0

    # KG Valid Query Rate (schema + syntax, no exec)
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

    # JaRou Factor (avg of ROUGE-L, token F1, Jaro-Winkler)
    full_jarou = avg("llama_full_jarou") * 100
    sem_jarou = avg("llama_sem_jarou") * 100

    # LLMetric = 0.3*Pass@1 + 0.4*KG_Valid + 0.2*JaccardOutput + 0.1*JaRou
    def llmetric(pass1, kg, jacc_out, jarou):
        return 0.3 * pass1 + 0.4 * kg + 0.2 * jacc_out + 0.1 * jarou

    full_llmetric = llmetric(full_pass1, full_kg_valid, full_out_jacc_avg, full_jarou)
    sem_llmetric = llmetric(sem_pass1, sem_kg_valid, sem_out_jacc_avg, sem_jarou)

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
        full_jr = avg_cat("llama_full_jarou") * 100
        sem_jr = avg_cat("llama_sem_jarou") * 100
        
        full_llm = llmetric(full_p1, full_kg, full_oj, full_jr)
        sem_llm = llmetric(sem_p1, sem_kg, sem_oj, sem_jr)
        
        return {
            "count": n,
            "full_kg": full_kg,
            "sem_kg": sem_kg,
            "full_pass1": full_p1,
            "sem_pass1": sem_p1,
            "full_out_jacc": full_oj,
            "sem_out_jacc": sem_oj,
            "full_jarou": full_jr,
            "sem_jarou": sem_jr,
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
        }

    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_MD.open("w") as md:
        md.write("# Text-to-Cypher Evaluation (Llama3: Full Schema vs Semantic Schema)\n\n")
        md.write(f"Dataset size: **{len(rows)}** questions\n\n")
        md.write(f"Evaluation date: 2025-10-26\n\n")

        md.write("## Overall Aggregated Metrics\n\n")
        md.write("| Pipeline | Pass@1 | KG Valid Rate | Output Jaccard (avg) | JaRou Factor | LLMetric |\n|---|---:|---:|---:|---:|---:|\n")
        md.write(f"| Llama3 Full Schema | {full_pass1:.1f}% | {full_kg_valid:.1f}% | {full_out_jacc_avg:.1f}% | {full_jarou:.1f}% | {full_llmetric:.1f} |\n")
        md.write(f"| Llama3 Semantic Schema | {sem_pass1:.1f}% | {sem_kg_valid:.1f}% | {sem_out_jacc_avg:.1f}% | {sem_jarou:.1f}% | {sem_llmetric:.1f} |\n\n")

        md.write("## Overall Cypher Text Similarity (averages)\n\n")
        md.write("| Pipeline | Jaro-Winkler | Jaccard (tokens) | ROUGE-L (F1) | BLEU-4 |\n|---|---:|---:|---:|---:|\n")
        md.write(f"| Llama3 Full Schema | {full_jw:.1f}% | {full_jacc:.1f}% | {full_rouge:.1f}% | {full_bleu:.1f}% |\n")
        md.write(f"| Llama3 Semantic Schema | {sem_jw:.1f}% | {sem_jacc:.1f}% | {sem_rouge:.1f}% | {sem_bleu:.1f}% |\n\n")

        # Per-category breakdown
        md.write("---\n\n")
        md.write("## Performance by Question Category\n\n")
        
        # Sort categories for consistent reporting
        sorted_categories = sorted(category_rows.keys())
        
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            
            md.write(f"### {cat} (n={cat_metrics['count']})\n\n")
            
            md.write("**Key Metrics:**\n\n")
            md.write("| Pipeline | Pass@1 | KG Valid Rate | Output Jaccard | JaRou Factor | LLMetric |\n|---|---:|---:|---:|---:|---:|\n")
            md.write(f"| Full Schema | {cat_metrics['full_pass1']:.1f}% | {cat_metrics['full_kg']:.1f}% | {cat_metrics['full_out_jacc']:.1f}% | {cat_metrics['full_jarou']:.1f}% | {cat_metrics['full_llmetric']:.1f} |\n")
            md.write(f"| Semantic Schema | {cat_metrics['sem_pass1']:.1f}% | {cat_metrics['sem_kg']:.1f}% | {cat_metrics['sem_out_jacc']:.1f}% | {cat_metrics['sem_jarou']:.1f}% | {cat_metrics['sem_llmetric']:.1f} |\n\n")
            
            md.write("**Cypher Text Similarity:**\n\n")
            md.write("| Pipeline | Jaro-Winkler | Jaccard (tokens) | ROUGE-L | BLEU-4 |\n|---|---:|---:|---:|---:|\n")
            md.write(f"| Full Schema | {cat_metrics['full_jw']:.1f}% | {cat_metrics['full_jacc']:.1f}% | {cat_metrics['full_rouge']:.1f}% | {cat_metrics['full_bleu']:.1f}% |\n")
            md.write(f"| Semantic Schema | {cat_metrics['sem_jw']:.1f}% | {cat_metrics['sem_jacc']:.1f}% | {cat_metrics['sem_rouge']:.1f}% | {cat_metrics['sem_bleu']:.1f}% |\n\n")
        
        # Summary table across categories
        md.write("---\n\n")
        md.write("## Category Comparison Summary\n\n")
        md.write("| Category | Count | Full Pass@1 | Sem Pass@1 | Full KG Valid | Sem KG Valid | Full LLMetric | Sem LLMetric |\n")
        md.write("|---|---:|---:|---:|---:|---:|---:|---:|\n")
        
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            md.write(f"| {cat} | {cat_metrics['count']} | {cat_metrics['full_pass1']:.1f}% | {cat_metrics['sem_pass1']:.1f}% | ")
            md.write(f"{cat_metrics['full_kg']:.1f}% | {cat_metrics['sem_kg']:.1f}% | ")
            md.write(f"{cat_metrics['full_llmetric']:.1f} | {cat_metrics['sem_llmetric']:.1f} |\n")
        
        md.write("\n")
        
        # Insights section
        md.write("---\n\n")
        md.write("## Key Insights\n\n")
        md.write("### Winner by Category (based on LLMetric)\n\n")
        for cat in sorted_categories:
            cat_metrics = compute_metrics(category_rows[cat])
            if not cat_metrics:
                continue
            winner = "**Full Schema**" if cat_metrics['full_llmetric'] > cat_metrics['sem_llmetric'] else "**Semantic Schema**"
            diff = abs(cat_metrics['full_llmetric'] - cat_metrics['sem_llmetric'])
            md.write(f"- **{cat}**: {winner} (margin: {diff:.1f})\n")
        
        md.write("\n")

    print(f"Finished. Report written to {REPORT_MD}")

if __name__ == "__main__":
    main()