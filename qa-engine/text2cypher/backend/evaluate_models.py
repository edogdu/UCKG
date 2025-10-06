import csv
from pathlib import Path
from typing import Dict, List, Optional
from tqdm import tqdm
from neo4j import GraphDatabase

import sys, pathlib
BACKEND_DIR = pathlib.Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from text2cypher import Text2Cypher
from gemma_llm import GemmaLLM
from ollama_llm import OllamaLLM

CSV_PATH = Path("evaluation/eval_dataset_template.csv")
REPORT_MD = Path("evaluation/report.md")

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "abcd90909090"

# prepare Gemma model separately for zero-shot

llama_t2c = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASS, OllamaLLM(model="llama3:instruct"))

# Gemma zero-shot helpers
from gemma_mps import load_model, generate, PROMPT_TEMPLATE
gem_tok, gem_model = load_model()

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
    try:
        with driver.session() as sess:
            sess.run(query).consume()
        return True
    except Exception:
        return False

# helper to catch generation errors
def safe_generate(t2c: Text2Cypher, question: str) -> str:
    try:
        return t2c.text_to_cypher(question)
    except Exception as _:
        return ""

def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {CSV_PATH}")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


    rows: List[Dict] = []
    with CSV_PATH.open() as f:
        reader = csv.DictReader(f)
        for row in tqdm(reader, desc="Evaluating"):
            question = row["nl_question"]
            gold     = row["cypher_query"].strip()

            # zero-shot Gemma generation
            # Dynamic property list
            main_label = first_label(gold) or "UcoCVE"
            props_line = f"{main_label}: {props_for(main_label, driver)}"

            PROMPT_FULL = PROMPT_TEMPLATE + "\nSchema: " + SCHEMA_STR + "\nProperties:\n" + props_line + "\nQuestion: {question}\nCypher output:"

            try:
                gemma_pred = generate(gem_tok, gem_model, question, schema=SCHEMA_STR)
            except Exception:
                gemma_pred = ""

            llama_pred = safe_generate(llama_t2c, question)

            gemma_valid = validate_cypher(driver, gemma_pred)
            llama_valid = validate_cypher(driver, llama_pred)

            rows.append({
                "question": question,
                "gold": gold,
                "gemma": gemma_pred,
                "gemma_exact": gemma_pred.strip() == gold,
                "gemma_valid": gemma_valid,
                "llama": llama_pred,
                "llama_exact": llama_pred.strip() == gold,
                "llama_valid": llama_valid,
            })

    def relaxed_norm(q:str)->str:
        import re
        q=re.sub(r"LIMIT \d+","LIMIT",q,flags=re.I)
        return "".join(q.lower().split())

    gemma_exact = sum(r["gemma_exact"] for r in rows) / len(rows) * 100
    llama_exact = sum(r["llama_exact"] for r in rows) / len(rows) * 100

    gemma_relaxed = sum(relaxed_norm(r["gemma"])==relaxed_norm(r["gold"]) for r in rows)/len(rows)*100
    llama_relaxed = sum(relaxed_norm(r["llama"])==relaxed_norm(r["gold"]) for r in rows)/len(rows)*100

    gemma_valid = sum(r["gemma_valid"] for r in rows) / len(rows) * 100
    llama_valid = sum(r["llama_valid"] for r in rows) / len(rows) * 100

    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_MD.open("w") as md:
        md.write("# Text-to-Cypher Evaluation\n\n")
        md.write(f"Dataset size: **{len(rows)}** questions\n\n")
        md.write("| Model | Exact | Relaxed | Valid Cypher |\n|---|---|---|---|\n")
        md.write(f"| Gemma-2-9B | {gemma_exact:.1f}% | {gemma_relaxed:.1f}% | {gemma_valid:.1f}% |\n")
        md.write(f"| Llama (Ollama) | {llama_exact:.1f}% | {llama_relaxed:.1f}% | {llama_valid:.1f}% |\n")

    print(f"Finished. Report written to {REPORT_MD}")

if __name__ == "__main__":
    main()