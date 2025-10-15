import os
import re
import csv
from pathlib import Path
from typing import List

from neo4j import GraphDatabase
import random
import json
import hashlib

REPO_ROOT = Path(__file__).resolve().parents[2]
# Paths where we expect raw cypher files
CYPHER_DIRS = [REPO_ROOT / "text2cypher" / "backend"]
TEST_DIRS = [REPO_ROOT / "text2cypher" / "backend"]

OUTPUT_CSV = REPO_ROOT / "evaluation" / "eval_dataset_template.csv"
COMPLEX_CSV = REPO_ROOT / "evaluation" / "complex_eval_dataset.csv"

DESIRED_COUNT = 400  # aim for larger dataset

COMPLEX_SAMPLING_LIMIT = 200

PROP_VALUE_LIMIT = 3

# Allowed cybersecurity labels and relationships
ALLOWED_LABELS = {
    "UcoCVE", "UcoVulnerability", "UcoexCPE", "UcoCWE", "UcoexCAPEC",
    "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS",
    "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS", "UcoexObservedExample"
}
ALLOWED_RELS = {
    "UCOHASWEAKNESS", "UCOHASCVE_ID", "UCOHASVULNERABILITY", "UCOEXHASCPE",
    "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE", "UCOEXCAMPAIGNUSESTECHNIQUE",
    "UCOEXSOFTWAREUSESTECHNIQUE", "UCOEXMITIGATES", "UCOEXGROUPUSESSOFTWARE",
    "UCOEXCAMPAIGNUSESSOFTWARE", "UCOEXATTRIBUTEDTO", "UCOEXHASRELATEDWEAKNESS",
    "UCOEXHASTAXONOMYMAPPING", "UCOHASOBSERVEDEXAMPLE"
}

# helper to check labels in query
import re
LABEL_PATTERN = re.compile(r"`?([A-Za-z][A-Za-z0-9_]*)`?")

def query_has_only_allowed_labels(query: str) -> bool:
    labels = LABEL_PATTERN.findall(query)
    return all(lbl in ALLOWED_LABELS for lbl in labels)

def extract_from_cypher_file(path: Path) -> List[str]:
    """Return list of Cypher queries separated by blank lines or comment lines"""
    queries: List[str] = []
    current: List[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            # comment delimiter – treat as separator
            if current:
                queries.append("\n".join(current).strip())
                current = []
            continue
        if not stripped:
            # blank line as separator
            if current:
                queries.append("\n".join(current).strip())
                current = []
            continue
        current.append(line.rstrip())
    if current:
        queries.append("\n".join(current).strip())
    return [q for q in queries if q]

def extract_from_test_file(path: Path) -> List[str]:
    """Pull Cypher strings that appear in test_*.py"""
    queries: List[str] = []
    pattern = re.compile(r"\"([A-Z].*?)(?:\"\"|\")", re.DOTALL)
    text = path.read_text()
    for match in re.finditer(r"return\s+\"([^\"]+)\"", text):
        cypher = match.group(1)
        # crude filter: assume queries start with MATCH/CREATE/CALL/etc.
        if cypher.strip().upper().startswith(("MATCH", "CALL", "CREATE", "RETURN")):
            queries.append(cypher.strip())
    return queries

def normalize_query(q: str) -> str:
    # remove varying LIMIT clauses and compress whitespace
    q_no_limit = re.sub(r"LIMIT\s+\d+", "LIMIT", q, flags=re.IGNORECASE)
    return " ".join(q_no_limit.split()).strip().lower()

def validate_query(driver, query: str) -> bool:
    try:
        with driver.session() as session:
            session.run(query).consume()
        return True
    except Exception as exc:
        print(f"Validation error for query: {query}\n  {exc}")
        return False

def get_labels(driver):
    with driver.session() as session:
        result = session.run("CALL db.labels() YIELD label RETURN label")
        return [record["label"] for record in result if record["label"] in ALLOWED_LABELS]

def get_relationship_types(driver):
    with driver.session() as session:
        result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
        return [record["relationshipType"] for record in result if record["relationshipType"] in ALLOWED_RELS]

def get_sample_properties(driver, label):
    with driver.session() as session:
        record = session.run(f"MATCH (n:`{label}`) RETURN keys(n) AS props LIMIT 1").single()
        return record["props"] if record else []

def sample_property_values(driver, label, prop):
    if 'embedding' in prop.lower():
        return []
    with driver.session() as session:
        result = session.run(
            f"MATCH (n:`{label}`) WHERE n.`{prop}` IS NOT NULL RETURN DISTINCT n.`{prop}` AS val LIMIT {PROP_VALUE_LIMIT}"
        )
        return [record["val"] for record in result]

def generate_schema_queries(driver):
    generated = []  # (question, query)
    labels = get_labels(driver)
    rel_types = get_relationship_types(driver)
    random.shuffle(labels)

    # Node-based queries
    for lbl in labels:
        # list nodes
        q = f"MATCH (n:`{lbl}`) RETURN n LIMIT 10"
        generated.append((f"List some {lbl} nodes", q))
        # count nodes
        q = f"MATCH (n:`{lbl}`) RETURN count(n) AS count"
        generated.append((f"How many {lbl} nodes are in the graph?", q))

        # property existence queries
        props = get_sample_properties(driver, lbl)
        for prop in props[:2]:  # limit to 2 props per label
            q = f"MATCH (n:`{lbl}`) WHERE n.`{prop}` IS NOT NULL RETURN n.`{prop}` LIMIT 10"
            generated.append((f"Show the {prop} values for {lbl} nodes", q))

            # Equality filters with real values
            values = sample_property_values(driver, lbl, prop)
            for val in values:
                safe_val = str(val)
                val_literal = json.dumps(safe_val)
                q_eq = f"MATCH (n:`{lbl}`) WHERE n.`{prop}` = {val_literal} RETURN n LIMIT 10"
                generated.append((f"List {lbl} nodes where {prop} = {val}", q_eq))

    # Relationship queries
    for rel in rel_types:
        record = driver.session().run(f"MATCH (a)-[r:`{rel}`]->(b) RETURN labels(a)[0] AS aLbl, labels(b)[0] AS bLbl LIMIT 1").single()
        if not record:
            continue
        a_lbl, b_lbl = record["aLbl"], record["bLbl"]
        q = f"MATCH (a:`{a_lbl}`)-[:`{rel}`]->(b:`{b_lbl}`) RETURN a, b LIMIT 10"
        generated.append((f"Find {a_lbl} nodes that {rel} {b_lbl} nodes", q))
    return generated

def generate_complex_queries(driver):
    pairs = []
    # Multi-hop traversals
    record = driver.session().run(
        f"MATCH (a)-[r1]->()-[r2]->(c) RETURN type(r1) AS r1, type(r2) AS r2, labels(a)[0] AS aLbl, labels(c)[0] AS cLbl, count(*) AS cnt ORDER BY cnt DESC LIMIT {COMPLEX_SAMPLING_LIMIT}"
    )
    for rec in record:
        if rec['aLbl'] not in ALLOWED_LABELS or rec['cLbl'] not in ALLOWED_LABELS:
            continue
        q = f"MATCH (a:`{rec['aLbl']}`)-[:`{rec['r1']}`]->()-[:`{rec['r2']}`]->(c:`{rec['cLbl']}`) RETURN a, c LIMIT 10"
        pairs.append((f"Find {rec['aLbl']} that {rec['r1']} something that {rec['r2']} {rec['cLbl']}", q))

    # Property filter + relationship
    rel_records = driver.session().run(
        f"MATCH (a)-[r]->(b) RETURN DISTINCT type(r) AS rel, labels(a)[0] AS aLbl, labels(b)[0] AS bLbl LIMIT {COMPLEX_SAMPLING_LIMIT}"
    )
    # after rel_records fetch
    rel_records = list(rel_records)
    rel_records = [rec for rec in rel_records if rec['rel'] in ALLOWED_RELS and rec['aLbl'] in ALLOWED_LABELS and rec['bLbl'] in ALLOWED_LABELS]
    for rec in rel_records:
        props = [p for p in get_sample_properties(driver, rec['aLbl']) if 'embedding' not in p.lower()]
        if not props:
            continue
        prop = props[0]
        values = sample_property_values(driver, rec['aLbl'], prop)
        if not values:
            continue
        for val in values:
            val_str = json.dumps(val)
            q = f"MATCH (a:`{rec['aLbl']}`)-[:`{rec['rel']}`]->(b:`{rec['bLbl']}`) WHERE a.`{prop}` = {val_str} RETURN a, b LIMIT 10"
            pairs.append((f"Find {rec['aLbl']} where {prop} is {val} that {rec['rel']} {rec['bLbl']}", q))

    # Order-by top N within relationship
    for rec in rel_records:
        props = get_sample_properties(driver, rec['aLbl'])
        numeric_prop = None
        for p in props:
            if p.lower().endswith('score') or p.lower().endswith('count') and 'embedding' not in p.lower():
                numeric_prop = p
                break
        if not numeric_prop and props:
            numeric_prop = props[0]
        if not numeric_prop:
            continue
        q = (
            f"MATCH (a:`{rec['aLbl']}`)-[:`{rec['rel']}`]->(b:`{rec['bLbl']}`) "
            f"WHERE a.`{numeric_prop}` IS NOT NULL RETURN a, b ORDER BY a.`{numeric_prop}` DESC LIMIT 5"
        )
        pairs.append((f"Top {rec['aLbl']} by {numeric_prop} that {rec['rel']} {rec['bLbl']}", q))

    # OPTIONAL MATCH / pattern existence
    labels = get_labels(driver)
    if len(labels) >= 2:
        a_lbl, b_lbl = labels[0], labels[1]
        q = (
            f"MATCH (a:`{a_lbl}`) OPTIONAL MATCH (a)-->(b:`{b_lbl}`) "
            f"RETURN a, b LIMIT 10"
        )
        pairs.append((f"Show {a_lbl} and optionally connected {b_lbl}", q))
    return pairs

def make_question_from_query(cypher: str) -> str:
    cypher_upper = cypher.upper()
    if "COUNT(" in cypher_upper:
        return "How many nodes match this pattern?"
    m = re.search(r"MATCH \(.*?:`?(\w+)`?\)", cypher, re.IGNORECASE)
    if m:
        lbl = m.group(1)
        return f"List some {lbl} nodes"
    return f"Run query: {cypher[:40]}..."

def main():
    neo4j_url = os.environ.get("NEO4J_URL", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_pass = os.environ.get("NEO4J_PASSWORD", "abcd90909090")

    driver = GraphDatabase.driver(neo4j_url, auth=(neo4j_user, neo4j_pass))

    all_queries: List[str] = []
    all_pairs = []  # list of (question, cypher)

    for d in CYPHER_DIRS:
        for f in d.glob("*.cypher"):
            all_queries.extend(extract_from_cypher_file(f))

    for d in TEST_DIRS:
        for f in d.glob("test_*.py"):
            all_queries.extend(extract_from_test_file(f))

    print(f"Found {len(all_queries)} raw queries before validation")

    valid_pairs = []
    seen = set()
    for q in all_queries:
        if validate_query(driver, q) and query_has_only_allowed_labels(q):
            norm = normalize_query(q)
            if norm in seen:
                continue
            seen.add(norm)
            valid_pairs.append(q)
            all_pairs.append((make_question_from_query(q), q))

    print(f"{len(valid_pairs)} queries passed validation; writing to {OUTPUT_CSV}")

    # After validating existing queries
    if len(valid_pairs) < DESIRED_COUNT:
        schema_pairs = generate_schema_queries(driver)
        for question, cypher in schema_pairs:
            if len(valid_pairs) >= DESIRED_COUNT:
                break
            norm = normalize_query(cypher)
            if norm in seen:
                continue
            seen.add(norm)
            if validate_query(driver, cypher):
                valid_pairs.append(cypher)
                all_pairs.append((question, cypher))

    # After schema_pairs generation
    if len(valid_pairs) < DESIRED_COUNT:
        complex_pairs = generate_complex_queries(driver)
        complex_pairs_saved = []
        for question, cypher in complex_pairs:
            if len(valid_pairs) >= DESIRED_COUNT:
                break
            norm = normalize_query(cypher)
            if norm in seen:
                continue
            if validate_query(driver, cypher):
                seen.add(norm)
                valid_pairs.append(cypher)
                all_pairs.append((question, cypher))
                complex_pairs_saved.append((question, cypher))

    # write primary dataset
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["nl_question", "cypher_query"])
        for pair in all_pairs:
            writer.writerow(pair)

    # write complex dataset
    COMPLEX_CSV.parent.mkdir(parents=True, exist_ok=True)
    with COMPLEX_CSV.open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["nl_question", "cypher_query"])
        for pair in complex_pairs_saved:
            writer.writerow(pair)

    print(f"Primary dataset: {OUTPUT_CSV} (rows: {len(all_pairs)})")
    print(f"Complex dataset: {COMPLEX_CSV} (rows: {len(complex_pairs_saved)})")

if __name__ == "__main__":
    main()