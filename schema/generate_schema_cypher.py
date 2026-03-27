"""
generate_schema_cypher.py
=========================
Generates a fully self-contained, static Cypher script from
semantic_schema_uckg_v3.json. The output file has zero runtime
dependencies — no Python, no APOC — and can be executed:

  • In Neo4j Browser  (paste and run)
  • Via cypher-shell:
        cypher-shell -u neo4j -p abcd90909090 \\
            --file neo4j/import/uckg_semantic_schema.cypher
  • As a Docker init file (see METHOD D below)

Usage
-----
    python core/generate_schema_cypher.py [--schema PATH] [--out PATH]

Defaults:
    --schema  configt2c/semantic_schema_uckg_v3.json
    --out     neo4j/import/uckg_semantic_schema.cypher
              (placed directly in the Neo4j import mount so it is
               accessible to cypher-shell inside the container)
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

# ─── defaults ────────────────────────────────────────────────────────────────
REPO_ROOT      = Path(__file__).resolve().parent.parent       # UCKG/
SCHEMA_DEFAULT = Path(__file__).resolve().parent / "semantic_schema_uckg_v3.json"
OUT_DEFAULT    = REPO_ROOT / "neo4j" / "import" / "uckg_semantic_schema.cypher"


# ─── helpers ──────────────────────────────────────────────────────────────────

def esc(value) -> str:
    """Escape a value for embedding in a Cypher string literal."""
    if value is None:
        return ""
    s = str(value)
    return s.replace("\\", "\\\\").replace("'", "\\'")


def cypher_list(items) -> str:
    """Render a Python list as a Cypher list literal of strings."""
    if not items:
        return "[]"
    escaped = [f"'{esc(i)}'" for i in items]
    return "[" + ", ".join(escaped) + "]"


# ─── generator ────────────────────────────────────────────────────────────────

def generate(schema: dict) -> str:
    lines: list[str] = []
    version = schema.get("version", "v3")
    ts      = datetime.utcnow().isoformat()

    def w(s: str = "") -> None:
        lines.append(s)

    # ── header ────────────────────────────────────────────────────────────────
    w("// ═══════════════════════════════════════════════════════════════════════════")
    w(f"// UCKG Semantic Schema — static Cypher bootstrap  (generated {ts})")
    w(f"// Source : configt2c/semantic_schema_uckg_v3.json  version={version}")
    w("// Run in Neo4j Browser, cypher-shell, or as Docker init script.")
    w("// ═══════════════════════════════════════════════════════════════════════════")
    w()

    # ── 1. schema singleton ───────────────────────────────────────────────────
    w("// ── 1. UCKGMeta_Schema singleton ─────────────────────────────────────────")
    notes      = esc(schema.get("notes", ""))
    corpus_len = len(schema.get("embedding_corpus", []))
    w(f"MERGE (s:UCKGMeta_Schema {{version: '{version}'}}) "
      f"SET s.notes = '{notes}', "
      f"s.embedding_corpus_size = {corpus_len}, "
      f"s.last_loaded = '{ts}';")
    w()

    # ── 2. node types ─────────────────────────────────────────────────────────
    w("// ── 2. UCKGMeta_Node — one per entity type ────────────────────────────────")
    for nd in schema.get("nodes", []):
        sem     = esc(nd.get("semantic", ""))
        phys    = esc(nd.get("physical_label", ""))
        purpose = esc(nd.get("purpose", ""))
        desc    = esc(nd.get("description", ""))
        key_id  = esc(nd.get("key_identifier", ""))
        key_ex  = esc(nd.get("key_identifier_example", ""))
        triggers = cypher_list(nd.get("typical_natural_language_triggers", []))

        w(f"MERGE (n:UCKGMeta_Node {{semantic: '{sem}'}}) "
          f"SET n.physical_label = '{phys}', "
          f"n.purpose = '{purpose}', "
          f"n.description = '{desc}', "
          f"n.key_identifier = '{key_id}', "
          f"n.key_identifier_example = '{key_ex}', "
          f"n.triggers = {triggers};")
        # link to schema singleton
        w(f"MATCH (s:UCKGMeta_Schema {{version: '{version}'}}), "
          f"(n:UCKGMeta_Node {{semantic: '{sem}'}}) "
          f"MERGE (s)-[:META_HAS_NODE]->(n);")
        w()

    # ── 3. properties ─────────────────────────────────────────────────────────
    w("// ── 3. UCKGMeta_Property — one per property per entity type ───────────────")
    for nd in schema.get("nodes", []):
        node_sem = esc(nd.get("semantic", ""))
        for prop in nd.get("properties", []):
            p_sem  = esc(prop.get("semantic", ""))
            p_phys = esc(prop.get("physical", ""))
            p_type = esc(prop.get("type", ""))
            p_desc = esc(prop.get("description", ""))
            p_ex   = esc(prop.get("example", ""))
            p_qp   = esc(prop.get("query_pattern", ""))

            w(f"MERGE (p:UCKGMeta_Property {{semantic: '{p_sem}', belongs_to: '{node_sem}'}}) "
              f"SET p.physical = '{p_phys}', "
              f"p.type = '{p_type}', "
              f"p.description = '{p_desc}', "
              f"p.example = '{p_ex}', "
              f"p.query_pattern = '{p_qp}';")
            w(f"MATCH (n:UCKGMeta_Node {{semantic: '{node_sem}'}}), "
              f"(p:UCKGMeta_Property {{semantic: '{p_sem}', belongs_to: '{node_sem}'}}) "
              f"MERGE (n)-[:META_HAS_PROPERTY]->(p);")
        w()

    # ── 4. relationship triples ────────────────────────────────────────────────
    w("// ── 4. UCKGMeta_Relationship + META_CONNECTS_TO edges ────────────────────")
    for rel in schema.get("relationships", []):
        sem    = esc(rel.get("semantic", ""))
        phys   = esc(rel.get("physical_rel", ""))
        d_sem  = esc(rel.get("domain_semantic", ""))
        d_phys = esc(rel.get("domain_physical", ""))
        r_sem  = esc(rel.get("range_semantic", ""))
        r_phys = esc(rel.get("range_physical", ""))
        desc   = esc(rel.get("description", ""))
        trav   = esc(rel.get("traversal_direction", ""))
        cpat   = esc(rel.get("cypher_pattern", ""))
        trigs  = cypher_list(rel.get("natural_language_triggers", []))
        ex_q   = esc(rel.get("example_query", ""))

        w(f"MERGE (r:UCKGMeta_Relationship {{semantic: '{sem}'}}) "
          f"SET r.physical_rel = '{phys}', "
          f"r.domain_semantic = '{d_sem}', "
          f"r.domain_physical = '{d_phys}', "
          f"r.range_semantic = '{r_sem}', "
          f"r.range_physical = '{r_phys}', "
          f"r.description = '{desc}', "
          f"r.traversal_direction = '{trav}', "
          f"r.cypher_pattern = '{cpat}', "
          f"r.triggers = {trigs}, "
          f"r.example_query = '{ex_q}';")
        # link to schema node
        w(f"MATCH (s:UCKGMeta_Schema {{version: '{version}'}}), "
          f"(r:UCKGMeta_Relationship {{semantic: '{sem}'}}) "
          f"MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);")
        # META_CONNECTS_TO between UCKGMeta_Node nodes
        if d_sem and r_sem:
            w(f"MATCH (src:UCKGMeta_Node {{semantic: '{d_sem}'}}), "
              f"(tgt:UCKGMeta_Node {{semantic: '{r_sem}'}}) "
              f"MERGE (src)-[e:META_CONNECTS_TO {{via_semantic: '{sem}'}}]->(tgt) "
              f"SET e.via_physical = '{phys}', "
              f"e.description = '{desc}', "
              f"e.cypher_pattern = '{cpat}';")
        w()

    # ── 5. traversal paths ─────────────────────────────────────────────────────
    w("// ── 5. UCKGMeta_TraversalPath — documented multi-hop paths ───────────────")
    for path in schema.get("graph_traversal_paths", []):
        name    = esc(path.get("name", ""))
        p_desc  = esc(path.get("description", ""))
        p_cpat  = esc(path.get("cypher_pattern", ""))
        p_cases = cypher_list(path.get("use_cases", []))

        w(f"MERGE (tp:UCKGMeta_TraversalPath {{name: '{name}'}}) "
          f"SET tp.description = '{p_desc}', "
          f"tp.cypher_pattern = '{p_cpat}', "
          f"tp.use_cases = {p_cases};")
        w(f"MATCH (s:UCKGMeta_Schema {{version: '{version}'}}), "
          f"(tp:UCKGMeta_TraversalPath {{name: '{name}'}}) "
          f"MERGE (s)-[:META_HAS_PATH]->(tp);")
        w()

    # ── footer ────────────────────────────────────────────────────────────────
    w("// ── Verification query ────────────────────────────────────────────────────")
    w("MATCH (n:UCKGMeta_Node)")
    w("OPTIONAL MATCH (n)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)")
    w("RETURN n.semantic AS node, n.physical_label AS label,")
    w("       count(p) AS properties")
    w("ORDER BY n.semantic;")
    w()

    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate a static .cypher bootstrap file from semantic_schema_uckg_v3.json"
    )
    p.add_argument("--schema", type=Path, default=SCHEMA_DEFAULT,
                   help=f"Path to v3 JSON (default: {SCHEMA_DEFAULT})")
    p.add_argument("--out",    type=Path, default=OUT_DEFAULT,
                   help=f"Output .cypher path (default: {OUT_DEFAULT})")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.schema.exists():
        print(f"ERROR: schema not found: {args.schema}")
        raise SystemExit(1)

    print(f"📂  Reading schema from : {args.schema}")
    with open(args.schema, "r", encoding="utf-8") as f:
        schema = json.load(f)

    cypher_text = generate(schema)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(cypher_text)

    lines  = cypher_text.count("\n")
    merges = cypher_text.count("MERGE")
    print(f"✅  Written to          : {args.out}")
    print(f"    Lines               : {lines}")
    print(f"    MERGE statements    : {merges}")
    print()
    print("Run with cypher-shell (local):")
    print(f"  cypher-shell -u neo4j -p abcd90909090 --file {args.out}")
    print()
    print("Run inside the Docker container:")
    print("  docker compose exec neo4j cypher-shell -u neo4j -p abcd90909090 \\")
    print(f"    --file /var/lib/neo4j/import/uckg_semantic_schema.cypher")


if __name__ == "__main__":
    main()
