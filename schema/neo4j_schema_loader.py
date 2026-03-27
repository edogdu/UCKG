"""
neo4j_schema_loader.py
======================
Loads the UCKG semantic schema (v3 JSON) into Neo4j as a queryable metadata
sub-graph.  Running this script once (or re-running to refresh) creates/updates
the following node types inside your Neo4j database:

    UCKGMeta_Schema          – singleton version node
    UCKGMeta_Node            – one node per KG entity type (e.g. CVE, Group)
    UCKGMeta_Property        – one node per property of each entity type
    UCKGMeta_Relationship    – one node per directed relationship triple
    UCKGMeta_TraversalPath   – one node per documented multi-hop path

And the following meta-relationships between them:

    (UCKGMeta_Schema) -[:META_HAS_NODE]->         (UCKGMeta_Node)
    (UCKGMeta_Schema) -[:META_HAS_RELATIONSHIP]-> (UCKGMeta_Relationship)
    (UCKGMeta_Schema) -[:META_HAS_PATH]->         (UCKGMeta_TraversalPath)
    (UCKGMeta_Node)   -[:META_HAS_PROPERTY]->     (UCKGMeta_Property)
    (UCKGMeta_Node)   -[:META_CONNECTS_TO]->      (UCKGMeta_Node)
                        { via_semantic, via_physical, description, cypher_pattern }

Usage
-----
    python core/neo4j_schema_loader.py [--schema PATH] [--uri URI] [--user U] [--password P]

Defaults:
    --schema   qa-engine/text2cypher/configt2c/semantic_schema_uckg_v3.json
    --uri      bolt://localhost:7687
    --user     neo4j
    --password abcd90909090

After loading you can explore the schema inside Neo4j Browser with:

    MATCH (s:UCKGMeta_Schema) RETURN s
    MATCH (n:UCKGMeta_Node)   RETURN n
    MATCH (n:UCKGMeta_Node)-[r:META_CONNECTS_TO]->(m:UCKGMeta_Node) RETURN n,r,m
    MATCH (n:UCKGMeta_Node)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property) RETURN n,p LIMIT 30
    MATCH (tp:UCKGMeta_TraversalPath) RETURN tp
"""

import json
import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    from neo4j import GraphDatabase
except ImportError:
    print("ERROR: neo4j driver not installed.  Run:  pip install neo4j")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "configt2c"
    / "semantic_schema_uckg_v3.json"
)
DEFAULT_URI      = "bolt://localhost:7687"
DEFAULT_USER     = "neo4j"
DEFAULT_PASSWORD = "abcd90909090"


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

class UCKGSchemaLoader:
    """Reads the v3 semantic schema JSON and writes it to Neo4j as metadata."""

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    # ── public entry point ────────────────────────────────────────────────────

    def load(self, schema: dict) -> None:
        version    = schema.get("version", "v3")
        notes      = schema.get("notes", "")
        nodes      = schema.get("nodes", [])
        rels       = schema.get("relationships", [])
        paths      = schema.get("graph_traversal_paths", [])
        corpus     = schema.get("embedding_corpus", [])

        with self.driver.session() as session:
            print("  ▸ Creating UCKGMeta_Schema node …")
            schema_id = session.execute_write(
                self._upsert_schema_node, version, notes, corpus
            )

            print(f"  ▸ Loading {len(nodes)} node types …")
            node_id_map: dict[str, str] = {}          # semantic → element_id
            for nd in nodes:
                eid = session.execute_write(self._upsert_meta_node, nd, schema_id)
                node_id_map[nd["semantic"]] = eid
                # properties
                for prop in nd.get("properties", []):
                    session.execute_write(
                        self._upsert_meta_property, prop, nd["semantic"], eid
                    )

            print(f"  ▸ Loading {len(rels)} relationship types …")
            for rel in rels:
                session.execute_write(
                    self._upsert_meta_relationship, rel,
                    node_id_map, schema_id
                )

            print(f"  ▸ Loading {len(paths)} traversal paths …")
            for path in paths:
                session.execute_write(
                    self._upsert_meta_path, path, schema_id
                )

        print(f"\n✅  Schema '{version}' loaded into Neo4j.")
        print(     "    Browse with:  MATCH (n:UCKGMeta_Node) RETURN n")

    # ── writers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _upsert_schema_node(tx, version: str, notes: str, corpus: list) -> str:
        result = tx.run(
            """
            MERGE (s:UCKGMeta_Schema {version: $version})
            SET   s.notes          = $notes,
                  s.embedding_corpus_size = $corpus_size,
                  s.last_loaded    = $ts
            RETURN elementId(s) AS eid
            """,
            version=version,
            notes=notes,
            corpus_size=len(corpus),
            ts=datetime.utcnow().isoformat()
        )
        return result.single()["eid"]

    @staticmethod
    def _upsert_meta_node(tx, nd: dict, schema_eid: str) -> str:
        result = tx.run(
            """
            MERGE (n:UCKGMeta_Node {semantic: $semantic})
            SET   n.physical_label = $physical_label,
                  n.purpose        = $purpose,
                  n.description    = $description,
                  n.key_identifier = $key_id,
                  n.key_identifier_example = $key_ex,
                  n.triggers       = $triggers
            WITH  n
            MATCH (s:UCKGMeta_Schema {version: $schema_version})
            MERGE (s)-[:META_HAS_NODE]->(n)
            RETURN elementId(n) AS eid
            """,
            semantic        = nd["semantic"],
            physical_label  = nd.get("physical_label", ""),
            purpose         = nd.get("purpose", ""),
            description     = nd.get("description", ""),
            key_id          = nd.get("key_identifier", ""),
            key_ex          = nd.get("key_identifier_example", ""),
            triggers        = nd.get("typical_natural_language_triggers", []),
            schema_version  = "v3"    # tie back to the schema node
        )
        return result.single()["eid"]

    @staticmethod
    def _upsert_meta_property(tx, prop: dict, node_semantic: str,
                               node_eid: str) -> None:
        # Use a composite key: semantic + belongs_to_node
        tx.run(
            """
            MERGE (p:UCKGMeta_Property {semantic: $sem, belongs_to: $belongs_to})
            SET   p.physical      = $physical,
                  p.type          = $type,
                  p.description   = $description,
                  p.example       = $example,
                  p.query_pattern = $qp
            WITH  p
            MATCH (n:UCKGMeta_Node {semantic: $belongs_to})
            MERGE (n)-[:META_HAS_PROPERTY]->(p)
            """,
            sem         = prop.get("semantic", ""),
            belongs_to  = node_semantic,
            physical    = prop.get("physical", ""),
            type        = prop.get("type", ""),
            description = prop.get("description", ""),
            example     = str(prop.get("example", "")),
            qp          = prop.get("query_pattern", "")
        )

    @staticmethod
    def _upsert_meta_relationship(tx, rel: dict,
                                   node_id_map: dict, schema_eid: str) -> None:
        domain_sem = rel.get("source_node_semantic", "")
        range_sem  = rel.get("target_node_semantic", "")

        # 1. Create / update the UCKGMeta_Relationship node
        tx.run(
            """
            MERGE (r:UCKGMeta_Relationship {semantic: $semantic})
            SET   r.physical_rel         = $physical_rel,
                  r.source_node_semantic = $domain_semantic,
                  r.source_node_physical = $domain_physical,
                  r.target_node_semantic = $range_semantic,
                  r.target_node_physical = $range_physical,
                  r.description          = $description,
                  r.traversal_direction  = $traversal_direction,
                  r.cypher_pattern       = $cypher_pattern,
                  r.triggers             = $triggers,
                  r.example_query        = $example_query
            WITH  r
            MATCH (s:UCKGMeta_Schema {version: 'v3'})
            MERGE (s)-[:META_HAS_RELATIONSHIP]->(r)
            """,
            semantic            = rel.get("semantic", ""),
            physical_rel        = rel.get("physical_rel", ""),
            domain_semantic     = domain_sem,
            domain_physical     = rel.get("source_node_physical", ""),
            range_semantic      = range_sem,
            range_physical      = rel.get("target_node_physical", ""),
            description         = rel.get("description", ""),
            traversal_direction = rel.get("traversal_direction", ""),
            cypher_pattern      = rel.get("cypher_pattern", ""),
            triggers            = rel.get("natural_language_triggers", []),
            example_query       = rel.get("example_query", "")
        )

        # 2. Create the META_CONNECTS_TO edge between the two UCKGMeta_Node nodes
        if domain_sem and range_sem:
            tx.run(
                """
                MATCH (src:UCKGMeta_Node {semantic: $src_sem})
                MATCH (tgt:UCKGMeta_Node {semantic: $tgt_sem})
                MERGE (src)-[e:META_CONNECTS_TO {via_semantic: $via_sem}]->(tgt)
                SET   e.via_physical       = $via_phys,
                      e.description        = $description,
                      e.cypher_pattern     = $cypher_pattern
                """,
                src_sem        = domain_sem,
                tgt_sem        = range_sem,
                via_sem        = rel.get("semantic", ""),
                via_phys       = rel.get("physical_rel", ""),
                description    = rel.get("description", ""),
                cypher_pattern = rel.get("cypher_pattern", "")
            )

    @staticmethod
    def _upsert_meta_path(tx, path: dict, schema_eid: str) -> None:
        tx.run(
            """
            MERGE (p:UCKGMeta_TraversalPath {name: $name})
            SET   p.description    = $description,
                  p.cypher_pattern = $cypher_pattern,
                  p.use_cases      = $use_cases
            WITH  p
            MATCH (s:UCKGMeta_Schema {version: 'v3'})
            MERGE (s)-[:META_HAS_PATH]->(p)
            """,
            name           = path.get("name", ""),
            description    = path.get("description", ""),
            cypher_pattern = path.get("cypher_pattern", ""),
            use_cases      = path.get("use_cases", [])
        )


# ─────────────────────────────────────────────────────────────────────────────
# Verification queries
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(driver):
    """Print a post-load summary from Neo4j."""
    counts = {}
    labels = [
        "UCKGMeta_Schema",
        "UCKGMeta_Node",
        "UCKGMeta_Property",
        "UCKGMeta_Relationship",
        "UCKGMeta_TraversalPath",
    ]
    with driver.session() as session:
        for label in labels:
            result = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
            counts[label] = result.single()["c"]

    print("\n─────────────────────────────────────────────")
    print("  Neo4j UCKGMeta sub-graph summary")
    print("─────────────────────────────────────────────")
    for label, count in counts.items():
        print(f"  {label:<35} {count:>4} node(s)")

    # Edge counts
    edge_types = [
        "META_HAS_NODE",
        "META_HAS_RELATIONSHIP",
        "META_HAS_PATH",
        "META_HAS_PROPERTY",
        "META_CONNECTS_TO",
    ]
    with driver.session() as session:
        for et in edge_types:
            result = session.run(
                f"MATCH ()-[r:{et}]->() RETURN count(r) AS c"
            )
            print(f"  [:{et:<30}] {result.single()['c']:>4} edge(s)")
    print("─────────────────────────────────────────────\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Load UCKG semantic schema (v3) into Neo4j as UCKGMeta_* nodes."
    )
    p.add_argument(
        "--schema", type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help=f"Path to semantic_schema_uckg_v3.json (default: {DEFAULT_SCHEMA_PATH})"
    )
    p.add_argument("--uri",      default=DEFAULT_URI,      help="Neo4j bolt URI")
    p.add_argument("--user",     default=DEFAULT_USER,     help="Neo4j username")
    p.add_argument("--password", default=DEFAULT_PASSWORD, help="Neo4j password")
    p.add_argument(
        "--dry-run", action="store_true",
        help="Parse the schema and print what would be loaded, without writing to Neo4j"
    )
    return p.parse_args()


def dry_run_report(schema: dict) -> None:
    """Print a summary of what the loader would write, without touching Neo4j."""
    nodes = schema.get("nodes", [])
    rels  = schema.get("relationships", [])
    paths = schema.get("graph_traversal_paths", [])
    corpus = schema.get("embedding_corpus", [])
    total_props = sum(len(n.get("properties", [])) for n in nodes)

    print("\n━━━━  DRY-RUN: Schema contents  ━━━━")
    print(f"  Version     : {schema.get('version')}")
    print(f"  Node types  : {len(nodes)}")
    print(f"  Properties  : {total_props}")
    print(f"  Rel triples : {len(rels)}")
    print(f"  Trav. paths : {len(paths)}")
    print(f"  Corpus lines: {len(corpus)}")

    print("\n  ── Node types ──")
    for nd in nodes:
        n_props = len(nd.get("properties", []))
        print(f"    {nd['semantic']:<20} ({nd.get('physical_label','?')}) — {n_props} properties")

    print("\n  ── Relationship triples ──")
    for rel in rels:
        print(f"    {rel.get('domain_semantic','?'):<20} -[{rel.get('semantic','?')}]-> {rel.get('range_semantic','?')}")
        print(f"      physical: [{rel.get('physical_rel','?')}]")

    print("\n  ── Traversal paths ──")
    for path in paths:
        print(f"    {path.get('name','?')}")

    print("\n  ── Embedding corpus (first 10 lines) ──")
    for line in corpus[:10]:
        print(f"    {line}")
    if len(corpus) > 10:
        print(f"    … (+{len(corpus)-10} more)")

    print("\n  (No changes written to Neo4j — dry-run mode)")


def main():
    args = parse_args()

    # Load JSON
    schema_path = args.schema
    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}")
        sys.exit(1)

    print(f"\n📂  Loading schema from: {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    print(f"    Version : {schema.get('version', '?')}")
    print(f"    Nodes   : {len(schema.get('nodes', []))}")
    print(f"    Rels    : {len(schema.get('relationships', []))}")
    print(f"    Paths   : {len(schema.get('graph_traversal_paths', []))}")

    if args.dry_run:
        dry_run_report(schema)
        return

    # Connect and load
    print(f"\n🔌  Connecting to Neo4j at {args.uri} …")
    loader = UCKGSchemaLoader(args.uri, args.user, args.password)

    try:
        print("\n🚀  Writing UCKGMeta_* nodes …\n")
        loader.load(schema)
        print_summary(loader.driver)
    finally:
        loader.close()

    print("💡  Example queries to explore the metadata:\n")
    print("    MATCH (n:UCKGMeta_Node) RETURN n.semantic, n.physical_label, n.description LIMIT 20")
    print("    MATCH (n:UCKGMeta_Node)-[r:META_CONNECTS_TO]->(m:UCKGMeta_Node)")
    print("          RETURN n.semantic, r.via_semantic, m.semantic")
    print("    MATCH (n:UCKGMeta_Node {semantic:'CVE'})-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)")
    print("          RETURN p.semantic, p.physical, p.description")
    print("    MATCH (tp:UCKGMeta_TraversalPath) RETURN tp.name, tp.cypher_pattern\n")


if __name__ == "__main__":
    main()
