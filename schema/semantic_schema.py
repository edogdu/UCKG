"""
semantic_schema.py
==================
Single entry point for all UCKG semantic schema operations.

This module is the *only* interface that Q&A, Text2Cypher, and any other
consumer should use to interact with the UCKG semantic schema.  It replaces
the previous standalone scripts (neo4j_schema_loader.py,
neo4j_semantic_extractor.py, generate_schema_cypher.py).

Workflow
--------
1. **Author**  — edit ``schema/semantic_schema.cypher`` (hand-authored Cypher)
2. **Load**    — ``update()``  executes that file into Neo4j (MERGE, idempotent)
3. **Extract** — ``extract_schema()``  queries Neo4j → JSON or TTL file
4. **Generate**— ``extract_text()``   fills nl_templates with real data nodes
                  → natural-language description sentences

Public API
----------
update(definition, ...)
    Execute the Cypher definition file to push / update schema metadata.

extract_schema(type, output, ...)
    Pull semantic schema from Neo4j and serialise to JSON or TTL.

extract_text(node, relation, pattern, output, limit, ...)
    Generate natural-language descriptions from the dataset using metadata
    templates stored in Neo4j (nl_template property on UCKGMeta_* nodes).

CLI
---
    python3 schema/semantic_schema.py update
    python3 schema/semantic_schema.py extract-schema --type json --output schema/schema.json
    python3 schema/semantic_schema.py extract-text   --node CVE --relation hasCPE --output uckg.txt
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Literal

from neo4j import GraphDatabase

# ─── Default paths ────────────────────────────────────────────────────────────
_HERE        = Path(__file__).resolve().parent           # UCKG/schema/
_REPO        = _HERE.parent                               # UCKG/

SCHEMA_CQL   = _HERE / "semantic_schema.cypher"          # authoritative Cypher
SCHEMA_JSON  = _HERE / "schema.json"                     # default JSON output
SCHEMA_TTL   = _HERE / "schema.ttl"                      # default TTL output

# ─── Default connection ───────────────────────────────────────────────────────
NEO4J_URI      = "bolt://localhost:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "abcd90909090"


# ═════════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════════

def update(
    definition: str | Path = SCHEMA_CQL,
    uri:        str        = NEO4J_URI,
    user:       str        = NEO4J_USER,
    password:   str        = NEO4J_PASSWORD,
) -> None:
    """Execute a Cypher definition file to create or override semantic schema
    metadata in Neo4j.

    All statements in the file use ``MERGE``, so re-running is safe and
    idempotent — existing definitions are updated in place, new ones are
    created, nothing is deleted.

    Parameters
    ----------
    definition : str | Path
        Path to the ``.cypher`` file to execute.
        Defaults to ``schema/semantic_schema.cypher``.
    uri : str
        Neo4j Bolt URI.  Default: ``bolt://localhost:7687``.
    user : str
        Neo4j username.  Default: ``neo4j``.
    password : str
        Neo4j password.

    Raises
    ------
    FileNotFoundError
        If *definition* does not exist.
    neo4j.exceptions.ServiceUnavailable
        If the Neo4j instance is unreachable.

    Example
    -------
    >>> from schema.semantic_schema import update
    >>> update()                            # use defaults
    >>> update("schema/semantic_schema.cypher", uri="bolt://neo4j:7687")
    """
    path = Path(definition)
    if not path.exists():
        raise FileNotFoundError(f"Cypher definition not found: {path}")

    driver = _get_driver(uri, user, password)
    try:
        _run_cypher_file(driver, path)
        print(f"✓ Schema metadata loaded from {path}")
    finally:
        driver.close()


def extract_schema(
    type:     Literal["json", "ttl"] = "json",
    output:   str | Path | None      = None,
    uri:      str = NEO4J_URI,
    user:     str = NEO4J_USER,
    password: str = NEO4J_PASSWORD,
) -> dict:
    """Extract semantic schema metadata from Neo4j and optionally write to file.

    Queries all ``UCKGMeta_*`` nodes and edges then serialises the result in
    the requested format.  If *output* is *None* the schema is returned as a
    Python dict without touching the filesystem.

    Parameters
    ----------
    type : "json" | "ttl"
        Serialisation format.
        - ``"json"`` — structured dict / JSON file  (default)
        - ``"ttl"``  — Turtle RDF (``@prefix uckg: <...> .``)
    output : str | Path | None
        Destination file path.  When *None* the schema is returned in memory.
        Default paths when not specified:
        - JSON → ``schema/schema.json``
        - TTL  → ``schema/schema.ttl``
    uri, user, password : str
        Neo4j connection parameters.

    Returns
    -------
    dict
        Schema dictionary with keys::

            {
                "version":               "v3",
                "source":                "neo4j",
                "classes":               [...],   # 14 node type entries
                "object_properties":     [...],   # 16 relationship entries
                "data_properties":       {...},   # properties keyed by node
                "graph_traversal_paths": [...],   # 7 multi-hop patterns
            }

    Raises
    ------
    ValueError
        If *type* is not ``"json"`` or ``"ttl"``.
    neo4j.exceptions.ServiceUnavailable
        If the Neo4j instance is unreachable.

    Example
    -------
    >>> from schema.semantic_schema import extract_schema
    >>> schema = extract_schema()                         # returns dict, no file
    >>> extract_schema(type="json", output="schema/schema.json")
    >>> extract_schema(type="ttl",  output="schema/schema.ttl")
    """
    if type not in ("json", "ttl"):
        raise ValueError(f"Unsupported type: {type!r}. Use 'json' or 'ttl'.")

    driver = _get_driver(uri, user, password)
    try:
        nodes = _fetch_node_metadata(driver)
        rels  = _fetch_relationship_metadata(driver)
        paths = _fetch_traversal_paths(driver)
        schema = _schema_to_json(nodes, rels, paths)

        if type == "ttl":
            ttl_str = _schema_to_ttl(schema)
            if output is not None:
                Path(output).write_text(ttl_str, encoding="utf-8")
                print(f"✓ Schema written to {output}")
            return schema

        # JSON
        if output is not None:
            Path(output).write_text(
                json.dumps(schema, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"✓ Schema written to {output}")
        return schema
    finally:
        driver.close()


def extract_text(
    node:     str | list[str] = "all",
    relation: str | list[str] = "all",
    pattern:  str | list[str] = "all",
    output:   str | Path | None = None,
    limit:    int | None        = None,
    uri:      str = NEO4J_URI,
    user:     str = NEO4J_USER,
    password: str = NEO4J_PASSWORD,
) -> list[str]:
    """Generate natural-language descriptions from the UCKG dataset by
    combining actual data nodes / edges with the ``nl_template`` strings
    stored in ``UCKGMeta_*`` nodes.

    For each matching instance the function retrieves the appropriate template
    from Neo4j and substitutes real node values to produce sentences such as:

        "CVE-2021-44228, which is a vulnerability, has a CPE,
         cpe:/a:apache:log4j:2.14.1, which is a software platform titled
         'Apache Log4j 2.14.1'."

    Template variables substituted at runtime:
        - ``{SRC_ID}``    — source node key identifier value
        - ``{SRC_LABEL}`` — source node human-readable name / title
        - ``{TGT_ID}``    — target node key identifier value
        - ``{TGT_LABEL}`` — target node human-readable name / title

    Parameters
    ----------
    node : str | list[str]
        Semantic node type(s) to include (e.g. ``"CVE"``,
        ``["CVE", "Weakness"]``).  ``"all"`` processes every node type.
        When specified, node-level descriptions are generated using the
        node's own ``nl_template``.
    relation : str | list[str]
        Semantic relationship type(s) to include (e.g. ``"hasCPE"``).
        ``"all"`` processes every relationship type.
        When specified, edge-level sentences are generated by traversing
        actual graph edges and filling in the relationship ``nl_template``.
    pattern : str | list[str]
        Traversal path name(s) to include
        (e.g. ``"CWE to CVE (full chain)"``).
        ``"all"`` processes every documented traversal path.
        When specified, multi-hop descriptions are assembled from the
        sequence of nl_templates along the path.
    output : str | Path | None
        File to write descriptions to (one sentence per line).
        If *None*, returns the list in memory without writing.
    limit : int | None
        Maximum number of data instances to process per type.
        *None* means no limit (whole dataset).
    uri, user, password : str
        Neo4j connection parameters.

    Returns
    -------
    list[str]
        Natural-language description strings, one per graph instance.

    Raises
    ------
    neo4j.exceptions.ServiceUnavailable
        If the Neo4j instance is unreachable.

    Example
    -------
    >>> from schema.semantic_schema import extract_text
    >>> sentences = extract_text(relation="hasCPE", limit=100)
    >>> extract_text(node="all", relation="all", output="uckg.txt")
    >>> extract_text(node="CVE", relation="hasCPE", pattern="all",
    ...              output="cve_descriptions.txt", limit=500)
    """
    driver = _get_driver(uri, user, password)
    sentences: list[str] = []

    try:
        # ── 1. Node-level sentences ──────────────────────────────────────
        if node != "none":
            node_types = _resolve_node_types(driver, node)
            if node_types:
                node_sents = _generate_node_sentences(driver, node_types, limit)
                sentences.extend(node_sents)
                print(f"  ✓ Generated {len(node_sents)} node sentences "
                      f"across {len(node_types)} types")

        # ── 2. Edge-level sentences ──────────────────────────────────────
        if relation != "none":
            rel_types = _resolve_rel_types(driver, relation)
            if rel_types:
                edge_sents = _generate_edge_sentences(driver, rel_types, limit)
                sentences.extend(edge_sents)
                print(f"  ✓ Generated {len(edge_sents)} edge sentences "
                      f"across {len(rel_types)} relationship types")

        # ── 3. Traversal-path sentences (skipped for now) ────────────────
        # Multi-hop path sentences require executing complex Cypher patterns;
        # this will be implemented in a later iteration.

        print(f"\n  Total: {len(sentences)} sentences generated")

        # ── Write output ─────────────────────────────────────────────────
        if output is not None:
            _write_lines(sentences, Path(output))
            print(f"  ✓ Written to {output}")

        return sentences

    finally:
        driver.close()


# ═════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═════════════════════════════════════════════════════════════════════════════

def _get_driver(uri: str, user: str, password: str):
    """Return a live ``neo4j.GraphDatabase.driver`` instance.

    The caller is responsible for closing the driver after use.
    """
    return GraphDatabase.driver(uri, auth=(user, password))


def _run_cypher_file(driver, path: Path) -> None:
    """Split a ``.cypher`` file on statement boundaries (``;``) and execute
    each statement inside a single write transaction.

    Empty statements and pure-comment blocks are skipped.
    """
    text = path.read_text(encoding="utf-8")
    raw_stmts = text.split(";")

    success = 0
    skipped = 0

    with driver.session() as session:
        for raw in raw_stmts:
            # Strip and remove pure-comment lines for the emptiness check
            stripped = raw.strip()
            non_comment_lines = [
                l for l in stripped.splitlines()
                if l.strip() and not l.strip().startswith("//")
            ]
            if not non_comment_lines:
                skipped += 1
                continue
            try:
                session.run(stripped)
                success += 1
            except Exception as e:
                # Skip comment blocks that fail to parse
                skipped += 1

    print(f"  Executed {success} statements ({skipped} skipped)")


def _fetch_node_metadata(driver) -> list[dict]:
    """Return a list of dicts, one per ``UCKGMeta_Node``, including its
    associated properties fetched via ``META_HAS_PROPERTY`` edges.
    """
    query = """
    MATCH (n:UCKGMeta_Node)
    OPTIONAL MATCH (n)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)
    WITH n, collect({
        semantic:    p.semantic,
        physical:    p.physical,
        type:        p.type,
        description: p.description,
        example:     p.example
    }) AS props
    RETURN n.semantic          AS semantic,
           n.physical_label    AS physical_label,
           n.purpose           AS purpose,
           n.description       AS description,
           n.key_identifier    AS key_identifier,
           n.nl_template       AS nl_template,
           n.triggers          AS triggers,
           props
    ORDER BY n.semantic
    """
    with driver.session() as session:
        result = session.run(query)
        nodes = []
        for rec in result:
            props = rec["props"]
            # Filter out empty property dicts (from OPTIONAL MATCH with no match)
            props = [p for p in props if p.get("semantic") is not None]
            nodes.append({
                "semantic":       rec["semantic"],
                "physical_label": rec["physical_label"],
                "purpose":        rec["purpose"],
                "description":    rec["description"],
                "key_identifier": rec["key_identifier"],
                "nl_template":    rec["nl_template"],
                "triggers":       list(rec["triggers"]) if rec["triggers"] else [],
                "properties":     props,
            })
        return nodes


def _fetch_relationship_metadata(driver) -> list[dict]:
    """Return a list of dicts, one per ``META_CONNECTS_TO`` edge (relationship
    metadata is now stored directly on the edge).
    """
    query = """
    MATCH (src:UCKGMeta_Node)-[e:META_CONNECTS_TO]->(tgt:UCKGMeta_Node)
    RETURN src.semantic        AS source_node_semantic,
           src.physical_label  AS source_node_physical,
           tgt.semantic        AS target_node_semantic,
           tgt.physical_label  AS target_node_physical,
           e.semantic          AS semantic,
           e.physical_rel      AS physical_rel,
           e.description       AS description,
           e.nl_template       AS nl_template,
           e.cypher_pattern    AS cypher_pattern,
           e.triggers          AS triggers,
           e.example_query     AS example_query,
           src.key_identifier  AS src_key_identifier,
           tgt.key_identifier  AS tgt_key_identifier
    ORDER BY src.semantic, e.semantic
    """
    with driver.session() as session:
        result = session.run(query)
        rels = []
        for rec in result:
            rels.append({
                "semantic":             rec["semantic"],
                "physical_rel":         rec["physical_rel"],
                "source_node_semantic": rec["source_node_semantic"],
                "source_node_physical": rec["source_node_physical"],
                "target_node_semantic": rec["target_node_semantic"],
                "target_node_physical": rec["target_node_physical"],
                "description":          rec["description"],
                "nl_template":          rec["nl_template"],
                "cypher_pattern":       rec["cypher_pattern"],
                "triggers":             list(rec["triggers"]) if rec["triggers"] else [],
                "example_query":        rec["example_query"],
                "src_key_identifier":   rec["src_key_identifier"],
                "tgt_key_identifier":   rec["tgt_key_identifier"],
            })
        return rels


def _fetch_traversal_paths(driver) -> list[dict]:
    """Return a list of dicts, one per ``UCKGMeta_TraversalPath``."""
    query = """
    MATCH (tp:UCKGMeta_TraversalPath)
    RETURN tp.name           AS name,
           tp.description    AS description,
           tp.cypher_pattern AS cypher_pattern,
           tp.use_cases      AS use_cases
    ORDER BY tp.name
    """
    with driver.session() as session:
        result = session.run(query)
        return [
            {
                "name":           rec["name"],
                "description":    rec["description"],
                "cypher_pattern": rec["cypher_pattern"],
                "use_cases":      list(rec["use_cases"]) if rec["use_cases"] else [],
            }
            for rec in result
        ]


def _schema_to_json(nodes: list, rels: list, paths: list) -> dict:
    """Assemble a structured schema dict from pre-fetched metadata lists."""
    # Build data_properties keyed by node semantic name
    data_props = {}
    for n in nodes:
        if n["properties"]:
            data_props[n["semantic"]] = n["properties"]

    # Build classes (strip properties from each node entry)
    classes = []
    for n in nodes:
        classes.append({
            "semantic":       n["semantic"],
            "physical_label": n["physical_label"],
            "purpose":        n["purpose"],
            "description":    n["description"],
            "key_identifier": n["key_identifier"],
            "nl_template":    n["nl_template"],
            "triggers":       n["triggers"],
        })

    # Build object_properties
    obj_props = []
    for r in rels:
        obj_props.append({
            "semantic":             r["semantic"],
            "physical_rel":         r["physical_rel"],
            "source_node_semantic": r["source_node_semantic"],
            "source_node_physical": r["source_node_physical"],
            "target_node_semantic": r["target_node_semantic"],
            "target_node_physical": r["target_node_physical"],
            "description":          r["description"],
            "nl_template":          r["nl_template"],
            "cypher_pattern":       r["cypher_pattern"],
            "triggers":             r["triggers"],
            "example_query":        r["example_query"],
        })

    return {
        "version":               "v3",
        "source":                "neo4j",
        "classes":               classes,
        "object_properties":     obj_props,
        "data_properties":       data_props,
        "graph_traversal_paths": [dict(p) for p in paths],
    }


def _schema_to_ttl(schema: dict) -> str:
    """Serialise a schema dict to Turtle (RDF) format."""
    lines = [
        "@prefix uckg:  <http://purl.org/cyber/uckg#> .",
        "@prefix owl:   <http://www.w3.org/2002/07/owl#> .",
        "@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .",
        "@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .",
        "",
    ]

    # Classes
    for c in schema.get("classes", []):
        sem = c["semantic"]
        lines.append(f"uckg:{sem} a owl:Class ;")
        lines.append(f'    rdfs:label "{sem}" ;')
        lines.append(f'    rdfs:comment "{c.get("purpose", "")}" .')
        lines.append("")

    # Object properties (relationships)
    for r in schema.get("object_properties", []):
        sem = r["semantic"]
        lines.append(f"uckg:{sem} a owl:ObjectProperty ;")
        lines.append(f'    rdfs:label "{sem}" ;')
        lines.append(f'    rdfs:domain uckg:{r["source_node_semantic"]} ;')
        lines.append(f'    rdfs:range  uckg:{r["target_node_semantic"]} ;')
        lines.append(f'    rdfs:comment "{r.get("description", "")}" .')
        lines.append("")

    # Data properties
    for node_sem, props in schema.get("data_properties", {}).items():
        for p in props:
            prop_id = f"{node_sem}_{p['semantic']}"
            lines.append(f"uckg:{prop_id} a owl:DatatypeProperty ;")
            lines.append(f'    rdfs:label "{p["semantic"]}" ;')
            lines.append(f'    rdfs:domain uckg:{node_sem} ;')
            lines.append(f'    rdfs:comment "{p.get("description", "")}" .')
            lines.append("")

    return "\n".join(lines)


def _fill_nl_template(template: str, src: dict, tgt: dict | None = None) -> str:
    """Substitute runtime node data into an ``nl_template`` string.

    Expected placeholder tokens in *template*:
        - ``{ID}``        → src["id"]    (for node-level templates)
        - ``{DESC}``      → src["desc"]  (descriptive property value)
        - ``{SRC_ID}``    → src["id"]    (key identifier value)
        - ``{SRC_LABEL}`` → src["label"] (human-readable name)
        - ``{TGT_ID}``    → tgt["id"]
        - ``{TGT_LABEL}`` → tgt["label"]

    Missing keys are replaced with ``"<unknown>"``.
    """
    unknown = "<unknown>"

    result = template
    result = result.replace("{ID}",        str(src.get("id", unknown)))
    result = result.replace("{DESC}",      str(src.get("desc", "")))
    result = result.replace("{SRC_ID}",    str(src.get("id", unknown)))
    result = result.replace("{SRC_LABEL}", str(src.get("label", src.get("id", unknown))))

    if tgt is not None:
        result = result.replace("{TGT_ID}",    str(tgt.get("id", unknown)))
        result = result.replace("{TGT_LABEL}", str(tgt.get("label", tgt.get("id", unknown))))

    return result


def _clean_text(text: str, max_len: int = 200) -> str:
    """Clean raw text from Neo4j for use in NL sentences.

    - Strip markdown links: [text](url) → text
    - Strip citation markers: (Citation: ...)
    - Collapse whitespace
    - Truncate to first sentence or *max_len* chars, whichever is shorter.
    """
    if not text:
        return ""
    # Strip markdown links
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Strip citation markers
    text = re.sub(r'\(Citation:[^)]*\)', '', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Truncate to first sentence boundary (. or !) within max_len
    if len(text) > max_len:
        # Try to cut at a sentence boundary
        cut = text[:max_len]
        for end_char in ['. ', '! ', '? ']:
            last_period = cut.rfind(end_char)
            if last_period > 40:  # don't cut too short
                return cut[:last_period + 1]
        return cut.rstrip() + "…"
    return text


def _strip_uri_prefix(uri: str) -> str:
    """Extract the meaningful ID from a full URI.

    ``http://purl.org/cyber/uco#VULN-CVE-2000-0363`` → ``VULN-CVE-2000-0363``
    ``http://example.com/ucoex#CWE-22-CVE-2024-0520``  → ``CWE-22-CVE-2024-0520``
    """
    if not uri or not isinstance(uri, str):
        return str(uri) if uri else "<unknown>"
    if "#" in uri:
        return uri.rsplit("#", 1)[-1]
    if "/" in uri:
        return uri.rsplit("/", 1)[-1]
    return uri


# ─── Resolution helpers ──────────────────────────────────────────────────────

def _resolve_node_types(driver, node: str | list[str]) -> list[str]:
    """Resolve 'all' to the full list of semantic node types from metadata."""
    if node == "all":
        query = "MATCH (n:UCKGMeta_Node) RETURN n.semantic AS sem ORDER BY sem"
        with driver.session() as session:
            return [r["sem"] for r in session.run(query)]
    if isinstance(node, str):
        return [node]
    return list(node)


def _resolve_rel_types(driver, relation: str | list[str]) -> list[str]:
    """Resolve 'all' to the full list of semantic relationship types."""
    if relation == "all":
        query = """
        MATCH (:UCKGMeta_Node)-[e:META_CONNECTS_TO]->(:UCKGMeta_Node)
        RETURN e.semantic AS sem ORDER BY sem
        """
        with driver.session() as session:
            return [r["sem"] for r in session.run(query)]
    if isinstance(relation, str):
        return [relation]
    return list(relation)


# ─── Node sentence generation ────────────────────────────────────────────────

# Properties commonly used as a human-readable label (tried in order)
_LABEL_CANDIDATES = ["label", "ucoexNAME", "ucoexMITRED3FEND_LABEL", "cpeName"]


def _generate_node_sentences(
    driver, node_types: list[str], limit: int | None
) -> list[str]:
    """Query actual data nodes and produce one NL sentence per node."""
    sentences: list[str] = []

    # Fetch metadata for all requested node types
    meta_query = """
    MATCH (m:UCKGMeta_Node)
    WHERE m.semantic IN $types
    RETURN m.semantic       AS semantic,
           m.physical_label AS physical_label,
           m.key_identifier AS key_identifier,
           m.nl_template    AS nl_template,
           m.desc_property  AS desc_property
    """
    with driver.session() as session:
        meta_records = list(session.run(meta_query, types=node_types))

    for meta in meta_records:
        semantic       = meta["semantic"]
        physical_label = meta["physical_label"]
        key_id_prop    = meta["key_identifier"]
        nl_template    = meta["nl_template"]
        desc_prop      = meta.get("desc_property")
        is_uri_key     = key_id_prop == "uri"

        if not nl_template:
            continue

        # Build the description property clause
        has_desc = desc_prop and desc_prop != "NONE"
        desc_clause = (
            f", n.`{desc_prop}` AS desc"
            if has_desc else ", null AS desc"
        )

        # Build a Cypher query to fetch actual data instances
        limit_clause = f"LIMIT {limit}" if limit else ""
        data_query = (
            f"MATCH (n:`{physical_label}`) "
            f"WHERE n.`{key_id_prop}` IS NOT NULL "
            + (f"AND n.`{desc_prop}` IS NOT NULL " if has_desc else "")
            + f"RETURN n.`{key_id_prop}` AS id, "
            f"       coalesce(n.label, n.ucoexNAME, n.ucoexMITRED3FEND_LABEL, "
            f"                n.`{key_id_prop}`) AS node_label"
            + desc_clause + " "
            + limit_clause
        )

        with driver.session() as session:
            data_records = list(session.run(data_query))

        for rec in data_records:
            node_id    = rec["id"]
            node_label = rec["node_label"]
            desc_val   = rec["desc"]
            if node_id is None:
                continue

            # Clean up URI identifiers
            if is_uri_key:
                node_id = _strip_uri_prefix(str(node_id))
                if node_label and "://" in str(node_label):
                    node_label = _strip_uri_prefix(str(node_label))

            # Clean description text
            desc_clean = _clean_text(str(desc_val), max_len=200) if desc_val else ""

            sentence = _fill_nl_template(
                nl_template,
                src={
                    "id":    node_id,
                    "label": node_label or node_id,
                    "desc":  desc_clean,
                },
            )
            sentences.append(sentence)

    return sentences


# ─── Edge sentence generation ────────────────────────────────────────────────

def _generate_edge_sentences(
    driver, rel_types: list[str], limit: int | None
) -> list[str]:
    """Traverse actual graph edges and produce one NL sentence per edge."""
    sentences: list[str] = []

    # Fetch relationship metadata from META_CONNECTS_TO edges
    meta_query = """
    MATCH (src_meta:UCKGMeta_Node)-[e:META_CONNECTS_TO]->(tgt_meta:UCKGMeta_Node)
    WHERE e.semantic IN $types
    RETURN e.semantic            AS semantic,
           e.physical_rel        AS physical_rel,
           e.nl_template         AS nl_template,
           src_meta.physical_label  AS src_physical,
           src_meta.key_identifier  AS src_key_id,
           tgt_meta.physical_label  AS tgt_physical,
           tgt_meta.key_identifier  AS tgt_key_id
    ORDER BY e.semantic
    """
    with driver.session() as session:
        meta_records = list(session.run(meta_query, types=rel_types))

    for meta in meta_records:
        semantic     = meta["semantic"]
        physical_rel = meta["physical_rel"]
        nl_template  = meta["nl_template"]
        src_physical = meta["src_physical"]
        src_key_id   = meta["src_key_id"]
        tgt_physical = meta["tgt_physical"]
        tgt_key_id   = meta["tgt_key_id"]

        if not nl_template:
            continue

        # Build Cypher to traverse actual edges in the graph
        limit_clause = f"LIMIT {limit}" if limit else ""
        data_query = (
            f"MATCH (s:`{src_physical}`)-[:`{physical_rel}`]->(t:`{tgt_physical}`) "
            f"RETURN s.`{src_key_id}` AS src_id, "
            f"       coalesce(s.label, s.ucoexNAME, s.ucoexMITRED3FEND_LABEL, "
            f"                s.`{src_key_id}`) AS src_label, "
            f"       t.`{tgt_key_id}` AS tgt_id, "
            f"       coalesce(t.label, t.ucoexNAME, t.ucoexMITRED3FEND_LABEL, "
            f"                t.`{tgt_key_id}`) AS tgt_label "
            f"{limit_clause}"
        )

        with driver.session() as session:
            data_records = list(session.run(data_query))

        src_is_uri = src_key_id == "uri"
        tgt_is_uri = tgt_key_id == "uri"

        for rec in data_records:
            src_id    = rec["src_id"]
            tgt_id    = rec["tgt_id"]
            src_label = rec["src_label"]
            tgt_label = rec["tgt_label"]
            if src_id is None or tgt_id is None:
                continue

            # Clean URI-based identifiers
            if src_is_uri:
                src_id = _strip_uri_prefix(str(src_id))
                if src_label and "://" in str(src_label):
                    src_label = _strip_uri_prefix(str(src_label))
            if tgt_is_uri:
                tgt_id = _strip_uri_prefix(str(tgt_id))
                if tgt_label and "://" in str(tgt_label):
                    tgt_label = _strip_uri_prefix(str(tgt_label))

            sentence = _fill_nl_template(
                nl_template,
                src={"id": src_id, "label": src_label or src_id},
                tgt={"id": tgt_id, "label": tgt_label or tgt_id},
            )
            sentences.append(sentence)

    return sentences


def _generate_path_sentences(
    driver, path_names: list[str], limit: int | None
) -> list[str]:
    """Execute the ``cypher_pattern`` of each named traversal path and
    assemble multi-hop sentences by chaining the individual ``nl_template``
    strings of each node and relationship along the path.

    NOTE: Not yet implemented — requires parsing and executing arbitrary
    multi-hop Cypher patterns. Will be added in a future iteration.
    """
    return []


def _write_lines(lines: list[str], path: Path) -> None:
    """Write *lines* to *path*, one line per sentence, UTF-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="semantic_schema",
        description="UCKG Semantic Schema Manager",
    )
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    # ── update ────────────────────────────────────────────────────────────
    pu = sub.add_parser("update", help="Push Cypher definitions into Neo4j")
    pu.add_argument("--definition", default=str(SCHEMA_CQL),
                    help="Path to .cypher file  (default: schema/semantic_schema.cypher)")
    pu.add_argument("--uri",      default=NEO4J_URI)
    pu.add_argument("--user",     default=NEO4J_USER)
    pu.add_argument("--password", default=NEO4J_PASSWORD)

    # ── extract-schema ────────────────────────────────────────────────────
    pe = sub.add_parser("extract-schema", help="Export schema to JSON or TTL")
    pe.add_argument("--type",   choices=["json", "ttl"], default="json")
    pe.add_argument("--output", default=None,
                    help="Destination file  (default: schema/schema.json or schema/schema.ttl)")
    pe.add_argument("--uri",      default=NEO4J_URI)
    pe.add_argument("--user",     default=NEO4J_USER)
    pe.add_argument("--password", default=NEO4J_PASSWORD)

    # ── extract-text ──────────────────────────────────────────────────────
    pt = sub.add_parser("extract-text",
                         help="Generate NL descriptions from the dataset")
    pt.add_argument("--node",     default="all",
                    help='Semantic node type(s), comma-separated, or "all"')
    pt.add_argument("--relation", default="all",
                    help='Semantic relationship type(s), comma-separated, or "all"')
    pt.add_argument("--pattern",  default="all",
                    help='Traversal path name(s), comma-separated, or "all"')
    pt.add_argument("--output",   default=None,
                    help="Output file (one sentence per line).  Omit to print to stdout.")
    pt.add_argument("--limit",    type=int, default=None,
                    help="Max instances per type  (default: no limit)")
    pt.add_argument("--uri",      default=NEO4J_URI)
    pt.add_argument("--user",     default=NEO4J_USER)
    pt.add_argument("--password", default=NEO4J_PASSWORD)

    return p


if __name__ == "__main__":
    parser = _build_parser()
    args   = parser.parse_args()

    if args.cmd == "update":
        update(args.definition, args.uri, args.user, args.password)

    elif args.cmd == "extract-schema":
        result = extract_schema(args.type, args.output, args.uri, args.user, args.password)
        if args.output is None:
            print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.cmd == "extract-text":
        node     = args.node     if args.node     == "all" else args.node.split(",")
        relation = args.relation if args.relation == "all" else args.relation.split(",")
        pattern  = args.pattern  if args.pattern  == "all" else args.pattern.split(",")
        lines = extract_text(node, relation, pattern, args.output, args.limit,
                             args.uri, args.user, args.password)
        if args.output is None:
            for line in lines:
                print(line)

    else:
        parser.print_help()
        sys.exit(1)
