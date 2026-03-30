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
import sys
from pathlib import Path
from typing import Literal

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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


# ═════════════════════════════════════════════════════════════════════════════
# Internal helpers  (to be implemented before the public API above)
# ═════════════════════════════════════════════════════════════════════════════

def _get_driver(uri: str, user: str, password: str):
    """Return a live ``neo4j.GraphDatabase.driver`` instance.

    The caller is responsible for closing the driver after use.
    """
    raise NotImplementedError


def _run_cypher_file(driver, path: Path) -> None:
    """Split a ``.cypher`` file on statement boundaries (``;\n``) and execute
    each statement inside a single write transaction.

    Empty statements and pure-comment blocks are skipped.
    """
    raise NotImplementedError


def _fetch_node_metadata(driver) -> list[dict]:
    """Return a list of dicts, one per ``UCKGMeta_Node``, including its
    associated properties fetched via ``META_HAS_PROPERTY`` edges.

    Each dict shape::

        {
            "semantic":          str,
            "physical_label":    str,
            "purpose":           str,
            "description":       str,
            "key_identifier":    str,
            "nl_template":       str,
            "triggers":          list[str],
            "properties": [
                {
                    "semantic":    str,
                    "physical":    str,
                    "type":        str,
                    "description": str,
                    "example":     str,
                },
                ...
            ],
        }
    """
    raise NotImplementedError


def _fetch_relationship_metadata(driver) -> list[dict]:
    """Return a list of dicts, one per ``UCKGMeta_Relationship``.

    Each dict shape::

        {
            "semantic":             str,
            "physical_rel":         str,
            "source_node_semantic": str,
            "source_node_physical": str,
            "target_node_semantic": str,
            "target_node_physical": str,
            "description":          str,
            "nl_template":          str,
            "cypher_pattern":       str,
            "triggers":             list[str],
            "example_query":        str,
        }
    """
    raise NotImplementedError


def _fetch_traversal_paths(driver) -> list[dict]:
    """Return a list of dicts, one per ``UCKGMeta_TraversalPath``.

    Each dict shape::

        {
            "name":           str,
            "description":    str,
            "cypher_pattern": str,
            "use_cases":      list[str],
        }
    """
    raise NotImplementedError


def _schema_to_json(nodes: list, rels: list, paths: list) -> dict:
    """Assemble a structured schema dict from pre-fetched metadata lists.

    Returns a dict compatible with ``semantic_schema_uckg_v3.json`` structure
    (``classes``, ``object_properties``, ``data_properties``,
    ``graph_traversal_paths``).
    """
    raise NotImplementedError


def _schema_to_ttl(schema: dict) -> str:
    """Serialise a schema dict to Turtle (RDF) format.

    Uses the ``uckg:`` prefix for all UCKG-specific URIs and maps
    ``UCKGMeta_Node`` → ``owl:Class``, ``UCKGMeta_Relationship`` →
    ``owl:ObjectProperty``, ``UCKGMeta_Property`` → ``owl:DatatypeProperty``.

    Returns the full Turtle string (UTF-8).
    """
    raise NotImplementedError


def _fill_nl_template(template: str, src: dict, tgt: dict | None = None) -> str:
    """Substitute runtime node data into an ``nl_template`` string.

    Expected placeholder tokens in *template*:
        - ``{SRC_ID}``    → src["id"]    (key identifier value)
        - ``{SRC_LABEL}`` → src["label"] (human-readable name)
        - ``{TGT_ID}``    → tgt["id"]
        - ``{TGT_LABEL}`` → tgt["label"]

    Missing keys are replaced with ``"<unknown>"``.
    """
    raise NotImplementedError


def _generate_node_sentences(driver, node_types: list[str], limit: int | None) -> list[str]:
    """Query actual data nodes of the given semantic types and generate one
    description sentence per node using the node's ``nl_template``.

    Uses the ``key_identifier`` and ``purpose`` fields from ``UCKGMeta_Node``
    to build the sentence context.
    """
    raise NotImplementedError


def _generate_edge_sentences(driver, rel_types: list[str], limit: int | None) -> list[str]:
    """Traverse actual graph edges matching the given semantic relationship
    types and generate one sentence per edge by filling in the relationship
    ``nl_template`` with source / target node data.
    """
    raise NotImplementedError


def _generate_path_sentences(driver, path_names: list[str], limit: int | None) -> list[str]:
    """Execute the ``cypher_pattern`` of each named traversal path and
    assemble multi-hop sentences by chaining the individual ``nl_template``
    strings of each node and relationship along the path.
    """
    raise NotImplementedError


def _write_lines(lines: list[str], path: Path) -> None:
    """Write *lines* to *path*, one line per sentence, UTF-8."""
    raise NotImplementedError


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
