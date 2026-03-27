"""
neo4j_semantic_extractor.py
============================
Extracts the UCKG semantic schema live from Neo4j by querying the
UCKGMeta_* metadata sub-graph that was written by neo4j_schema_loader.py.

This mirrors exactly what qa-engine/shared/schema_extract.py does for
the physical schema — instead of reading a flat text file or a local JSON,
the schema is fetched directly from the database and returned as a dict
that is fully compatible with the existing pipeline helpers:

    build_embedding_corpus(schema)   ← t2css_enhanced.py
    build_maps(schema)               ← t2css_enhanced.py

The returned dict has the same keys as semantic_schema_uckg_v2.json:

    {
      "version": "v3",
      "classes":           [{"semantic", "physical_labels", "description"}, ...],
      "object_properties": [{"semantic", "domain", "range", "physical_rel",
                             "description", "cypher_pattern",
                             "natural_language_triggers", "example_query"}, ...],
      "data_properties":   {"NodeSemantic": ["prop: physical — description", ...]},
      "embedding_corpus":  [...],         # reconstructed from structured data
      "graph_traversal_paths": [...],     # bonus: multi-hop path metadata
      "notes":  str,
      "source": "neo4j"
    }

Usage
-----
    from neo4j_semantic_extractor import SemanticSchemaExtractor

    extractor = SemanticSchemaExtractor("bolt://localhost:7687", "neo4j", "pass")
    schema    = extractor.extract()          # live from Neo4j
    extractor.close()

    # or with a local cache file (re-fetches only when stale / missing):
    schema = extractor.extract(cache_path="configt2c/semantic_schema_neo4j_cache.json",
                               max_age_hours=24)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Cypher queries
# ─────────────────────────────────────────────────────────────────────────────

_Q_SCHEMA_META = """
MATCH (s:UCKGMeta_Schema {version: $version})
RETURN s.notes AS notes,
       s.last_loaded AS last_loaded,
       s.embedding_corpus_size AS corpus_size
"""

_Q_NODES = """
MATCH (n:UCKGMeta_Node)
RETURN n.semantic          AS semantic,
       n.physical_label    AS physical_label,
       n.description       AS description,
       n.purpose           AS purpose,
       n.key_identifier    AS key_identifier,
       n.key_identifier_example AS key_identifier_example,
       n.triggers          AS triggers
ORDER BY n.semantic
"""

_Q_PROPERTIES = """
MATCH (n:UCKGMeta_Node)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)
RETURN n.semantic       AS node_semantic,
       p.semantic       AS prop_semantic,
       p.physical       AS physical,
       p.type           AS type,
       p.description    AS description,
       p.example        AS example,
       p.query_pattern  AS query_pattern
ORDER BY n.semantic, p.semantic
"""

_Q_RELATIONSHIPS = """
MATCH (r:UCKGMeta_Relationship)
RETURN r.semantic            AS semantic,
       r.physical_rel        AS physical_rel,
       r.domain_semantic     AS domain_semantic,
       r.domain_physical     AS domain_physical,
       r.range_semantic      AS range_semantic,
       r.range_physical      AS range_physical,
       r.description         AS description,
       r.traversal_direction AS traversal_direction,
       r.cypher_pattern      AS cypher_pattern,
       r.triggers            AS triggers,
       r.example_query       AS example_query
ORDER BY r.domain_semantic, r.semantic
"""

_Q_PATHS = """
MATCH (tp:UCKGMeta_TraversalPath)
RETURN tp.name           AS name,
       tp.description    AS description,
       tp.cypher_pattern AS cypher_pattern,
       tp.use_cases      AS use_cases
ORDER BY tp.name
"""

_Q_EXISTS = """
MATCH (s:UCKGMeta_Schema {version: $version})
RETURN count(s) AS c
"""


# ─────────────────────────────────────────────────────────────────────────────
# Extractor
# ─────────────────────────────────────────────────────────────────────────────

class SemanticSchemaExtractor:
    """
    Queries the UCKGMeta_* metadata sub-graph from Neo4j and returns a schema
    dict identical in structure to the semantic_schema_uckg_v2.json format,
    so it can be dropped straight into the existing T2CSS pipeline.
    """

    def __init__(self, uri: str, user: str, password: str,
                 version: str = "v3"):
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:
            raise ImportError(
                "neo4j Python driver is required: pip install neo4j"
            ) from exc

        self._driver  = GraphDatabase.driver(uri, auth=(user, password))
        self._version = version

    def close(self) -> None:
        self._driver.close()

    # ── public API ────────────────────────────────────────────────────────────

    def schema_exists(self) -> bool:
        """Return True if UCKGMeta_Schema (version) is present in Neo4j."""
        with self._driver.session() as session:
            result = session.run(_Q_EXISTS, version=self._version)
            return result.single()["c"] > 0

    def extract(
        self,
        cache_path: Optional[str] = None,
        max_age_hours: float = 0,       # 0 → always re-fetch from Neo4j
    ) -> Dict:
        """
        Pull the semantic schema from Neo4j and return a pipeline-compatible dict.

        Parameters
        ----------
        cache_path : str | None
            If given, write the result to this JSON file (and re-use it when
            the file is younger than max_age_hours).
        max_age_hours : float
            Cache TTL in hours. 0 means never use cache.
        """
        # ── cache hit? ────────────────────────────────────────────────────────
        if cache_path and max_age_hours > 0:
            cached = self._try_load_cache(cache_path, max_age_hours)
            if cached is not None:
                logger.info("SemanticSchemaExtractor: using cache %s", cache_path)
                return cached

        # ── live extraction ───────────────────────────────────────────────────
        logger.info(
            "SemanticSchemaExtractor: extracting semantic schema from Neo4j (version=%s)…",
            self._version
        )

        if not self.schema_exists():
            raise RuntimeError(
                f"UCKGMeta_Schema (version='{self._version}') not found in Neo4j. "
                "Run neo4j_schema_loader.py first to bootstrap the metadata."
            )

        with self._driver.session() as session:
            meta         = self._fetch_meta(session)
            nodes        = self._fetch_nodes(session)
            props_by_node = self._fetch_properties(session)
            rels         = self._fetch_relationships(session)
            paths        = self._fetch_paths(session)

        schema = self._assemble(meta, nodes, props_by_node, rels, paths)

        # ── optional cache write ──────────────────────────────────────────────
        if cache_path:
            self._write_cache(cache_path, schema)
            logger.info("SemanticSchemaExtractor: cached to %s", cache_path)

        return schema

    # ── private fetch helpers ─────────────────────────────────────────────────

    def _fetch_meta(self, session) -> Dict:
        result = session.run(_Q_SCHEMA_META, version=self._version)
        rec = result.single()
        if rec is None:
            return {}
        return dict(rec)

    def _fetch_nodes(self, session) -> List[Dict]:
        result = session.run(_Q_NODES)
        return [dict(r) for r in result]

    def _fetch_properties(self, session) -> Dict[str, List[Dict]]:
        """Returns {node_semantic: [prop_dict, ...]}"""
        result = session.run(_Q_PROPERTIES)
        by_node: Dict[str, List[Dict]] = {}
        for rec in result:
            node_sem = rec["node_semantic"]
            by_node.setdefault(node_sem, []).append(dict(rec))
        return by_node

    def _fetch_relationships(self, session) -> List[Dict]:
        result = session.run(_Q_RELATIONSHIPS)
        return [dict(r) for r in result]

    def _fetch_paths(self, session) -> List[Dict]:
        result = session.run(_Q_PATHS)
        return [dict(r) for r in result]

    # ── assembly → v2-compatible dict ────────────────────────────────────────

    def _assemble(
        self,
        meta: Dict,
        nodes: List[Dict],
        props_by_node: Dict[str, List[Dict]],
        rels: List[Dict],
        paths: List[Dict],
    ) -> Dict:
        """
        Reassemble the pipeline-compatible schema dict.

        Mirrors semantic_schema_uckg_v2.json keys so that the existing
        build_embedding_corpus() and build_maps() functions work unchanged.
        """

        # ── classes (v2 key) ──────────────────────────────────────────────────
        classes = []
        for n in nodes:
            classes.append({
                "semantic":       n["semantic"],
                # v2 uses a list; in the DB we stored a single string
                "physical_labels": [n["physical_label"]] if n.get("physical_label") else [],
                "description":    n.get("description") or "",
                # bonus fields (ignored by v2 helpers, used for richer prompts)
                "purpose":        n.get("purpose") or "",
                "key_identifier": n.get("key_identifier") or "",
                "key_identifier_example": n.get("key_identifier_example") or "",
                "triggers":       list(n.get("triggers") or []),
            })

        # ── object_properties (v2 key) ────────────────────────────────────────
        object_properties = []
        for r in rels:
            object_properties.append({
                "semantic":    r["semantic"],
                "domain":      r.get("domain_semantic") or "",   # v2 key
                "range":       r.get("range_semantic") or "",    # v2 key
                "physical_rel": r.get("physical_rel") or "",
                "description": r.get("description") or "",
                # bonus fields
                "domain_physical":      r.get("domain_physical") or "",
                "range_physical":       r.get("range_physical") or "",
                "traversal_direction":  r.get("traversal_direction") or "",
                "cypher_pattern":       r.get("cypher_pattern") or "",
                "natural_language_triggers": list(r.get("triggers") or []),
                "example_query":        r.get("example_query") or "",
            })

        # ── data_properties (v2 key) ──────────────────────────────────────────
        # v2 format: {"CVE": ["cveId: label — description.", ...], ...}
        data_properties: Dict[str, List[str]] = {}
        for node_sem, prop_list in props_by_node.items():
            lines = []
            for p in prop_list:
                p_sem   = p.get("prop_semantic") or p.get("semantic") or "property"
                p_phys  = p.get("physical") or p_sem
                p_desc  = p.get("description") or ""
                p_ex    = p.get("example") or ""
                line    = f"{p_sem}: {p_phys} — {p_desc}"
                if p_ex:
                    line += f" (e.g. {p_ex})"
                lines.append(line)
            data_properties[node_sem] = lines

        # ── graph_traversal_paths (bonus, v3-only) ────────────────────────────
        graph_traversal_paths = [
            {
                "name":           p.get("name") or "",
                "description":    p.get("description") or "",
                "cypher_pattern": p.get("cypher_pattern") or "",
                "use_cases":      list(p.get("use_cases") or []),
            }
            for p in paths
        ]

        # ── embedding_corpus: reconstruct from triples + path descriptions ────
        # This supplements whatever build_embedding_corpus() will generate from
        # the structured fields above, giving the pipeline the manually curated
        # natural-language lines that were authored in the v3 JSON.
        embedding_corpus = self._reconstruct_corpus(
            nodes, rels, paths, props_by_node
        )

        return {
            "version":                self._version,
            "source":                 "neo4j",
            "notes":                  meta.get("notes") or "",
            "last_loaded":            meta.get("last_loaded") or "",
            # ── v2-compatible keys (consumed by existing helpers) ────────────
            "classes":                classes,
            "object_properties":      object_properties,
            "data_properties":        data_properties,
            "embedding_corpus":       embedding_corpus,
            # ── v3-only bonus keys ────────────────────────────────────────────
            "nodes":                  nodes,          # raw node dicts
            "relationships":          rels,           # raw rel dicts
            "graph_traversal_paths":  graph_traversal_paths,
        }

    def _reconstruct_corpus(
        self,
        nodes:        List[Dict],
        rels:         List[Dict],
        paths:        List[Dict],
        props_by_node: Dict[str, List[Dict]],
    ) -> List[str]:
        """
        Reconstruct the embedding_corpus list from the structured metadata.
        Produces the same kinds of lines that were manually authored in the v3
        JSON embedding_corpus section, so the vector index stays representative.
        """
        lines: List[str] = []

        # node description lines
        for n in nodes:
            sem  = n.get("semantic") or "Node"
            phys = n.get("physical_label") or ""
            desc = n.get("description") or ""
            ki   = n.get("key_identifier") or ""
            kex  = n.get("key_identifier_example") or ""

            lines.append(f"DESC: {sem} ({phys}) — {desc}")
            if ki:
                lines.append(f"{sem} identified by {ki} property" +
                              (f" (e.g. {kex})" if kex else ""))
            for trig in (n.get("triggers") or []):
                lines.append(f"{sem} query trigger: {trig}")

        # property lines
        for node_sem, prop_list in props_by_node.items():
            for p in prop_list:
                p_sem  = p.get("prop_semantic") or p.get("semantic") or "property"
                p_phys = p.get("physical") or p_sem
                p_desc = p.get("description") or ""
                p_ex   = p.get("example") or ""
                lines.append(
                    f"{node_sem} has {p_sem} ({p_phys}): {p_desc}" +
                    (f" e.g. {p_ex}" if p_ex else "")
                )
                # include query_pattern as a corpus hint
                qp = p.get("query_pattern") or ""
                if qp:
                    lines.append(f"Cypher for {node_sem}.{p_sem}: {qp}")

        # relationship triple lines
        for r in rels:
            sem  = r.get("semantic") or "rel"
            phys = r.get("physical_rel") or ""
            dsem = r.get("domain_semantic") or ""
            rsem = r.get("range_semantic") or ""
            desc = r.get("description") or ""
            cpat = r.get("cypher_pattern") or ""
            ex_q = r.get("example_query") or ""

            lines.append(
                f"{dsem} {sem} {rsem} — physical: {phys} — {desc}"
            )
            if cpat:
                lines.append(f"Cypher pattern: {cpat}")
            if ex_q:
                lines.append(f"Example: {ex_q}")
            for trig in (r.get("triggers") or []):
                lines.append(f"Relationship trigger: {trig}")

        # traversal path lines
        for path in paths:
            name  = path.get("name") or ""
            pdesc = path.get("description") or ""
            cpat  = path.get("cypher_pattern") or ""
            cases = path.get("use_cases") or []

            lines.append(f"PATH: {name} — {pdesc}")
            if cpat:
                lines.append(f"PATH Cypher: {cpat}")
            for uc in cases:
                lines.append(f"Use case: {uc}")

        # de-duplicate while preserving order
        seen: set = set()
        deduped: List[str] = []
        for line in lines:
            s = str(line).strip()
            if s and s not in seen:
                seen.add(s)
                deduped.append(s)

        return deduped

    # ── cache helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _try_load_cache(cache_path: str, max_age_hours: float) -> Optional[Dict]:
        p = Path(cache_path)
        if not p.exists():
            return None
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
        age_h = (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 3600
        if age_h > max_age_hours:
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            # only use cache if it came from Neo4j
            if data.get("source") == "neo4j":
                return data
        except Exception:
            pass
        return None

    @staticmethod
    def _write_cache(cache_path: str, schema: Dict) -> None:
        p = Path(cache_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2, default=str)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function — drop-in replacement for load_semantic_schema()
# ─────────────────────────────────────────────────────────────────────────────

def load_semantic_schema_from_neo4j(
    uri:      str = "bolt://localhost:7687",
    user:     str = "neo4j",
    password: str = "abcd90909090",
    version:  str = "v3",
    cache_path: Optional[str] = None,
    max_age_hours: float = 0,
) -> Dict:
    """
    Convenience wrapper: extract semantic schema from Neo4j and return it.

    Exact drop-in for load_semantic_schema() in t2css_enhanced.py:

        schema = load_semantic_schema_from_neo4j()
        corpus = build_embedding_corpus(schema)
        label_map, rel_map = build_maps(schema)
    """
    extractor = SemanticSchemaExtractor(uri, user, password, version)
    try:
        return extractor.extract(cache_path=cache_path,
                                 max_age_hours=max_age_hours)
    finally:
        extractor.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI — mirror the schema_extract.py pattern
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(schema: Dict) -> None:
    classes    = schema.get("classes", [])
    obj_props  = schema.get("object_properties", [])
    data_props = schema.get("data_properties", {})
    corpus     = schema.get("embedding_corpus", [])
    paths      = schema.get("graph_traversal_paths", [])

    total_dp = sum(len(v) for v in data_props.values())

    print("\n─────────────────────────────────────────────────────────")
    print(f"  UCKG Semantic Schema  (source=neo4j  version={schema.get('version')})")
    print("─────────────────────────────────────────────────────────")
    print(f"  Node types (classes)     : {len(classes)}")
    print(f"  Relationship triples     : {len(obj_props)}")
    print(f"  Data-property lines      : {total_dp}")
    print(f"  Embedding corpus lines   : {len(corpus)}")
    print(f"  Traversal paths          : {len(paths)}")
    print("─────────────────────────────────────────────────────────")
    print()
    print("  Node types:")
    for c in classes:
        phys = (c.get("physical_labels") or ["?"])[0]
        print(f"    {c['semantic']:<22} → {phys}")
    print()
    print("  Relationship triples:")
    for r in obj_props:
        print(f"    {r['domain']:<18} -[{r['semantic']}]-> {r['range']}")
        print(f"      [{r['physical_rel']}]")
    print("─────────────────────────────────────────────────────────\n")


def main() -> None:
    import argparse, sys

    p = argparse.ArgumentParser(
        description="Extract UCKG semantic schema from Neo4j UCKGMeta_* nodes"
    )
    p.add_argument("--uri",      default="bolt://localhost:7687")
    p.add_argument("--user",     default="neo4j")
    p.add_argument("--password", default="abcd90909090")
    p.add_argument("--version",  default="v3")
    p.add_argument(
        "--out", default=None,
        help="Optional JSON output path (default: print summary only)"
    )
    p.add_argument(
        "--cache-hours", type=float, default=0,
        help="Re-use --out cache if younger than N hours (0=always re-fetch)"
    )
    args = p.parse_args()

    print(f"🔌  Connecting to Neo4j at {args.uri} …")
    try:
        schema = load_semantic_schema_from_neo4j(
            uri           = args.uri,
            user          = args.user,
            password      = args.password,
            version       = args.version,
            cache_path    = args.out,
            max_age_hours = args.cache_hours,
        )
    except RuntimeError as exc:
        print(f"\n❌  {exc}")
        sys.exit(1)

    _print_summary(schema)

    if args.out:
        print(f"✅  Schema written to: {args.out}")
    else:
        print("💡  Use --out PATH to save the schema to a JSON file.")


if __name__ == "__main__":
    main()
