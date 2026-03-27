# UCKG Semantic Schema — Loading & Querying Guide

This guide covers the **two workflows actually used** to load the semantic schema
into Neo4j and query it back out.

---

## Overview

The semantic schema is defined once in `schema/semantic_schema_uckg_v3.json`.
From that JSON a static Cypher file is generated and either:

- **loaded automatically** when the Neo4j Docker container first boots, or
- **loaded manually** via the Python driver when the container is already running.

At runtime Neo4j holds the schema as `UCKGMeta_*` nodes and edges. Any tool that
needs it queries Neo4j directly — the JSON is never read at runtime.

---

## Workflow 1 — Auto-load on `docker compose up` (recommended)

### When to use
Fresh environment, first-time setup, or after editing the schema JSON.

### Step 1 — Generate the static Cypher file

Run this once (or every time `semantic_schema_uckg_v3.json` changes):

```bash
cd /path/to/UCKG
python3 schema/generate_schema_cypher.py
```

Output: `neo4j/import/uckg_semantic_schema.cypher`  
This file is already mounted into the container via the existing Docker volume.

### Step 2 — Start the stack

```bash
docker compose up
```

On first boot, Neo4j's APOC initializer runs `neo4j/import/init.cypher`, which
ends with:

```cypher
CALL apoc.cypher.runFile('uckg_semantic_schema.cypher') YIELD row, result RETURN row, result;
```

All `UCKGMeta_*` nodes and edges are created before any service queries the DB.

> **The JSON file is never read at runtime.**  
> Only `uckg_semantic_schema.cypher` is needed once the Cypher file has been
> generated and committed.

> **Subsequent boots:** the MERGE statements in the Cypher file are idempotent —
> running them again updates existing nodes rather than creating duplicates.

---

## Workflow 2 — Manual load with Python driver

### When to use
Neo4j is already running and you need to push a schema update without restarting.

```bash
python3 schema/neo4j_schema_loader.py
```

The script reads `schema/semantic_schema_uckg_v3.json` and merges all
`UCKGMeta_*` nodes and edges using `MERGE` (safe to re-run at any time).

Default connection: `bolt://localhost:7687`, user `neo4j`.  
Override with `--uri`, `--user`, `--password` flags if needed.

---

## Verifying the load

Run these in Neo4j Browser or via `cypher-shell`:

```cypher
// 1. Health check — confirm schema version and load time
MATCH (s:UCKGMeta_Schema)
RETURN s.version, s.last_loaded;

// 2. Count all metadata nodes by type
MATCH (n)
WHERE any(l IN labels(n) WHERE l STARTS WITH 'UCKGMeta')
RETURN labels(n)[1] AS type, count(n) AS total
ORDER BY total DESC;

// 3. List all node types with purpose
MATCH (s:UCKGMeta_Schema)-[:META_HAS_NODE]->(n:UCKGMeta_Node)
RETURN n.semantic AS name, n.physical_label AS label, n.purpose AS purpose
ORDER BY n.semantic;

// 4. List all relationships with source → target and description
MATCH (s:UCKGMeta_Schema)-[:META_HAS_RELATIONSHIP]->(r:UCKGMeta_Relationship)
RETURN r.source_node_semantic AS source,
       r.semantic             AS rel,
       r.target_node_semantic AS target,
       r.description          AS description
ORDER BY r.source_node_semantic;

// 5. List all properties for a specific node type (e.g. CVE)
MATCH (n:UCKGMeta_Node {semantic:'CVE'})-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)
RETURN p.semantic AS property,
       p.physical AS physical_key,
       p.type     AS type,
       p.description AS description;

// 6. Traverse the schema graph — which nodes are reachable from CVE in ≤2 hops?
MATCH (a:UCKGMeta_Node {semantic:'CVE'})-[:META_CONNECTS_TO*1..2]->(b:UCKGMeta_Node)
RETURN DISTINCT a.semantic AS from, b.semantic AS to;
```

---

## Extracting the schema from Neo4j

To pull the live schema back out as a JSON (e.g. to regenerate a cache or inspect
what is actually stored):

```bash
python3 schema/neo4j_semantic_extractor.py \
  --out schema/semantic_schema_neo4j_cache.json
```

---

## File map

```
schema/
├── semantic_schema_uckg_v3.json      ← source of truth (edit this)
├── generate_schema_cypher.py         ← JSON → static Cypher
├── neo4j_schema_loader.py            ← Python driver loader
├── neo4j_semantic_extractor.py       ← pull schema back from Neo4j
└── SCHEMA_LOADING_GUIDE.md           ← this file

neo4j/import/
├── init.cypher                       ← Docker init hook (patched)
└── uckg_semantic_schema.cypher       ← generated static Cypher (committed)
```
