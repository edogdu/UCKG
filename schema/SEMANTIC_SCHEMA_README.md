# UCKG Semantic Schema — General Reference

The **UCKG Semantic Schema** is a human-authored, machine-readable documentation
layer that describes the **meaning** of every node type, property, and relationship
in the UCKG knowledge graph.

It is **not** tied to any single application. It is a shared KG artifact — analogous
to an ontology or a data dictionary — that any tool, pipeline, or service can read
to understand what the graph contains and how to work with it.

---

## Table of Contents

1. [What is the semantic schema?](#1-what-is-the-semantic-schema)
2. [Who can use it?](#2-who-can-use-it)
3. [Where does it live?](#3-where-does-it-live)
4. [Schema structure (v3)](#4-schema-structure-v3)
5. [Covered nodes (14)](#5-covered-nodes-14)
6. [Covered relationships (16)](#6-covered-relationships-16)
7. [Covered traversal paths (7)](#7-covered-traversal-paths-7)
8. [Storing it in Neo4j as metadata](#8-storing-it-in-neo4j-as-metadata)
9. [Extracting it from Neo4j](#9-extracting-it-from-neo4j)
10. [Consumer: Text-to-Cypher (T2CSS)](#10-consumer-text-to-cypher-t2css)
11. [Consumer: Documentation & Exploration](#11-consumer-documentation--exploration)
12. [Consumer: LLM Agents & RAG Systems](#12-consumer-llm-agents--rag-systems)
13. [Consumer: API & Frontend](#13-consumer-api--frontend)
14. [Consumer: Validation & Governance](#14-consumer-validation--governance)
15. [File inventory](#15-file-inventory)
16. [Quick-start](#16-quick-start)
17. [Neo4j metadata graph layout](#17-neo4j-metadata-graph-layout)
18. [Design decisions](#18-design-decisions)

---

## 1. What is the semantic schema?

The **physical schema** of a graph database answers: *what labels and relationship
types exist?*

The **semantic schema** answers the deeper questions:

| Question | Physical schema | Semantic schema |
|---|---|---|
| What labels exist? | ✅ yes | ✅ yes |
| What property keys exist? | ✅ yes | ✅ yes |
| What does each label _mean_? | ❌ no | ✅ yes |
| Which property is the primary identifier? | ❌ no | ✅ yes |
| What are example property values? | ❌ no | ✅ yes |
| How should I filter by a property in Cypher? | ❌ no | ✅ yes |
| What does a relationship between two nodes _mean_? | ❌ no | ✅ yes |
| Which nodes can I reach in 2–3 hops? | ❌ no | ✅ yes |
| What natural-language phrases map to this node/rel? | ❌ no | ✅ yes |

In the UCKG, the semantic schema lives in:

- **JSON files** (portable, version-controlled, offline-readable)
- **Neo4j itself** (queryable, always in sync with the graph, accessible to any tool)

---

## 2. Who can use it?

```
                    ┌─────────────────────────────────────┐
                    │       UCKG Semantic Schema           │
                    │  configt2c/semantic_schema_uckg_v3   │
                    │         or UCKGMeta_* in Neo4j       │
                    └───────────────┬─────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                          │
          ▼                         ▼                          ▼
  ┌───────────────┐       ┌──────────────────┐      ┌──────────────────┐
  │  Text-to-     │       │  LLM Agents /    │      │  REST API /      │
  │  Cypher       │       │  RAG Systems     │      │  Frontend        │
  │  (T2CSS)      │       │                  │      │                  │
  └───────────────┘       └──────────────────┘      └──────────────────┘
          │                         │                          │
          ▼                         ▼                          ▼
  ┌───────────────┐       ┌──────────────────┐      ┌──────────────────┐
  │  Validation & │       │  Documentation / │      │  Data Pipeline   │
  │  Governance   │       │  KG Exploration  │      │  & ETL Checks    │
  └───────────────┘       └──────────────────┘      └──────────────────┘
```

Every consumer reads the **same source** — the JSON file or the `UCKGMeta_*` nodes
in Neo4j — so they all have a consistent, up-to-date view of the graph's meaning.

---

## 3. Where does it live?

| Location | Format | Use |
|---|---|---|
| `configt2c/semantic_schema_uckg_v3.json` | JSON | Authoring, version control, offline access, bootstrap source |
| `UCKGMeta_*` nodes in Neo4j | Graph nodes/edges | Live queryable metadata, accessible to any Cypher-capable tool |
| (optional) `configt2c/semantic_schema_neo4j_cache.json` | JSON cache | Fast offline reads after an initial Neo4j extraction |

---

## 4. Schema structure (v3)

`configt2c/semantic_schema_uckg_v3.json` has the following top-level keys:

```
semantic_schema_uckg_v3.json
│
├── version                "v3"
├── notes                  free-text: purpose and authoring notes
│
├── nodes[]                14 entries — one per KG entity type
│   ├── semantic                 human name          (e.g. "CVE")
│   ├── physical_label           Neo4j label         (e.g. "UcoCVE")
│   ├── purpose                  one-line purpose
│   ├── description              full semantic description
│   ├── key_identifier           primary lookup property
│   ├── key_identifier_example   concrete example value
│   ├── typical_natural_language_triggers   NL phrases that signal this node
│   └── properties[]             one object per property
│       ├── semantic             human property name
│       ├── physical             actual Neo4j property key
│       ├── type                 data type  (string / datetime / boolean / list)
│       ├── description          what this property stores
│       ├── example              concrete example value
│       └── query_pattern        ready-to-use WHERE/RETURN clause snippet
│
├── relationships[]        16 entries — one per directed relationship triple
│   ├── semantic                 human relationship name
│   ├── physical_rel             Neo4j relationship type
│   ├── source_node_semantic     source node — human name
│   ├── source_node_physical     source node — Neo4j label
│   ├── target_node_semantic     target node — human name
│   ├── target_node_physical     target node — Neo4j label
│   ├── description              what this connection means
│   ├── traversal_direction      "NodeA → NodeB" short arrow description
│   ├── cypher_pattern           MATCH clause template
│   ├── natural_language_triggers   NL phrases that signal this relationship
│   └── example_query            complete working Cypher example
│
├── graph_traversal_paths[] 7 entries — documented multi-hop query recipes
│   ├── name
│   ├── description
│   ├── cypher_pattern
│   └── use_cases[]


---

## 5. Covered nodes (14)

| Semantic name | Physical label | Key identifier | Example value |
|---|---|---|---|
| CVE | UcoCVE | `label` | CVE-2021-44228 |
| Vulnerability | UcoVulnerability | `uri` | urn:uckg:vuln:… |
| Weakness | UcoCWE | `ucocweID` | CWE-79 |
| ExploitTarget | UcoExploitTarget | `uri` | urn:uckg:et:… |
| Campaign | UcoexCAMPAIGNS | `ucoexNAME` | APT29 |
| Group | UcoexGROUPS | `ucoexNAME` | Lazarus Group |
| Technique | UcoexMITREATTACK | `ucoexNAME` | T1059 |
| Tactic | UcoexTACTICS | `ucoexNAME` | Execution |
| Software | UcoexSOFTWARE | `ucoexNAME` | Cobalt Strike |
| Mitigation | UcoexMITIGATIONS | `ucoexNAME` | M1038 |
| AttackPattern | UcoexCAPEC | `ucoexCAPEC_id` | CAPEC-66 |
| D3FENDControl | UcoexMITRED3FEND | `ucoexMITRED3FEND_LABEL` | D3-OTF |
| ObservedExample | UcoexObservedExample | `uri` | urn:uckg:obs:… |
| CPE | UcoexCPE | `cpeName` | cpe:2.3:a:apache:… |

---

## 6. Covered relationships (16)

```
CVE               -[UCOEXHASCPE]->                CPE
Weakness          -[UCOHASOBSERVEDEXAMPLE]->       ObservedExample
ExploitTarget     -[UCOHASVULNERABILITY]->         Vulnerability
ExploitTarget     -[UCOHASWEAKNESS]->              Weakness
Vulnerability     -[UCOHASCVE_ID]->               CVE
Campaign          -[UCOEXATTRIBUTEDTO]->           Group
Campaign          -[UCOEXCAMPAIGNUSESSOFTWARE]->   Software
Campaign          -[UCOEXCAMPAIGNUSESTECHNIQUE]->  Technique
AttackPattern     -[UCOEXHASRELATEDWEAKNESS]->     Weakness
AttackPattern     -[UCOEXHASTAXONOMYMAPPING]->     Technique
Group             -[UCOEXGROUPUSESSOFTWARE]->      Software
Group             -[UCOEXGROUPUSESTECHNIQUE]->     Technique
Mitigation        -[UCOEXMITIGATES]->              Technique
D3FENDControl     -[UCOEXHASMITREATTACK]->         Technique
ObservedExample   -[UCOEXEXAMPLEOBSERVEDIN]->      CVE
Software          -[UCOEXSOFTWAREUSESTECHNIQUE]->  Technique
```

---

## 7. Covered traversal paths (7)

Multi-hop query patterns documented in `graph_traversal_paths[]`:

| Path name | Pattern summary |
|---|---|
| CVE to Weakness (via ExploitTarget) | CVE → Vulnerability → ExploitTarget → CWE |
| CVE to Technique | CVE → Vulnerability → ExploitTarget → CWE → CAPEC → Technique |
| Group to CVE | Group → Technique ← CAPEC ← CWE ← ExploitTarget ← Vulnerability ← CVE |
| Software to CVE | Software → Technique ← CAPEC ← CWE ← ExploitTarget ← Vulnerability ← CVE |
| Mitigation for CVE | CVE → Vulnerability → ExploitTarget → CWE → CAPEC → Technique ← Mitigation |
| D3FEND for CVE | same chain … → Technique ← D3FENDControl |
| Campaign full footprint | Campaign → Group, Software, Technique |

Each entry includes a full Cypher MATCH template and natural-language use-case
examples, making them directly usable by any tool that generates or explains queries.

---

## 8. Storing and querying it in Neo4j

The semantic schema is persisted inside Neo4j as **`UCKGMeta_*` nodes**, making
it queryable via Cypher like any other graph data.

> **See [`SCHEMA_LOADING_GUIDE.md`](SCHEMA_LOADING_GUIDE.md) for the full
> step-by-step loading and querying workflow.**

**In short — two methods are used:**

| Method | When | Command |
|---|---|---|
| **Docker auto-load** | Fresh environment / first boot | `python3 schema/generate_schema_cypher.py` → `docker compose up` |
| **Python driver** | Neo4j already running, push an update | `python3 schema/neo4j_schema_loader.py` |

**To extract the schema back from Neo4j:**

```bash
python3 schema/neo4j_semantic_extractor.py \
  --out schema/semantic_schema_neo4j_cache.json
```

---

## 10. Consumer: Text-to-Cypher (T2CSS)

The **Enhanced T2CSS pipeline** (`core/t2css_enhanced.py`) uses the schema to:

1. Build an **embedding corpus** — one vector per schema "fact"
2. At query time, embed the user question and retrieve the **top-K most similar facts**
3. Inject those facts as a focused schema slice into the LLM prompt

`load_semantic_schema()` is the entry point. It now accepts a `source` parameter:

```python
from core.t2css_enhanced import load_semantic_schema

schema = load_semantic_schema()                    # auto: Neo4j → file fallback
schema = load_semantic_schema(source="neo4j")      # Neo4j only
schema = load_semantic_schema(source="file")       # JSON file only
schema = load_semantic_schema(
    source="neo4j",
    cache_path="configt2c/semantic_schema_neo4j_cache.json",
    cache_max_age_hours=24,
)
```

The pipeline auto-normalises v3 format to the v2-compatible keys that
`build_embedding_corpus()` and `build_maps()` expect.

---

## 11. Consumer: Documentation & Exploration

Because the schema is stored in Neo4j as nodes, it is **browsable and queryable**
by anyone with Neo4j Browser access — no code required.

Useful queries for documentation:

```cypher
-- What does each node type represent?
MATCH (n:UCKGMeta_Node)
RETURN n.semantic, n.physical_label, n.purpose
ORDER BY n.semantic

-- All properties of a specific node type
MATCH (n:UCKGMeta_Node {semantic:'CVE'})-[:META_HAS_PROPERTY]->(p)
RETURN p.semantic, p.physical, p.type, p.description, p.example

-- What relationships connect to a given node type?
MATCH (src:UCKGMeta_Node {semantic:'Group'})-[e:META_CONNECTS_TO]->(tgt)
RETURN e.via_semantic, e.cypher_pattern, tgt.semantic

-- Which nodes can I reach from CVE in 2 hops?
MATCH (start:UCKGMeta_Node {semantic:'CVE'})
      -[:META_CONNECTS_TO*1..2]->(related:UCKGMeta_Node)
RETURN DISTINCT related.semantic, related.physical_label
```

---

## 12. Consumer: LLM Agents & RAG Systems

Any LLM agent or retrieval-augmented generation system that needs to understand the
UCKG graph can use the semantic schema as its context source:

**Option A — Load from Neo4j at agent startup:**
```python
from core.neo4j_semantic_extractor import load_semantic_schema_from_neo4j

schema = load_semantic_schema_from_neo4j()
corpus = schema["embedding_corpus"]   # 70+ ready-to-embed fact strings
```

**Option B — Load from JSON file (no Neo4j connection):**
```python
import json
with open("configt2c/semantic_schema_uckg_v3.json") as f:
    schema = json.load(f)

# Build context for an LLM prompt
for node in schema["nodes"]:
    print(f"{node['semantic']} ({node['physical_label']}): {node['description']}")
```

**Option C — Use the embedding corpus directly** (each line is already a
dense, self-contained fact — ideal for chunking and indexing):

```python
corpus = schema["embedding_corpus"]
# Lines with prefixes:
# CLS| — node class descriptions
# REL| — relationship descriptions
# PROP| — property descriptions
# PATTERN| — query pattern hints
# DESC: — extended node summaries
# PATH: — multi-hop path hints
```

---

## 13. Consumer: API & Frontend

A REST endpoint or GraphQL resolver can expose the semantic schema to frontend
applications without requiring them to understand Neo4j:

```python
# FastAPI example
@app.get("/api/schema/nodes")
async def get_nodes():
    schema = load_semantic_schema_from_neo4j()
    return [
        {
            "id":          n["physical_label"],
            "label":       n["semantic"],
            "description": n["description"],
            "properties":  [
                {"name": p["physical"], "type": p["type"], "description": p["description"]}
                for p in n.get("properties", [])
            ]
        }
        for n in schema["classes"]
    ]

@app.get("/api/schema/relationships")
async def get_relationships():
    schema = load_semantic_schema_from_neo4j()
    return [
        {
            "type":   r["physical_rel"],
            "label":  r["semantic"],
            "from":   r["source_node_physical"],
            "to":     r["target_node_physical"],
            "meaning": r["description"],
            "example": r["example_query"]
        }
        for r in schema["object_properties"]
    ]
```

A frontend schema explorer, knowledge-graph visualiser, or chatbot UI can consume
these endpoints to render a human-friendly view of the graph without embedding any
schema knowledge in the frontend code.

---

## 14. Consumer: Validation & Governance

The semantic schema is an authoritative record of what *should* exist in the UCKG.
It can drive validation and governance workflows:

```python
from core.neo4j_semantic_extractor import load_semantic_schema_from_neo4j

schema   = load_semantic_schema_from_neo4j()
expected = {n["physical_label"] for n in schema["classes"]}

# Compare against physical schema
from shared.schema_extract import SchemaExtractor

extractor = SchemaExtractor(driver)
physical  = extractor.extract()
actual    = set(physical["labels"])

missing  = expected - actual
extra    = actual - expected

if missing:
    print(f"WARNING: labels documented but not in DB: {missing}")
if extra:
    print(f"INFO: labels in DB but not documented: {extra}")
```

Use it in CI to catch undocumented node types added to the graph, or to flag
documented types that have been accidentally dropped.

---

## 15. File inventory

```
qa-engine/text2cypher/
│
├── configt2c/
│   ├── semantic_schema_uckg_v2.json         previous version (kept for reference)
│   └── semantic_schema_uckg_v3.json   ★ NEW  richly authored v3 semantic schema
│
├── core/
│   ├── neo4j_schema_loader.py         ★ NEW  push schema → Neo4j (Method 0)
│   ├── apoc_schema_load.cypher        ★ NEW  push schema via APOC (Method A)
│   ├── generate_schema_cypher.py      ★ NEW  generate static .cypher (Method B)
│   ├── neo4j_semantic_extractor.py    ★ NEW  pull schema ← Neo4j
│   └── t2css_enhanced.py              ★ PATCHED  load_semantic_schema() updated
│
├── main.py                            ★ PATCHED  lifespan auto-bootstrap (Method C)
├── SEMANTIC_SCHEMA_README.md          ★ NEW  this file
│
└── (repo root)/
    └── neo4j/import/init.cypher       ★ PATCHED  Docker init hook (Method D)
```

---

## 16. Quick-start

> **Full step-by-step loading and querying instructions are in
> [`SCHEMA_LOADING_GUIDE.md`](SCHEMA_LOADING_GUIDE.md).**

Two commands cover the common case:

```bash
# 1. Generate static Cypher from the JSON (one-time, or after editing the schema)
python3 schema/generate_schema_cypher.py

# 2. Start the stack — schema loads automatically on first Neo4j boot
docker compose up
```

If Neo4j is already running and you just need to push an update:

```bash
python3 schema/neo4j_schema_loader.py
```

---

## 17. Neo4j metadata graph layout

```
(:UCKGMeta_Schema {version, notes, last_loaded, embedding_corpus_size})
        │
        ├── [:META_HAS_NODE]──────────────► (:UCKGMeta_Node)
        │                                    {semantic, physical_label,
        │                                     purpose, description,
        │                                     key_identifier, triggers}
        │                                           │
        │                                    [:META_HAS_PROPERTY]
        │                                           ▼
        │                                    (:UCKGMeta_Property)
        │                                    {semantic, belongs_to, physical,
        │                                     type, description, example,
        │                                     query_pattern}
        │
        ├── [:META_HAS_RELATIONSHIP]──────► (:UCKGMeta_Relationship)
        │                                    {semantic, physical_rel,
        │                                     source_node_semantic, target_node_semantic,
        │                                     description, cypher_pattern,
        │                                     triggers, example_query}
        │
        └── [:META_HAS_PATH]──────────────► (:UCKGMeta_TraversalPath)
                                             {name, description,
                                              cypher_pattern, use_cases}

(:UCKGMeta_Node) -[:META_CONNECTS_TO {via_semantic, via_physical,
                                       description, cypher_pattern}]->
(:UCKGMeta_Node)
```

The `META_CONNECTS_TO` edges reproduce the **relationship topology** of the UCKG
at the schema level, so the metadata itself is a traversable graph — you can use
Cypher path queries on the schema just as you would on the data.

---

## 18. Design decisions

### Why a general-purpose schema, not a T2CSS-specific config?

A T2CSS-specific schema config would need to be duplicated and kept in sync for
every other tool that needs to understand the graph (API, agents, validators,
frontends). A shared artifact avoids drift and makes every consumer authoritative.

### Why store in Neo4j at all?

| Benefit | Detail |
|---|---|
| **Single source of truth** | Lives in the same DB as the data — no separate file to keep in sync |
| **Queryable as a graph** | `MATCH (:UCKGMeta_Node)-[:META_CONNECTS_TO*2]->()` works |
| **Tool-independent** | Any Cypher-capable client can read it — no Python, no API |
| **Evolvable** | Add a new node type to the DB → update the metadata → all consumers see it |

### Why keep the JSON file too?

- **Bootstrap**: something must exist before Neo4j is running
- **Offline development**: no DB connection needed for local testing
- **Version control**: human-readable diffs for schema changes
- **Fallback**: `source="auto"` falls back to JSON if Neo4j is unavailable

### Why reconstruct the embedding corpus in the extractor?

The `UCKGMeta_Property`, `UCKGMeta_Node`, and `UCKGMeta_Relationship` nodes contain
all the information the corpus needs. Reconstructing it from structured data keeps
it perfectly in sync with the metadata — no second copy to maintain. The
reconstruction in `_reconstruct_corpus()` is deterministic and fast (< 1 ms).

---

*File: `schema/SEMANTIC_SCHEMA_README.md`*
