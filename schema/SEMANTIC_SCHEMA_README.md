# UCKG Semantic Schema — Workflow & Design Reference

> **Version**: v3  
> **Module**: `schema/semantic_schema.py`  
> **Source of truth**: `schema/semantic_schema.cypher` → Neo4j `UCKGMeta_*` nodes

---

## Table of Contents

1. [What is the semantic schema?](#1-what-is-the-semantic-schema)
2. [Architecture overview](#2-architecture-overview)
3. [What lives in Neo4j](#3-what-lives-in-neo4j)
4. [What each metadata node contains](#4-what-each-metadata-node-contains)
5. [The `nl_template` mechanism](#5-the-nl_template-mechanism)
6. [Covered nodes (14)](#6-covered-nodes-14)
7. [Covered relationships (16)](#7-covered-relationships-16)
8. [Covered traversal paths (7)](#8-covered-traversal-paths-7)
9. [Loading the schema into Neo4j](#9-loading-the-schema-into-neo4j)
10. [Extracting the schema from Neo4j](#10-extracting-the-schema-from-neo4j)
11. [Generating natural-language instance descriptions](#11-generating-natural-language-instance-descriptions)
12. [Querying the metadata directly](#12-querying-the-metadata-directly)
13. [Single module design (`semantic_schema.py`)](#13-single-module-design-semantic_schemapy)
14. [File inventory](#14-file-inventory)
15. [Design decisions](#15-design-decisions)

---

## 1. What is the semantic schema?

The **physical schema** of a graph database answers: *what labels and relationship types exist?*

The **semantic schema** answers deeper questions:

| Question | Physical schema | Semantic schema |
|---|---|---|
| What labels exist? | ✅ | ✅ |
| What property keys exist? | ✅ | ✅ |
| What does each label *mean*? | ❌ | ✅ |
| Which property is the primary identifier? | ❌ | ✅ |
| What are example property values? | ❌ | ✅ |
| What does a relationship between two nodes *mean*? | ❌ | ✅ |
| Which nodes can I reach in 2–3 hops? | ❌ | ✅ |
| How do I describe a graph instance in English? | ❌ | ✅ (`nl_template`) |

The semantic schema is embedded **inside Neo4j** as `UCKGMeta_*` metadata nodes — the same database that holds the data.  
Any Cypher-capable tool can read it. No external files required at runtime.

---

## 2. Architecture overview

```
  ┌─────────────────────────────────────────────────────────────┐
  │  AUTHOR TIME  (developer writes once)                        │
  │                                                              │
  │   semantic_schema.cypher                                     │
  │   ┌────────────────────────────────────────────────────┐    │
  │   │ MERGE (n:UCKGMeta_Node {semantic:'CVE'})           │    │
  │   │ SET n.nl_template = '{ID}, which is a              │    │
  │   │                      vulnerability'                │    │
  │   │                                                    │    │
  │   │ MERGE (r:UCKGMeta_Relationship {semantic:'hasCPE'})│    │
  │   │ SET r.nl_template = '{SRC_ID}, which is a          │    │
  │   │     vulnerability, has a CPE, {TGT_ID}, which is   │    │
  │   │     a software platform titled "{TGT_LABEL}".'     │    │
  │   └────────────────────────────────────────────────────┘    │
  │                          │                                   │
  │                          ▼                                   │
  │   semantic_schema.py update()                                │
  │   Executes Cypher → creates UCKGMeta_* nodes in Neo4j       │
  │                                                              │
  └──────────────────────────┬──────────────────────────────────┘
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  EXTRACT TIME  (automated, on demand)                        │
  │                                                              │
  │   extract_schema(type="json", output="schema.json")         │
  │   → Queries UCKGMeta_* nodes → exports structured file      │
  │                                                              │
  │   extract_text(node="all", relation="all", limit=20)        │
  │   → Reads nl_templates from Neo4j                           │
  │   → Queries real data nodes/edges                           │
  │   → Fills templates → natural-language sentences             │
  │                                                              │
  └─────────────────────────────────────────────────────────────┘
```

**The developer only writes templates once in `semantic_schema.cypher`.**  
Everything else — loading, exporting, sentence generation — is automated by `semantic_schema.py`.

---

## 3. What lives in Neo4j

```
Neo4j Database
│
├── DATA LAYER  (the actual knowledge graph)
│   ├── 200K+ UcoCVE nodes
│   ├── 100K+ UcoexCPE nodes
│   ├── 900+ UcoCWE nodes
│   ├── ...  (14 node types, 16 relationship types)
│   └── Total: ~500K+ nodes, ~1M+ edges
│
└── METADATA LAYER  (semantic descriptions — the semantic schema)
    ├──  1   UCKGMeta_Schema          version / root node
    ├── 14   UCKGMeta_Node            one per entity type
    ├── 81   UCKGMeta_Property        one per property per entity type
    ├── 16   UCKGMeta_Relationship    one per relationship type
    ├──  7   UCKGMeta_TraversalPath   documented multi-hop patterns
    ├── 16   META_CONNECTS_TO         schema-level topology edges
    └── nl_template on every Node and Relationship metadata node
```

### Metadata graph layout

```
(:UCKGMeta_Schema {version, notes, last_loaded})
    │
    ├──[:META_HAS_NODE]──────────► (:UCKGMeta_Node)
    │                               {semantic, physical_label, purpose,
    │                                description, key_identifier,
    │                                nl_template, triggers}
    │                                    │
    │                             [:META_HAS_PROPERTY]
    │                                    ▼
    │                               (:UCKGMeta_Property)
    │                               {semantic, belongs_to, physical,
    │                                type, description, example,
    │                                query_pattern}
    │
    ├──[:META_HAS_RELATIONSHIP]──► (:UCKGMeta_Relationship)
    │                               {semantic, physical_rel,
    │                                source_node_semantic/physical,
    │                                target_node_semantic/physical,
    │                                description, nl_template,
    │                                cypher_pattern, triggers,
    │                                example_query}
    │
    └──[:META_HAS_PATH]──────────► (:UCKGMeta_TraversalPath)
                                    {name, description,
                                     cypher_pattern, use_cases}

(:UCKGMeta_Node)──[:META_CONNECTS_TO {via_semantic, via_physical}]──►(:UCKGMeta_Node)
```

The `META_CONNECTS_TO` edges reproduce the **relationship topology** at the schema level,
so the metadata itself is a traversable graph.

---

## 4. What each metadata node contains

### UCKGMeta_Node (example: CVE)

| Property | Value |
|---|---|
| `semantic` | `"CVE"` |
| `physical_label` | `"UcoCVE"` |
| `purpose` | `"Canonical CVE disclosure entry. Primary vulnerability identifier node."` |
| `description` | `"A CVE node identifies a specific publicly known vulnerability..."` |
| `key_identifier` | `"label"` |
| `key_identifier_example` | `"CVE-2021-44228"` |
| **`nl_template`** | **`"{ID}, which is a vulnerability"`** |
| `triggers` | `["find CVE", "vulnerability identifier", "CVE score", ...]` |

### UCKGMeta_Relationship (example: hasCPE)

| Property | Value |
|---|---|
| `semantic` | `"hasCPE"` |
| `physical_rel` | `"UCOEXHASCPE"` |
| `source_node_semantic` | `"CVE"` |
| `source_node_physical` | `"UcoCVE"` |
| `target_node_semantic` | `"CPE"` |
| `target_node_physical` | `"UcoexCPE"` |
| `description` | `"Connects a CVE to the platform versions it affects..."` |
| **`nl_template`** | **`"{SRC_ID}, which is a vulnerability, has a CPE, {TGT_ID}, which is a software platform titled \"{TGT_LABEL}\"."`** |
| `cypher_pattern` | `"MATCH (c:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE)"` |
| `triggers` | `["affected platform", "which CPE", ...]` |
| `example_query` | `"MATCH (c:UcoCVE {label:'CVE-2021-44228'})-[:UCOEXHASCPE]->(cpe) RETURN cpe.cpeName"` |

### UCKGMeta_Property (example: baseSeverity on CVE)

| Property | Value |
|---|---|
| `semantic` | `"baseSeverity"` |
| `belongs_to` | `"CVE"` |
| `physical` | `"ucobaseSeverity"` |
| `type` | `"string"` |
| `description` | `"CVSS v3 base severity label (LOW / MEDIUM / HIGH / CRITICAL)"` |
| `example` | `"CRITICAL"` |
| `query_pattern` | `"WHERE n.ucobaseSeverity = 'CRITICAL'"` |

---

## 5. The `nl_template` mechanism

Every `UCKGMeta_Node` and `UCKGMeta_Relationship` carries an **`nl_template`** — a sentence pattern with placeholder variables that can be filled with real data at runtime.

### Node templates (describe a single entity)

| Node type | nl_template |
|---|---|
| CVE | `"{ID}, which is a vulnerability"` |
| Weakness | `"{ID}, which is a software weakness"` |
| Group | `"{ID}, which is a threat actor group"` |
| Technique | `"{ID}, which is an adversary technique"` |
| Software | `"{ID}, which is a threat software tool"` |
| Mitigation | `"{ID}, which is a security mitigation"` |
| Campaign | `"{ID}, which is a threat campaign"` |
| CPE | `"{ID}, which is a software platform"` |

### Relationship templates (describe a connection between two entities)

| Relationship | nl_template |
|---|---|
| hasCPE | `"{SRC_ID}, which is a vulnerability, has a CPE, {TGT_ID}, which is a software platform titled \"{TGT_LABEL}\"."` |
| attributedTo | `"Campaign {SRC_ID} is attributed to threat group {TGT_ID}."` |
| groupUsesTechnique | `"Threat group {SRC_ID} employs the adversary technique {TGT_ID}."` |
| hasRelatedWeakness | `"Attack pattern {SRC_ID} exploits the weakness {TGT_ID}, which is a {TGT_LABEL}."` |
| mitigates | `"Security mitigation {SRC_ID} reduces the effectiveness of technique {TGT_ID}."` |

### Template variables

| Variable | Replaced with at runtime | Source |
|---|---|---|
| `{ID}` | Node's key identifier value | e.g. `n.label` → `"CVE-2021-44228"` |
| `{SRC_ID}` | Source node's key identifier | e.g. `src.label` → `"CVE-2021-44228"` |
| `{SRC_LABEL}` | Source node's human-readable name | e.g. `src.ucoexNAME` |
| `{TGT_ID}` | Target node's key identifier | e.g. `tgt.cpeName` → `"cpe:/a:apache:log4j:2.14.1"` |
| `{TGT_LABEL}` | Target node's human-readable name | e.g. `tgt.label` → `"Apache Log4j 2.14.1"` |

The `key_identifier` field on each `UCKGMeta_Node` tells the system **which Neo4j property** to read for `{ID}`, `{SRC_ID}`, or `{TGT_ID}`. This is how the system dynamically builds Cypher queries from metadata — no hardcoding.

---

## 6. Covered nodes (14)

| Semantic name | Physical label | Key identifier | Example value |
|---|---|---|---|
| CVE | UcoCVE | `label` | CVE-2021-44228 |
| Vulnerability | UcoVulnerability | `uri` | http://uckg.org/vulnerability/… |
| Weakness | UcoCWE | `ucocweID` | CWE-79 |
| ExploitTarget | UcoExploitTarget | `uri` | http://uckg.org/exploittarget/… |
| Campaign | UcoexCAMPAIGNS | `ucoexNAME` | Operation Wocao |
| Group | UcoexGROUPS | `ucoexNAME` | APT29 |
| Technique | UcoexMITREATTACK | `ucoexNAME` | Phishing |
| Tactic | UcoexTACTICS | `ucoexNAME` | Initial Access |
| Software | UcoexSOFTWARE | `ucoexNAME` | Mimikatz |
| Mitigation | UcoexMITIGATIONS | `ucoexNAME` | Multi-factor Authentication |
| AttackPattern | UcoexCAPEC | `ucoexCAPEC_id` | CAPEC-66 |
| D3FENDControl | UcoexMITRED3FEND | `ucoexMITRED3FEND_LABEL` | Network Traffic Filtering |
| ObservedExample | UcoexObservedExample | `uri` | http://uckg.org/observedexample/… |
| CPE | UcoexCPE | `cpeName` | cpe:/a:apache:log4j:2.14.1 |

---

## 7. Covered relationships (16)

```
Source             Relationship                      Target
───────────────    ────────────────────────────────   ──────────────
CVE                -[UCOEXHASCPE]->                  CPE
Weakness           -[UCOHASOBSERVEDEXAMPLE]->         ObservedExample
ExploitTarget      -[UCOHASVULNERABILITY]->           Vulnerability
ExploitTarget      -[UCOHASWEAKNESS]->                Weakness
Vulnerability      -[UCOHASCVE_ID]->                  CVE
Campaign           -[UCOEXATTRIBUTEDTO]->             Group
Campaign           -[UCOEXCAMPAIGNUSESSOFTWARE]->     Software
Campaign           -[UCOEXCAMPAIGNUSESTECHNIQUE]->    Technique
AttackPattern      -[UCOEXHASRELATEDWEAKNESS]->       Weakness
AttackPattern      -[UCOEXHASTAXONOMYMAPPING]->       Technique
Group              -[UCOEXGROUPUSESSOFTWARE]->        Software
Group              -[UCOEXGROUPUSESTECHNIQUE]->       Technique
Mitigation         -[UCOEXMITIGATES]->                Technique
D3FENDControl      -[UCOEXHASMITREATTACK]->           Technique
ObservedExample    -[UCOEXEXAMPLEOBSERVEDIN]->        CVE
Software           -[UCOEXSOFTWAREUSESTECHNIQUE]->    Technique
```

Each relationship has a full `nl_template`, `description`, `cypher_pattern`, `triggers`, and `example_query` stored in its `UCKGMeta_Relationship` node.

---

## 8. Covered traversal paths (7)

| Path name | Hops | Pattern summary |
|---|---|---|
| CWE to CVE (full chain) | 4 | CWE ← ExploitTarget → Vulnerability → CVE |
| CVE to affected platforms | 1 | CVE → CPE |
| CVE to weakness (reverse) | 4 | CVE ← Vulnerability ← ExploitTarget → CWE |
| CWE to ATT&CK techniques (via CAPEC) | 3 | CWE ← CAPEC → Technique |
| Group full TTP profile | 1–3 | Group → Technique, Software; Campaign → Group |
| Technique to mitigations and D3FEND | 1–2 | Technique ← Mitigation; Technique ← D3FEND |
| CWE observed examples to CVE evidence | 2 | CWE → ObservedExample → CVE |

Each path includes a `cypher_pattern` and `use_cases` list stored in its `UCKGMeta_TraversalPath` node.

---

## 9. Loading the schema into Neo4j

There are two methods — both execute the same MERGE statements and are idempotent.

### Method 1 — Docker auto-load (recommended for fresh environments)

On container startup, Neo4j's APOC initializer runs `neo4j/import/init.cypher`, which includes:

```cypher
CALL apoc.cypher.runFile('uckg_semantic_schema.cypher')
  YIELD row, result RETURN row, result;
```

All `UCKGMeta_*` nodes and edges are created before any service queries the database.

```bash
docker compose up
```

> Subsequent boots: MERGE statements update existing nodes — no duplicates.

### Method 2 — Python driver (recommended for live updates)

When Neo4j is already running and you need to push schema changes without restarting:

```bash
python3 schema/semantic_schema.py update
```

This reads `schema/semantic_schema.cypher` and executes each statement via the Neo4j Python driver.

```python
# Programmatic usage
from schema.semantic_schema import update
update()                                             # defaults
update("schema/semantic_schema.cypher", uri="bolt://neo4j:7687")  # custom
```

### Verifying the load

```cypher
-- Health check
MATCH (s:UCKGMeta_Schema) RETURN s.version, s.last_loaded;

-- Count metadata nodes by type
MATCH (n)
WHERE any(l IN labels(n) WHERE l STARTS WITH 'UCKGMeta')
RETURN labels(n)[1] AS type, count(n) AS total
ORDER BY total DESC;

-- Expected: Schema=1, Node=14, Property=81, Relationship=16, TraversalPath=7
```

---

## 10. Extracting the schema from Neo4j

Pull the live semantic schema from Neo4j and export it as a structured file:

```bash
# Export as JSON
python3 schema/semantic_schema.py extract-schema --type json --output schema/schema.json

# Export as Turtle RDF
python3 schema/semantic_schema.py extract-schema --type ttl --output schema/schema.ttl
```

```python
# Programmatic usage — returns a dict without writing a file
from schema.semantic_schema import extract_schema

schema = extract_schema()                                 # in memory
extract_schema(type="json", output="schema/schema.json")  # write to file
extract_schema(type="ttl",  output="schema/schema.ttl")   # RDF format
```

The returned dict has this structure:

```
{
    "version":               "v3",
    "source":                "neo4j",
    "classes":               [...],    # 14 node type entries
    "object_properties":     [...],    # 16 relationship entries
    "data_properties":       {...},    # properties keyed by node
    "graph_traversal_paths": [...]     # 7 multi-hop patterns
}
```

---

## 11. Generating natural-language instance descriptions

`extract_text()` is the core function that turns abstract `nl_template` patterns into
**grounded English sentences** by filling them with real graph data.

### How it works

```
Step 1 — Read metadata from Neo4j
    MATCH (r:UCKGMeta_Relationship {semantic:'hasCPE'})
    RETURN r.nl_template, r.source_node_physical, r.target_node_physical

    Also fetch key_identifier for each side:
      CVE  → key_identifier = "label"
      CPE  → key_identifier = "cpeName"

Step 2 — Dynamically build a data query from metadata
    MATCH (src:UcoCVE)-[:UCOEXHASCPE]->(tgt:UcoexCPE)
    RETURN src.label   AS src_id,
           tgt.cpeName AS tgt_id,
           tgt.label   AS tgt_label
    LIMIT 20

Step 3 — Fill the template for each row
    _fill_nl_template(
        template = "{SRC_ID}, which is a vulnerability, has a CPE,
                    {TGT_ID}, which is a software platform titled
                    \"{TGT_LABEL}\".",
        src = {"id": "CVE-2021-44228"},
        tgt = {"id": "cpe:/a:apache:log4j:2.14.1",
               "label": "Apache Log4j 2.14.1"}
    )

    OUTPUT:
    "CVE-2021-44228, which is a vulnerability, has a CPE,
     cpe:/a:apache:log4j:2.14.1, which is a software platform
     titled "Apache Log4j 2.14.1"."

Step 4 — Repeat for all 16 relationship types + 14 node types
    → ~740 grounded NL sentences (balanced: ~20 per type)
```

### Example output

**Node descriptions:**
```
CVE-2021-44228, which is a vulnerability
CWE-79, which is a software weakness
APT29, which is a threat actor group
Mimikatz, which is a threat software tool
```

**Edge descriptions:**
```
CVE-2021-44228, which is a vulnerability, has a CPE,
cpe:/a:apache:log4j:2.14.1, which is a software platform
titled "Apache Log4j 2.14.1".

CWE-79, which is a software weakness, has an observed
real-world exploitation example: "Cross-site scripting
vulnerability in ..."

Threat group APT29 employs the adversary technique Phishing.

Campaign Operation Wocao is attributed to threat group APT20.

Security mitigation Multi-factor Authentication reduces
the effectiveness of technique Valid Accounts.
```

### Usage

```bash
# Generate NL sentences for everything (20 per type)
python3 schema/semantic_schema.py extract-text --limit 20 --output corpus.txt

# Generate only CVE-related sentences
python3 schema/semantic_schema.py extract-text --node CVE --relation hasCPE --limit 50

# Generate only relationship descriptions
python3 schema/semantic_schema.py extract-text --node none --relation all --output edges.txt
```

```python
# Programmatic usage
from schema.semantic_schema import extract_text

# All types, balanced, 20 instances each
sentences = extract_text(node="all", relation="all", limit=20)

# Specific types
sentences = extract_text(relation="hasCPE", limit=100)

# Write to file
extract_text(node="all", relation="all", output="corpus.txt", limit=20)
```

### Balanced corpus design

The `limit` parameter applies **per type**, not globally:

| Category | Types | × limit | = sentences |
|---|---|---|---|
| Node descriptions | 14 | 20 | 280 |
| Edge descriptions | 16 | 20 | 320 |
| Traversal paths | 7 | 20 | 140 |
| **Total** | | | **~740** |

This ensures every node type and relationship type has equal representation.

---

## 12. Querying the metadata directly

Because the semantic schema is stored as nodes in Neo4j, it is **browsable and queryable**
by anyone with Neo4j Browser access — no code required.

```cypher
-- What does each node type represent?
MATCH (n:UCKGMeta_Node)
RETURN n.semantic, n.physical_label, n.purpose
ORDER BY n.semantic;

-- All properties of a specific node type
MATCH (n:UCKGMeta_Node {semantic:'CVE'})-[:META_HAS_PROPERTY]->(p)
RETURN p.semantic, p.physical, p.type, p.description, p.example;

-- What relationships connect to a given node type?
MATCH (src:UCKGMeta_Node {semantic:'Group'})-[e:META_CONNECTS_TO]->(tgt)
RETURN e.via_semantic, tgt.semantic, e.via_physical;

-- Which nodes can I reach from CVE in 2 hops?
MATCH (start:UCKGMeta_Node {semantic:'CVE'})
      -[:META_CONNECTS_TO*1..2]->(related:UCKGMeta_Node)
RETURN DISTINCT related.semantic, related.physical_label;

-- Get the NL template for a specific relationship
MATCH (r:UCKGMeta_Relationship {semantic:'hasCPE'})
RETURN r.nl_template, r.source_node_semantic, r.target_node_semantic;

-- Full relationship catalogue with descriptions
MATCH (r:UCKGMeta_Relationship)
RETURN r.source_node_semantic AS source,
       r.semantic             AS rel,
       r.target_node_semantic AS target,
       r.description
ORDER BY r.source_node_semantic;
```

---

## 13. Single module design (`semantic_schema.py`)

All semantic schema operations are consolidated into one module:

```
schema/semantic_schema.py
│
├── update(definition="semantic_schema.cypher")
│   Execute Cypher definitions → create/update metadata in Neo4j.
│   Idempotent: MERGE statements, safe to re-run.
│
├── extract_schema(type="json", output="schema.json")
│   Query UCKGMeta_* nodes → export to JSON or Turtle RDF.
│   Returns dict in memory if output is omitted.
│
└── extract_text(node="all", relation="all", limit=20, output="corpus.txt")
    Read nl_templates + query real data → NL sentences.
    Returns list of strings in memory if output is omitted.
```

### CLI

```bash
# Push definitions to Neo4j
python3 schema/semantic_schema.py update

# Export schema as JSON
python3 schema/semantic_schema.py extract-schema --type json --output schema/schema.json

# Generate NL sentences
python3 schema/semantic_schema.py extract-text --limit 20 --output corpus.txt

# Generate specific subset
python3 schema/semantic_schema.py extract-text --node CVE --relation hasCPE --limit 50
```

### Internal helpers

| Helper | Purpose |
|---|---|
| `_get_driver()` | Create a Neo4j driver connection |
| `_run_cypher_file()` | Split and execute a `.cypher` file |
| `_fetch_node_metadata()` | Query all `UCKGMeta_Node` + properties |
| `_fetch_relationship_metadata()` | Query all `UCKGMeta_Relationship` |
| `_fetch_traversal_paths()` | Query all `UCKGMeta_TraversalPath` |
| `_schema_to_json()` | Assemble structured dict from metadata |
| `_schema_to_ttl()` | Serialise to Turtle RDF |
| `_fill_nl_template()` | Substitute real data into an nl_template |
| `_generate_node_sentences()` | Query real nodes → fill node templates |
| `_generate_edge_sentences()` | Traverse real edges → fill relationship templates |
| `_generate_path_sentences()` | Execute multi-hop patterns → chain templates |
| `_write_lines()` | Write sentence list to file |

---

## 14. File inventory

```
schema/
├── semantic_schema.cypher           ← SOURCE OF TRUTH: hand-authored Cypher definitions
├── semantic_schema.py               ← single Python module (update / extract / generate)
├── __init__.py                      ← package init
├── schema_cache.txt                 ← physical schema cache (node labels, rels, properties)
├── semantic_schema_uckg_v3.json     ← v3 JSON (reference / bootstrap, not used at runtime)
├── uckg_semantic_schema_v3_for_review.json  ← advisor review copy (no embedding_corpus)
├── uckg_schema_architecture.json    ← advisor-friendly architecture overview
├── schema_embeddings.json           ← pre-computed embeddings (for T2CSS consumer)
├── SEMANTIC_SCHEMA_README.md        ← this file
├── SEMANTIC_SCHEMA_SLIDES.md        ← presentation slides for advisor
└── SCHEMA_LOADING_GUIDE.md          ← step-by-step loading/querying workflows

neo4j/import/
├── init.cypher                      ← Docker init hook (calls uckg_semantic_schema.cypher)
└── uckg_semantic_schema.cypher      ← generated static Cypher for Docker auto-load
```

---

## 15. Design decisions

### Why store the schema in Neo4j?

| Benefit | Detail |
|---|---|
| **Single source of truth** | Lives in the same DB as the data — no separate file to keep in sync |
| **Queryable as a graph** | `MATCH (:UCKGMeta_Node)-[:META_CONNECTS_TO*2]->()` works natively |
| **Tool-independent** | Any Cypher-capable client can read it — no Python, no API |
| **Evolvable** | Add a new node type → update the Cypher file → re-run `update()` |

### Why hand-author `semantic_schema.cypher` instead of generating from JSON?

- **Neo4j is the primary source**, not JSON. The advisor's feedback was explicit: *"We want those descriptions to be in the Neo4j schema first. Then pull automatically by querying."*
- The Cypher file is directly executable, human-readable, and version-controllable.
- JSON exports are *derived* from Neo4j via `extract_schema()`, not the other way around.

### Why `nl_template` instead of pre-written sentences?

- Templates are authored **once per type** (30 templates for 14 nodes + 16 relationships).
- `extract_text()` generates **thousands of sentences** from those 30 templates by filling in real data.
- When the graph data changes, re-running `extract_text()` produces updated sentences — no manual rewriting.

### Why balanced sampling with `limit`?

If the corpus had 500 CVE→CPE sentences but only 10 Campaign→Group sentences, downstream consumers (e.g. embedding-based search) would be biased toward CVE patterns. The `limit` parameter applies per type, ensuring equal representation.

---

*File: `schema/SEMANTIC_SCHEMA_README.md`*
