# Core Text-to-Cypher (T2C) Pipelines

This folder contains the **core implementation** of UCKG’s Text→Cypher pipelines.
If you’re looking for “how the enhanced pipeline works”, start with `t2css_enhanced.py`.

> Note: There is also a higher-level overview in `qa-engine/text2cypher/README.md`.

## What “Enhanced T2CSS” means

**Enhanced T2CSS** is a Text→Cypher pipeline that reduces schema confusion by:

- **Semantic schema retrieval**: only the most relevant schema snippets are shown to the LLM (top‑K).
- **Bilingual schema rendering**: semantic concepts are rendered alongside the physical Neo4j labels/relationships.
- **Intent-aware prompting**: the question is classified into one of 9 query categories and gets:
  - a **clause scaffold** (query shape/template),
  - **dynamic rules** (global + intent-specific + micro-rules),
  - **dynamic few-shot examples** (top‑K examples chosen by similarity).

The end goal is to produce a Cypher query that is both **valid** (schema-adherent) and **correct** (returns the same result set as the gold query).

## Key files (what to read first)

- **`t2css_enhanced.py`**
  - Main enhanced pipeline implementation (`EnhancedT2CSSPipeline`).
  - Uses **Ollama embeddings** + dynamic rules + dynamic few-shot selection.

- **`dynamic_rules.py`**
  - Intent + feature detection → selects the rule bundle used in prompting.

- **`embeddings.py`**
  - `OllamaEmbeddings` wrapper for generating embeddings (used for schema + few-shot retrieval).

- **`t2css_integration.py`**
  - Wraps the “classic” `Text2Cypher` interface to enable semantic schema filtering in the prompt builder.

- **`text2cypher.py`**
  - Baseline “full schema” Text→Cypher pipeline and the shared interface:
    - `text_to_cypher(question, ..., skip_validation=True|False)`

- **`t2css_pipeline.py`**
  - Earlier/standard semantic schema filtering pipeline (less “enhanced” than `t2css_enhanced.py`).

- **`t2css_new.py`**
  - Older experimental version (SentenceTransformer-based) from which parts were folded into the enhanced pipeline.

## Enhanced pipeline flow (step-by-step)

At a high level, `EnhancedT2CSSPipeline.generate_cypher()` does:

1. **Normalize IDs** (CVE/CAPEC/T-technique formats) to reduce string mismatch.
2. **Classify intent** into one of 9 categories (node lookup, relationship traversal, multi-hop, aggregation, …).
3. **Select dynamic rules** (global rules + intent rules + micro-rules based on detected features).
4. **Retrieve schema slice**:
   - Embed the question
   - Score against the semantic schema corpus
   - Apply small bonuses (keyword/type)
   - Select **top‑K** schema lines
5. **Bilingualize schema** (semantic concept → physical labels/relationships).
6. **Choose a clause scaffold** based on intent (MATCH/WHERE/RETURN shape guidance).
7. **Select few-shot examples** (top‑K most similar examples from a candidate pool).
8. **Assemble prompt** and call the LLM to generate Cypher.

## Data/config dependencies

Enhanced T2CSS relies on:

- **Semantic schema JSON**: `qa-engine/text2cypher/configt2c/semantic_schema_uckg.json`
- **Few-shot candidates**: `qa-engine/text2cypher/configt2c/fewshot_candidates.json`
- **Embeddings cache**:
  - Some pipelines use cached embeddings like `schema_embeddings.json` (often large and usually ignored in git).

## Validation (where it happens)

There are *two* common validation paths:

- **No-exec validation (recommended for scoring KG validity)**:
  - `qa-engine/text2cypher/validation/noexec_validator.py`
  - Checks:
    - write-clause guard (CREATE/DELETE/…)
    - syntax via `EXPLAIN`
    - label/relationship/property existence (and sometimes strict value mapping)

- **Execution-time correctness (for evaluation)**:
  - The evaluation scripts run the generated query against Neo4j and compare the **result set** to the gold query’s result set.

## How to run (developer quickstart)

### Prerequisites

- Neo4j running with the UCKG dataset (Bolt enabled)
- Ollama running locally with:
  - a chat model (e.g. `llama3:instruct`)
  - an embedding model (e.g. `nomic-embed-text`)

### Run evaluation (compares pipelines)

From repo root:

```bash
python qa-engine/text2cypher/evaluation/evaluate_models.py
```

### Tips for safe local configuration

Avoid hardcoding credentials in code. Prefer environment variables:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="..."
```

## Troubleshooting

- **Low “KG Valid” but high text similarity**:
  - Often caused by strict property value mapping in the validator (value doesn’t exist in the DB).
- **Slow evaluation**:
  - Each question can require multiple LLM calls + Neo4j executions; use smaller `EVAL_LIMIT` for smoke tests.
- **Embeddings/model downloads**:
  - First run can be slow while Ollama models are pulled or embeddings are computed.


