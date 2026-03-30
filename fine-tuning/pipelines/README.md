# UCKG Synthetic Data Generation Pipeline

This directory contains the custom ETL (Extract, Transform, Load) pipeline used to extract structured knowledge from the UCKG Neo4j database and prepare it for Supervised Fine-Tuning (SFT) data generation.

## Directory Architecture

This module is intentionally separated into two distinct parts:
1. **`sft_engine/`** (Located one folder up): The core graph processing and LLM generation framework.
2. **`pipelines/`** (This folder): Your custom UCKG business logic, extraction scripts, and orchestration runners.

## The ETL Pipeline (`run_etl_pipeline.sh`)

The master script executes four sequential steps to pull data from Neo4j and stage it in a fast, local graph database (`KuzuDB`).

### Step 1: Extract (`extract_uckg_raw.py`)
**Purpose:** Pull connected subgraphs from the live Neo4j database.
*   **Mechanism:** Connects via Bolt protocol using credentials in `.env`. It executes Cypher queries designed to extract specific "Incident Response Triads".
*   **Target Data:** It specifically looks for the path: `[CAPEC] --(IS_A)--> [ATT&CK] <--(MITIGATES)-- [MITIGATION]`.
*   **Output:** Dumps the raw JSON response from Neo4j, including all node properties and relationship metadata, into `raw_data.jsonl`. This file is often massive and noisy.

### Step 2: Filter (`filter_uckg_data.py`)
**Purpose:** Reduce token bloat by stripping irrelevant metadata.
*   **Mechanism:** Reads `raw_data.jsonl` row by row and applies a strict property whitelist.
*   **Target Data:** It discards system properties (like `embedding_processed`) and keeps only human-readable, training-relevant fields. For example, on a CAPEC node, it retains `ucoexCAPEC_name`, `ucoexDescription`, `ucoexMitigations`, `ucoexPrerequisites`, and `ucoexExecutionFlowTechnique`.
*   **Output:** A much leaner file, `filtered_data.jsonl`, optimized to save LLM context window space.

### Step 3: Clean (`clean_uckg_data.py`)
**Purpose:** Format data structures for natural language reading.
*   **Mechanism:** The UCKG Neo4j database often stores complex lists (like lists of mitigations) as stringified JSON arrays (e.g., `"[\"Firewall\", \"Patch\"]"`). This script detects those strings and parses them back into Python lists.
*   **Transformation:** It normalizes whitespace, removes unicode artifacts, and converts lists into bulleted Markdown strings (e.g., `\n- Firewall\n- Patch`).
*   **Output:** `clean_data.jsonl`, which contains data that is highly readable by both humans and LLMs.

### Step 4: Load & Bake (`load_rich_atomic.py`)
**Purpose:** Structure the data for the generation engine using the "Fat Node" strategy.
*   **Mechanism:** It reads the clean data and initializes a local `KuzuDB` instance (an embedded, columnar graph database optimized for fast topological scans).
*   **The "Fat Node" Strategy:** Instead of loading the data as isolated, thin nodes, this script "bakes" the rich contextual metadata directly into the primary node. It takes the bulleted lists of Mitigations and Techniques and appends them to the end of the `description` property of the `CAPEC` node.
*   **Why?** By making the node "Fat", we guarantee that when the LLM samples a single attack node for a basic 0-hop Q&A, it automatically has access to the mitigation data in the same prompt. It ensures our training data always pairs the problem with the solution.
*   **Output:** The fully populated `KuzuDB` database, staged in `../cache/graph_kuzu/`.

## How to Run

1. Ensure your Neo4j container is running locally (`docker-compose up -d neo4j`).
2. Ensure you have installed the requirements (`pip install -r ../requirements.txt`).
3. Ensure your `.env` file is configured at the root of the `fine-tuning` folder.
4. Execute the master script from the terminal:

```bash
bash run_etl_pipeline.sh
```
