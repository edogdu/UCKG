# Dataset Validator for Text-to-Cypher

This script is a comprehensive validation tool for a **text-to-Cypher dataset**. It is designed to load a dataset (e.g., from a CSV), perform a series of rigorous checks, and produce detailed logs for any issues found.  
The goal is to ensure the dataset is **clean, accurate, and consistent** with a predefined graph schema *before* it's used for training or evaluation.

---

## Prerequisites

Before running the script, install the required dependencies:

```bash
pip install neo4j pandas openpyxl sentence-transformers
```

## Additional Requirements

This script also requires:

- A running **Neo4j** instance to validate query executability.  
- A **schema_cache.txt** file defining the graph schema.

---

## Configuration

All configuration is handled in the `if __name__ == '__main__':` block at the bottom of the script.

| Variable | Description | Example |
|-----------|--------------|----------|
| `NEO4J_URI` | Bolt URI for your Neo4j database | `"bolt://localhost:7687"` |
| `NEO4J_USER` | Username for your Neo4j database | `"neo4j"` |
| `NEO4J_PASSWORD` | Password for your Neo4j database | `"abcd90909090"` |
| `SCHEMA_FILE` | Path to your `schema_cache.txt` | `".\text2cypher\backend\evaluation\schema_cache.txt"` |
| `RAW_DATASET_FILE` | Path to the input dataset (e.g., `.csv`) |` ".\text2cypher\backend\dataset\neo4j_NaturalLanguageQuestion_ADJUSTED.csv"` |
| `ENRICHED_DATASET_FILE` | Output file for the enriched dataset | `".\text2cypher\backend\dataset\neo4j_evaluation_dataset_ENRICHED.csv"` |
| `LOG_DIRECTORY` | Directory where validation logs will be written | `".\text2cypher\backend\validation_log"` |

---

## Validation Process Flow

### **1. Initialization**
The `DatasetValidator` is initialized and attempts to connect to the Neo4j database while loading the graph schema.

### **2. Load Data**
Loads the raw dataset (e.g., `neo4j_NaturalLanguageQuestion_ADJUSTED.csv`) into memory.

### **3. Setup Loggers**
Creates all log files (e.g., `duplication_check.txt`, `schema_check.txt`) in the `LOG_DIRECTORY`.

### **4. Gatekeeper: Duplicate Check**
Runs `check_for_initial_duplicates()` — the first and most critical step.

- **If duplicates are found:**  
  They are logged, an error is printed, and execution halts (`sys.exit(1)`).

### **5. Enrichment**
If no duplicates exist, runs `enrich_dataset()` to parse every Cypher query and extract new helper columns such as:

- `ExpectedNodeLabels`  
- `ExpectedRelationshipTypes`  
- `ExpectedProperties`  
- `Hops`

### **6. Save Enriched Data**
The enriched dataset is saved as `neo4j_evaluation_dataset_ENRICHED.csv`.

### **7. Run Full Validation**
Executes `run_all_validators()` on the enriched dataset.  
This runs **Schema**, **Execution**, **Entity**, **Value**, and **Relevance** checks for every row.

### **8. Report Summary**
Displays a summary of pass/fail counts for each validation stage.

### **9. Cleanup**
Closes all log files and the Neo4j driver connection.

---

## Function Breakdown

### `__init__(self, schema_file, neo4j_uri, neo4j_user, neo4j_pass)`
**Purpose:** Initializes schema loading and establishes a Neo4j connection.  
**Action:** Uses `_load_schema()` and `neo4j.GraphDatabase.driver`.

---

### `_setup_loggers(self, log_directory)`
**Purpose:** Prepares log files and maps each validation type (e.g., duplication, schema) to a file handler.

---

### `_log(self, check_type, message)`
**Purpose:** Centralized logging helper to write messages to the appropriate log file.

---

### `close_loggers(self)`
**Purpose:** Closes all open log file handlers and flushes log data to disk.

---

### `_load_schema(self, schema_file)`
**Purpose:** Parses `schema_cache.txt` for node labels, relationship types, and properties using regex.  
**Output:** Structured schema dictionary `{ "nodes": {...}, "relationships": {...} }`.

---

### `load_dataset(self, file_path)`
**Purpose:** Loads dataset from `.csv`, `.json`, or `.xlsx` formats into a standardized structure.

---

### `_count_hops(self, cypher_query)`
**Purpose:** Counts the number of relationship traversals (`-->` or `<--`) in the Cypher query.

---

### `_extract_literal_values_from_query(self, cypher_query)`
**Purpose:** Extracts literal data values (strings, numbers, booleans) from queries while ignoring syntax-related values (e.g., `LIMIT 10`).  
**Usage:** Supports value consistency validation.

---

### `enrich_dataset(self, dataset)`
**Purpose:** Populates helper columns (`ExpectedNodeLabels`, `ExpectedRelationshipTypes`, `ExpectedProperties`, `Hops`, `ExtractedPropertyValues`) for each query.  
**Why:** Precomputes elements for faster and more consistent validation.

---

### `check_for_initial_duplicates(self, dataset)`
**Purpose:** Acts as a gatekeeper by scanning for duplicates before any further processing.  
**Detects:**
- Duplicate `NaturalLanguageQuestion`
- Duplicate `CypherQuery`
- Duplicate `(NaturalLanguageQuestion, CypherQuery)` pairs
- Duplicate `(NaturalLanguageQuestion, CypherToQuestion)` pairs  

**If duplicates are found:** Logs issues and stops execution.

---

### `validate_extracted_values_in_question(self, question, row, entry_id)`
**Purpose:** Ensures extracted values from the Cypher query also appear in the corresponding natural language question.  
**Example:** If query filters by `'CRITICAL'`, the question must mention “critical vulnerabilities”.

---

### `validate_schema_elements(self, cypher_query, entry_id)`
**Purpose:** Confirms that all schema elements (labels, relationships, properties) used in the Cypher query exist in `schema_cache.txt`.  
**Catches:** Typos, outdated labels, and invalid relationships.

---

### `validate_query_executability(self, cypher_query, entry_id)`
**Purpose:** Ensures Cypher query syntax validity by running the query against Neo4j.  
**Enhancement:** Automatically replaces or appends `LIMIT 1` for safe execution.

---

### `validate_expected_entities_match_query(self, cypher_query, row, entry_id)`
**Purpose:** Confirms that the Cypher query’s actual entities match the enriched dataset’s helper columns.  
**Usage:** Validates enrichment accuracy.

---

### `validate_semantic_relevance(self, natural_language_question, CypherToQuestion, entry_id, threshold)`
**Purpose:** Checks if `CypherToQuestion` and `natural_language_question` are semantically aligned using embeddings from the `all-MiniLM-L6-v2` Sentence Transformer.  
**Fails if:** Cosine similarity `< 0.7`.

---

### `run_all_validators(self, dataset)`
**Purpose:** Orchestrates all validation steps sequentially:

1. `validate_schema_elements`  
2. `validate_query_executability`  
3. `validate_expected_entities_match_query`  
4. `validate_extracted_values_in_question`  
5. `validate_semantic_relevance`

**Result:** Produces pass/fail summary and logs detailed row-level feedback.

---

### `close(self)`
**Purpose:** Gracefully closes the Neo4j driver and releases network resources.

---

## Validation Logs

All logs are stored in the `LOG_DIRECTORY`, providing a detailed record of validation results.

| Log File | Description |
|-----------|--------------|
| **duplication_check.txt** | Logs duplicate entries across questions, queries, or combinations. |
| **schema_check.txt** | Logs Cypher queries using invalid labels, relationships, or properties. |
| **cypher_check.txt** | Logs syntax or execution errors when running Cypher queries. |
| **entity_check.txt** | Logs mismatches between helper columns and actual Cypher entities. |
| **question_cypher_relevance.txt** | Logs semantic mismatches between questions and generated queries. |
| **value_check.txt** | Logs discrepancies where literal values in Cypher are missing in the NL question. |

---

## Summary

This script ensures your **Text-to-Cypher dataset** is validated at every level —  
**structure**, **schema**, **syntax**, **semantics**, and **duplication** —  
making it **production-ready** for **LLM fine-tuning** or **benchmark evaluation**.
