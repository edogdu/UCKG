# README: Dataset Validator Script Enhancements

## 1. Summary of Changes

This document outlines the recent enhancements made to the `dataset_validator.py` script. The new approach refactors the validation logic into a more robust and granular pipeline, starting with a crucial pre-check for data integrity followed by a four-stage validation process.

The core philosophy has shifted from a simple, combined validation check to a **comprehensive**, **row-by-row** analysis. A new **duplication check** now acts as a gatekeeper, ensuring the dataset's integrity before proceeding. If the dataset is clean, each entry is then subjected to four distinct tests. This provides a much clearer picture of the dataset's quality and pinpoints the exact nature and location of any failures.

---

## 2. The Validation Pipeline: A Preliminary Check + Four Stages

Instead of a single validation function, we now have a multi-stage process. It begins with a `dataset-wide duplication check`. If it passes, `four separate functions are run` on each row, with each stage targeting a specific potential failure point for LLM-generated data. Each check logs its results to a dedicated file in the validation_log directory.

### Preliminary Check: Dataset Duplication
* **Function**: `check_for_duplicates()`

* **Output File**: `duplication_check.txt`

* **What it Does**: This is the first and most critical step. It scans the entire dataset to find any duplicate `NaturalLanguageQuestion` entries. The check is case-insensitive and ignores extra whitespace to ensure accurate matching.

* **Why it's Important**: This check acts as a **gatekeeper**. Duplicate questions can negatively bias model training and indicate poor dataset quality. If any duplicates are found, the script logs the details and **halts immediately**, preventing wasted processing time on a flawed dataset.

### Stage 1: Schema Adherence Check
* **Function**: `validate_schema_elements()`
* **Output File**: `schema_check.txt`
* **What it Does**: This is the most fundamental check. It parses a Cypher query and verifies that every node label (e.g., `:UcoCVE`), relationship type (e.g., `-[:HAS_PROPERTY]->`), and property (e.g., `.label`) **actually exists** in the `schema_cache.txt` file.
* **Why it's Important**: This is a crucial first step. It immediately catches any "hallucinated" schema elements from the LLM, ensuring that every generated query is at least theoretically valid for your graph's structure.

### Stage 2: Cypher Executability Check
* **Function**: `validate_query_executability()`
* **Output File**: `cypher_check.txt`
* **What it Does**: This function takes the Cypher query and actually runs it against your Neo4j database to ensure it executes without error.
* **Recent Improvement**: The function is now more robust. It intelligently uses a regular expression to **replace an existing `LIMIT ...` clause with `LIMIT 1`** or appends `LIMIT 1` if no limit is present. This prevents syntax errors for queries that already contain a limit, making the check much more reliable.

### Stage 3: Entity Extraction Check
* **Function**: `validate_expected_entities_match_query()`
* **Output File**: `entity_check.txt`
* **What it Does**: This function compares the schema elements found inside the Cypher query string against the three *"expected"* columns in your dataset (`ExpectedNodeLabels`, `ExpectedRelationshipTypes`, `ExpectedProperties`).
* **Recent Improvement**: Property detection is now significantly more accurate. The function now uses **two separate regular expressions** to find properties in both dot notation (e.g., `c.label`) and map notation within curly braces (e.g., `{label: '...'}`). This correctly validates a much wider range of Cypher queries.

### Stage 4: Semantic Relevance Check
* **Function**: `validate_semantic_relevance()`
* **Output File**: `question_cypher_relevance.txt`
* **What it Does**: This is a major upgrade for checking relevance. Instead of simple keyword matching, this function uses a powerful **Hugging Face Sentence Transformer model** (`all-MiniLM-L6-v2`) to understand the *meaning* of the question and the query.
* **How it Works**: It converts both the natural language question and the Cypher query into numerical vectors (embeddings). It then calculates their **cosine similarity** to get a score of how semantically related they are. A score above a set threshold (e.g., 0.7) passes the check. This is far more effective at confirming that the query truly answers the user's question, even if the wording is very different.
* **New Dependency**: This check requires the `sentence-transformers` library (`pip install sentence-transformers`).

---

## 3. Structural and Logging Improvements

* **Row-by-Row Reporting**: The `run_all_validators` function iterates through every single row of the dataset and runs all four checks, logging the `PASS` or `FAIL` status for each entry in the appropriate file.
* **Dedicated Log Files**: As requested, the script creates four separate `.txt` files. This separation makes it easy to analyze specific types of failures.
* **Clearer Naming and Orchestration**: Functions have been named to clearly reflect their specific roles, and the main execution block cleanly handles setting up and closing log files.