# Dataset Validator Documentation

## Overview

The `Dataset Validator` is a comprehensive validation file for natural language to Cypher query datasets. It ensures data quality by checking for duplicates, schema compliance, query executability, semantic relevance, and data consistency between questions and their corresponding Cypher queries.

## Core Components

### Dependencies

The validator requires several Python libraries:
- **Required**: `csv`, `json`, `re`, `sys`, `pandas`, `openpyxl`
- **Optional**: 
  - `neo4j` - For connecting to Neo4j database and validating query executability
  - `sentence-transformers` - For semantic similarity checking between questions

If optional dependencies are missing, the validator will skip related checks and continue with other validations.

### Key Features

1. **Schema Validation** - Verifies that node labels, relationships, and properties in Cypher queries match the graph schema
2. **Duplicate Detection** - Identifies duplicate original-questions, queries, cypher-to-questions, original question - query pairs, and original question - cypher-to-question pairs
3. **Query Execution Testing** - Tests if Cypher queries can execute without errors
4. **Semantic Relevance** - Measures similarity between natural language questions and generated questions from Cypher
5. **Value Consistency** - Ensures literal values in Cypher queries appear in corresponding questions

## Class Structure

### Initialization

```python
DatasetValidator(schema_file, neo4j_uri, neo4j_user, neo4j_pass)
```

**Parameters:**
- `schema_file`: Path to schema cache file
- `neo4j_uri`: Neo4j database connection URI
- `neo4j_user`: Database username
- `neo4j_pass`: Database password

The initializer loads the schema and establishes a connection to Neo4j (if available).

### Schema Loading

The `_load_schema()` method parses a schema cache file to extract:
- **Node labels** and their properties (stored as `{label: {prop: type}}`)
- **Relationship types** (stored as a set)

The schema format expects patterns like:
```
NodeLabel {
  property1: type1,
  property2: type2
}
(:NodeLabel1)-[:RELATIONSHIP_TYPE]->(:NodeLabel2)
```

## Dataset Handling

### Loading Data

The `load_dataset()` method supports multiple formats:
- **CSV files** (`.csv`)
- **JSON files** (`.json`)
- **Excel files** (`.xlsx`)

### Dataset Enrichment

The `enrich_dataset()` method parses Cypher queries to automatically populate helper columns:

**Generated Columns:**
- `ExpectedNodeLabels` - JSON array of node labels found in query
- `ExpectedRelationshipTypes` - JSON array of relationship types
- `ExpectedProperties` - JSON array of properties accessed
- `Hops` - Number of relationship traversals in the query
- `ExtractedPropertyValues` - JSON array of literal values (strings, numbers, booleans)

**Parsing Strategy:**
The enrichment uses regex patterns while avoiding false positives:
- Removes string literals before parsing dot notation to prevent matching numbers (e.g., `3.9`)
- Distinguishes between map notation (`{key: value}`) and dot notation (`variable.property`)
- Filters out syntax-related values (LIMIT, SKIP clauses, path lengths)

## Validation Functions

### 1. Initial Duplicate Check

`check_for_initial_duplicates(dataset)` serves as a gatekeeper that detects four types of duplicates:

1. **Duplicate Questions** - Same natural language question appears multiple times
2. **Duplicate Cypher Queries** - Identical Cypher queries
3. **Duplicate Question-Query Pairs** - Same combination of question and query
4. **Duplicate NL-Generated Pairs** - Same `NaturalLanguageQuestion` with same `CypherToQuestion`

**Behavior:** If any duplicates are found, the validation process halts and logs all duplicate entries with their locations.

### 2. Schema Validation

`validate_schema_elements(cypher_query, entry_id)` checks if all elements in a Cypher query exist in the schema:

**Validates:**
- Node labels (e.g., `:Person`, `:Movie`)
- Relationship types (e.g., `-[:ACTED_IN]->`)
- Properties (e.g., `name`, `title`)

**Implementation Details:**
- Neutralizes string literals to avoid parsing properties from within quoted strings
- Uses improved regex pattern that requires alphabetic characters before dots (prevents matching `3.9` as `9` property)
- Checks node properties against the schema dictionary structure

### 3. Query Executability

`validate_query_executability(cypher_query, entry_id)` tests if queries can run without errors:

**Process:**
1. Modifies query to add/replace with `LIMIT 1` for performance
2. Executes query against Neo4j database
3. Catches and logs any execution errors

**Requires:** Active Neo4j connection

### 4. Semantic Relevance

`validate_semantic_relevance(natural_language_question, CypherToQuestion, entry_id, threshold=0.6)` measures semantic similarity:

**How it works:**
1. Encodes both questions using sentence-transformers model (`all-MiniLM-L6-v2`)
2. Computes cosine similarity between embeddings
3. Passes if similarity exceeds threshold (default: 0.6)

**Use case:** Ensures that the natural language question and the question derived from the Cypher query are semantically aligned.

### 5. Value Consistency

`validate_extracted_values_in_question(question, row, entry_id)` ensures literal values from Cypher appear in questions:

**Features:**
- Ignores common non-data literals (`true`, `false`, `1`, `0`)
- Skips values used in `LIMIT` and `SKIP` clauses
- Uses flexible word matching instead of exact substring matching
- Splits values into words and checks for intersection with question words

**Example:**
- If Cypher contains `name: "John Smith"`, the question should contain "john" or "smith"

## Logging System

### Log Setup

`_setup_loggers(log_directory)` creates separate log files for each validation type:

**Log Files:**
- `duplication_check.txt` - Duplicate detection results
- `schema_check.txt` - Schema validation issues
- `cypher_check.txt` - Query execution errors
- `question_cypher_relevance.txt` - Semantic relevance scores
- `value_check.txt` - Value consistency issues

Each log entry includes the entry ID and detailed information about passes or failures.

## Execution Flow

### Main Process

When run as a script, the validator follows this sequence:

1. **Initialize** - Load schema and connect to Neo4j
2. **Load Dataset** - Read raw dataset from file
3. **Setup Logging** - Create log files for validation reports
4. **Initial Duplicate Check** - Check for duplicates (halts if found)
5. **Enrich Dataset** - Parse queries and add helper columns
6. **Save Enriched Data** - Write enriched dataset to new CSV
7. **Run Full Validation** - Execute all validation checks
8. **Generate Reports** - Display summary statistics

### Configuration Variables

```python
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "your_password"
SCHEMA_FILE = "schema_cache.txt"
RAW_DATASET_FILE = "input_dataset.csv"
ENRICHED_DATASET_FILE = "output_enriched_dataset.csv"
LOG_DIRECTORY = "validation_logs/"
```

## Validation Summary Output

After running all validations, the tool displays:

```
----- Validation Summary -----
Schema Check PASSED: 95/100 (95.00%)
Execution Check PASSED: 92/100 (92.00%)
Value Check PASSED: 88/100 (88.00%)
Relevance Check PASSED: 85/100 (85.00%)
----------------------------
```

## Helper Methods

### Hop Counting

`_count_hops(cypher_query)` counts relationship traversals using regex pattern `-[\[...\]]-`

### Literal Value Extraction

`_extract_literal_values_from_query(cypher_query)` extracts data literals while filtering out:
- LIMIT/SKIP clause numbers
- Variable-length path specifications (e.g., `[*2]`, `[*3..5]`)
- Syntax-related literals

Returns a sorted, unique list of string, numeric, and boolean values.

## Robustness Features

### String Literal Protection

The validator uses `STRING_LITERAL_REGEX` to neutralize string contents before parsing:
```python
STRING_LITERAL_REGEX = re.compile(r"(['\"])(.*?)\1")
```

This prevents false positives when parsing:
- Property names that might appear in strings
- Numeric values in strings
- Special characters

### Error Handling

- Gracefully handles missing optional dependencies
- Provides fallback behavior when Neo4j is unavailable
- Catches and logs file not found errors
- Displays warnings instead of crashing when features are unavailable

## Use Cases

This validator is ideal for:

1. **Dataset Quality Assurance** - Before training text-to-Cypher models
2. **Data Cleaning** - Identifying and removing problematic entries
3. **Schema Alignment** - Ensuring queries match your graph structure
4. **Consistency Checking** - Verifying questions and queries are properly paired
5. **Regression Testing** - Validating dataset changes don't introduce errors

## Output Files

1. **Enriched Dataset CSV** - Original data plus computed helper columns
2. **Validation Logs** - Separate files for each validation type with detailed failure information
3. **Console Summary** - High-level pass/fail statistics for quick assessment