# Text-to-Cypher System

A comprehensive Text-to-Cypher system for cybersecurity knowledge graphs, featuring two pipeline approaches: **Full Schema** and **Semantic Schema (T2CSS)**.

## 🏗️ Architecture Overview

```
text2cypher/
├── core/                      # Core T2C pipeline implementations
│   ├── text2cypher.py        # Standard full-schema T2C pipeline
│   ├── t2css_pipeline.py     # Semantic schema filtering (T2CSS)
│   └── t2css_integration.py  # Integration wrapper
│
├── llm/                       # LLM integrations
│   ├── ollama_llm.py         # Ollama local LLM interface
│   └── gemma_llm.py          # Gemma model support
│
├── validation/                # Cypher query validation
│   ├── noexec_validator.py   # Pre-execution validation (syntax, schema, properties)
│   ├── README.md             # Validation guide
│   └── utils/                # Validation utilities
│       └── regex_patterns.py # Regex patterns for parsing
│
├── memory/                    # Conversation memory management
│   ├── chat_memory.py        # Chat history storage
│   └── chat_types.py         # Type definitions
│
├── evaluation/                # Evaluation framework
│   ├── evaluate_models.py    # Multi-metric evaluation script
│   ├── dataset_analysis.ipynb # Dataset exploration notebook
│   └── monitor_progress.sh   # Progress monitoring tool
│
├── dataset/                   # Evaluation datasets
│   └── technical_dataset_COMPLETION.csv  # 388 questions across 9 categories
│
├── docs/                      # Documentation
│   ├── T2C_ARCHITECTURE.md   # Detailed architecture
│   ├── T2CSS_PIPELINE_DIAGRAM.md  # Semantic schema pipeline
│   └── FULL_SCHEMA_PIPELINE_DIAGRAM.md  # Full schema pipeline
│
├── Data Generation/           # Dataset generation tools
│
├── config.py                  # Configuration and semantics
├── main.py                    # FastAPI server entry point
└── requirements.txt           # Python dependencies
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start Neo4j Database

Ensure Neo4j is running with your cybersecurity knowledge graph:
```bash
# Default connection
URI: bolt://localhost:7687
User: neo4j
Password: abcd90909090
```

### 3. Start Ollama (for LLM inference)

```bash
ollama serve
ollama pull llama3:instruct
ollama pull nomic-embed-text  # For T2CSS embeddings
```

### 4. Run the Backend

```bash
python main.py
```

API will be available at `http://localhost:8000`

## 📊 Two Pipeline Approaches

### 1. **Full Schema Pipeline** (`core/text2cypher.py`)

Uses the complete graph schema for prompting:
- **Pros**: Comprehensive context, no schema elements missed
- **Cons**: Large prompt size, potential context overload
- **Best for**: Simple queries, when all schema is relevant

### 2. **Semantic Schema Pipeline (T2CSS)** (`core/t2css_pipeline.py`)

Filters schema using semantic similarity:
- **Pros**: Focused context, reduced prompt size, better for complex queries
- **Cons**: Requires embedding generation, may miss relevant schema
- **Best for**: Complex queries, when schema is large

**T2CSS Steps:**
1. Generate semantic text from schema
2. Embed schema triples using `nomic-embed-text`
3. Embed user query
4. Filter top-K most relevant schema elements
5. Generate Cypher with focused schema

## 🔍 Validation System

The validation module (`validation/`) provides pre-execution query validation:

### `noexec_validator.py` - Non-Executing Validation

Validates Cypher queries WITHOUT executing them:

1. **Write Clause Guard**: Blocks CREATE, MERGE, DELETE, SET, REMOVE
2. **Syntax Check**: Uses `EXPLAIN` to verify Cypher grammar
3. **Schema Validation**: 
   - Checks node labels exist in database
   - Verifies relationship types are valid
   - Confirms properties exist on nodes/relationships
4. **Property Value Validation**: Optional enum/range checks

**Usage:**
```python
from validation.noexec_validator import validate_cypher_noexec

is_valid, errors = validate_cypher_noexec(driver, cypher_query)
if is_valid:
    # Safe to execute
    result = session.run(cypher_query)
```

## 📈 Evaluation Framework

Comprehensive evaluation system in `evaluation/`:

### Metrics Implemented

**Cypher Text Similarity:**
- Jaro-Winkler similarity
- Jaccard similarity (token-based)
- ROUGE-L (F1)
- BLEU-4

**Output Correctness:**
- Pass@1 (exact output match)
- Jaccard Output Similarity (set-based)

**Validation:**
- KG Valid Query Rate (syntax + schema + properties)

**Composite:**
- LLMetric = 0.3×Pass@1 + 0.4×KG_Valid + 0.2×Jaccard_Output + 0.1×JaRou_Factor

### Run Evaluation

```bash
cd evaluation
python evaluate_models.py

# Monitor progress
./monitor_progress.sh
```

### Dataset Categories (388 questions)

1. **Node Lookup Queries** (173) - 44.6%
2. **Relationship Traversal** (42) - 10.8%
3. **Existence and Set Operations** (26) - 6.7%
4. **Multi-hop Queries** (25) - 6.4%
5. **Aggregation and Counting** (25) - 6.4%
6. **Path Queries (Variable-length)** (25) - 6.4%
7. **Graph Pattern Matching** (25) - 6.4%
8. **Conditional and Boolean** (24) - 6.2%
9. **Comparative and Ranking** (23) - 5.9%

## 🔧 Configuration

Edit `config.py` for:
- Neo4j connection settings
- LLM model selection
- Cybersecurity domain semantics
- Schema cache paths
- Validation rules

## 📚 API Endpoints

### `/text2cypher` (POST)
Generate Cypher from natural language

**Request:**
```json
{
  "question": "Find all CVEs related to Microsoft Windows",
  "use_t2css": false,
  "validate": true
}
```

**Response:**
```json
{
  "cypher": "MATCH (c:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft:windows' RETURN c",
  "validated": true,
  "execution_time": 1.23
}
```

### `/chat` (POST)
Conversational interface with memory

### `/schema` (GET)
Retrieve current graph schema

## 🧪 Testing

Run the evaluation framework to test pipeline performance:

```bash
cd evaluation
python evaluate_models.py
```

## 📖 Documentation

Detailed documentation in `docs/`:
- **T2C_ARCHITECTURE.md**: System architecture and design decisions
- **T2CSS_PIPELINE_DIAGRAM.md**: Semantic schema pipeline flow
- **FULL_SCHEMA_PIPELINE_DIAGRAM.md**: Standard pipeline flow

## 🤝 Contributing

When adding features:
1. Core pipeline changes → `core/`
2. New validators → `validation/`
3. Evaluation metrics → `evaluation/`
4. Documentation → `docs/`

## 📝 License

[Your License Here]

## 🙏 Acknowledgments

- T2CSS methodology based on "Prompting large language models based on semantic schema for text-to-Cypher transformation" (DSS 2025)
- Neo4j validation components adapted from Neo4j GraphRAG examples
