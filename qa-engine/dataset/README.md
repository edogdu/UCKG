# create_evaluation_dataset.py

Generate evaluation datasets from the MultiRAG pipeline for Graph RAG testing.

## What It Does

Processes questions through the complete 4-stage GraphRAG pipeline and captures:
- **Question**: Original query text
- **Context**: Exact formatted text passed to LLM
- **Response**: Generated natural language answer
- **Metadata**: Mode, difficulty, node IDs, retrieval statistics

## Quick Start

```bash
# Activate venv
source ../text2cypher/venv/bin/activate

# Run full dataset generation
python create_evaluation_dataset.py
```

## What It Generates

Creates `evaluation_dataset.json` with this structure:

```json
{
  "dataset_metadata": {
    "total_questions": 151,
    "generation_date": "2025-10-20T...",
    "source_files": ["first 1 hop.json", "second 1 hop.json", ...],
    "pipeline": "MultiRAG GraphRAG 4-Stage Pipeline"
  },
  "samples": [
    {
      "id": 1,
      "question": "What is SQL injection?",
      "context": "[1] PRIMARY NODE: CWE-89...",
      "response": "SQL injection (CWE-89) is a vulnerability...",
      "metadata": {
        "mode": "graphrag",
        "source_file": "first 1 hop.json",
        "difficulty": 1,
        "node_info": {
          "start_node": 4682,
          "1-hop_node": 4583,
          "2-hop_node": ""
        },
        "retrieval_stats": {
          "num_sources": 2,
          "node_types": ["UcoCWE", "UcoexCAPEC"],
          "relationship_types": ["EXPLOITS", "MITIGATED_BY"]
        }
      }
    }
  ]
}
```

## Input

Reads all `*.json` files from `../questionSet/` directory. Each file should contain:

```json
{
  "questions": [
    {
      "text": "What is...",
      "start_node": 4682,
      "1-hop_node": 4583,
      "2-hop_node": "",
      "difficulty": 1
    }
  ]
}
```

## Configuration

Edit the script to customize:

```python
# Line 213: Limit questions for testing
LIMIT = None  # Process all questions
LIMIT = 10    # Process only first 10

# Line 209: Change output location
OUTPUT_FILE = "my_dataset.json"
```

## Processing Time

- ~5-10 seconds per question
- 151 questions ≈ 15-25 minutes total

Each question goes through:
1. Vector search (~0.5s)
2. Graph traversal (~1s)
3. Reranking (~0.5s)
4. LLM generation (~3-8s)

## Requirements

- **Neo4j**: Running with UCKG data
- **Ollama**: Models `llama3:8b` and `nomic-embed-text:latest`
- **Python env**: Use `../text2cypher/venv`

## Output

- **File**: `evaluation_dataset.json`
- **Size**: ~1-2MB for 151 questions
- **Format**: JSON with full context and responses

---

