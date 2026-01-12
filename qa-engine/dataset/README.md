# Dataset Generation for Graph RAG Evaluation

Generate evaluation datasets from the MultiRAG pipeline for testing Graph RAG performance across different question complexities.

## What It Does

Processes questions through the complete 4-stage GraphRAG pipeline and captures:
- **Question**: Original query text
- **Context**: Exact formatted text passed to LLM
- **Response**: Generated natural language answer
- **Metadata**: Mode, hop count, question type, node types, relationships, used properties, retrieval statistics

## File Structure

```
qa-engine/
├── dataset/                              # Dataset Generation Module
│   ├── README.md                        # This file
│   ├── create_evaluation_dataset.py     # Main dataset generator script
│   ├── evaluate_coverage.py             # Coverage analysis tool
│   ├── evaluation_dataset.json          # Generated output (129 samples)
│   └── evaluation_dataset.json.txt      # Text backup
│
└── shared/                               # Input Question Files
    └── question_set/                    # Question datasets by hop type
        ├── README.md                    # Question set documentation
        ├── questions_0hop.json          # 9 single-node questions
        ├── questions_1hop.json          # 25 one-hop questions
        ├── questions_2hop.json          # 25 two-hop questions
        ├── questions_0hop_bunny.json    # Alternative 0-hop set
        ├── questions_1hop_bunny.json    # Alternative 1-hop set
        ├── questions_2hop_bunny.json    # Alternative 2-hop set
        ├── getNodes.py                  # Node extraction utility
        ├── nodes.json                   # Extracted node data
        ├── generate_questions.py        # Question generation script
        ├── subgraph_description.py      # Subgraph analysis
        ├── subgraph_description.txt     # Generated descriptions
        └── semantic_descriptions.txt    # Semantic metadata
```

### Key Files

| File | Purpose | Input/Output |
|------|---------|--------------|
| `create_evaluation_dataset.py` | Main script - processes questions through GraphRAG pipeline | Input: `questions_*.json` → Output: `evaluation_dataset.json` |
| `evaluate_coverage.py` | Analyzes dataset coverage and statistics | Input: `evaluation_dataset.json` → Output: Coverage report |
| `evaluation_dataset.json` | Generated dataset with questions, contexts, and responses | 129 samples (9 + 25 + 25 from 0/1/2-hop questions) |
| `shared/question_set/questions_0hop.json` | Single-node questions (no graph traversal) | 9 questions answerable from one node |
| `shared/question_set/questions_1hop.json` | One-hop questions (one relationship) | 25 questions requiring 1 graph traversal |
| `shared/question_set/questions_2hop.json` | Two-hop questions (two relationships) | 25 questions requiring 2 graph traversals |

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Dataset Generation Pipeline                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  shared/question_set/                                           │
│  ├── questions_0hop.json  ──┐                                   │
│  ├── questions_1hop.json  ──┼──► create_evaluation_dataset.py   │
│  └── questions_2hop.json  ──┘            │                      │
│                                          │                      │
│                              ┌───────────▼──────────┐           │
│                              │  GraphRAG Pipeline   │           │
│                              │  (4-stage processing)│           │
│                              └───────────┬──────────┘           │
│                                          │                      │
│                              ┌───────────▼──────────┐           │
│                              │ evaluation_dataset.  │           │
│                              │        json          │           │
│                              │  (129 samples with   │           │
│                              │  context + responses)│           │
│                              └──────────────────────┘           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Navigate to dataset directory
cd /Users/shin/Programming/UCKG-2/qa-engine/dataset

# Activate venv
source ../text2cypher/venv/bin/activate

# Run full dataset generation (all 129 questions)
python create_evaluation_dataset.py

# Or test with limited questions
# Edit script: LIMIT = 10
```

## What It Generates

Creates `evaluation_dataset.json` with this structure:

```json
{
  "dataset_metadata": {
    "total_questions": 129,
    "generation_date": "2025-10-25T...",
    "source_files": [
      "questions_1node.json",
      "questions_1hop.json",
      "questions_2hop.json"
    ],
    "pipeline": "MultiRAG GraphRAG 4-Stage Pipeline"
  },
  "samples": [
    {
      "id": 1,
      "question": "How can Content Spoofing deceive users into trusting falsified information?",
      "context": "[1] PRIMARY NODE: CAPEC-148: Content Spoofing\n    Type: UcoexCAPEC\n    Content: Content spoofing is...",
      "response": "Content Spoofing (CAPEC-148) is an attack pattern where adversaries...",
      "metadata": {
        "mode": "graphrag",
        "source_file": "questions_1node.json",
        "hop_count": 0,
        "question_type": "<s,*,*>",
        "node_info": {
          "type": "<s,*,*>",
          "first_node": "CAPEC",
          "second_node": "",
          "third_node": "",
          "relationship_1": "",
          "relationship_2": "",
          "used_properties": {
            "first_node": ["name", "ucoexDescription"],
            "second_node": [],
            "third_node": []
          }
        },
        "retrieval_stats": {
          "num_sources": 2,
          "node_types": ["UcoexCAPEC"],
          "relationship_types": ["UCOEXHASRELATEDWEAKNESS"]
        }
      }
    }
  ]
}
```

## Input Question Files

Reads questions from `../shared/question_set/` directory:

### questions_1node.json (9 questions)
0-hop questions that can be answered from a single node.

```json
[
  {
    "question": "How does encryption protect sensitive data during storage and transmission?",
    "type": "<s,*,*>",
    "first_node": "MITIGATIONS",
    "used_properties": ["ucoexDESCRIPTION"]
  }
]
```

### questions_1hop.json (25 questions)
1-hop questions requiring traversal of one relationship.

```json
[
  {
    "question": "How could a SOAP Array Overflow arise from weaknesses in buffer length handling?",
    "type": "<s,p,o>",
    "first_node": "UcoexCAPEC",
    "used_properties_of_first_node": ["label", "ucoexDescription"],
    "relationship": "UCOEXHASRELATEDWEAKNESS",
    "second_node": "UcoCWE",
    "used_properties_of_second_node": ["ucocweName", "ucocweSummary"]
  }
]
```

### questions_2hop.json (25 questions)
2-hop questions requiring traversal of two relationships.

```json
[
  {
    "question": "How could symbolic link handling flaws lead to arbitrary file writes in Kubernetes?",
    "type": "<s,*,o>",
    "first_node": "UNIX Symbolic Link (Symlink) Following",
    "used_properties_of_first_node": ["ucocweSummary", "ucocweExtendedSummary"],
    "relationship_1": "UCOHASWEAKNESS",
    "second_node": "UcoExploitTarget",
    "used_properties_of_second_node": [],
    "relationship_2": "UCOHASVULNERABILITY",
    "third_node": "Kubernetes kubectl cp vulnerability",
    "used_properties_of_third_node": ["ucosummary"]
  }
]
```

## Configuration

Edit the script to customize:

```python
# Line 250: Limit questions for testing
LIMIT = None  # Process all 129 questions
LIMIT = 10    # Process only first 10

# Line 242: Change output location
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "my_dataset.json")
```

## Processing Time

- **~5 seconds per question**

Each question goes through:
1. **Dynamic Hop Selection** (~0.2s) - Determines optimal graph depth
2. **Vector Search** (~0.5s) - Semantic similarity retrieval
3. **Graph Traversal** (~1s) - 1-hop or 2-hop neighbor expansion
4. **Similarity Filtering** (~0.3s) - Top-2 per relationship type
5. **Reranking** (~0.5s) - Neighbor-aware scoring
6. **LLM Generation** (~3-8s) - Natural language answer

## Requirements

- **Neo4j**: Running with UCKG data and `global_embedding_idx` vector index
- **Ollama**: Models `llama3:8b` (LLM) and `nomic-embed-text:latest` (embeddings)
- **Python env**: Use `../text2cypher/venv`

## Output

- **File**: `evaluation_dataset.json`
- **Format**: JSON with complete context and responses

---

