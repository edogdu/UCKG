# GraphRAG-Similarity Pipeline

A modular 4-stage pipeline for cybersecurity knowledge graph question answering.

## Overview

GraphRAG-Similarity combines semantic search, graph traversal, and LLM-powered enhancements to answer questions using a Neo4j cybersecurity knowledge graph (UCKG).

## Quick Start

### Environment Setup

Create a `.env` file in the `qa-engine/` directory with your Neo4j credentials:

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password_here
INDEX_NAME=global_embedding_idx
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GraphRAG Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Stage 0: Pre-Processing                                    │
│  ├─ Hop Selection (0/1/2-hop based on query complexity)     │
│  └─ Relationship Prediction (LLM predicts relevant rels)    │
│                          ↓                                  │
│  Stage 1-2: Retrieval                                       │
│  ├─ Semantic Search (vector similarity via embeddings)      │
│  └─ Graph Traversal (enrich with 1-hop/2-hop neighbors)     │
│                          ↓                                  │
│  Stage 3: Reranking                                         │
│  ├─ Filter neighbors by similarity                          │
│  ├─ Apply relationship prediction bonuses                   │
│  └─ Recompute scores (primary + neighbor)                   │
│                          ↓                                  │
│  Stage 4: Generation                                        │
│  ├─ Format context (nodes + relationships)                  │
│  └─ LLM generates natural language answer                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

```
graphrag/
├── __init__.py          # Clean exports: GraphRAGSimilarity, GraphRAGConfig, RAGMode
├── utils.py             # Configuration, enums, helper functions
├── retrieval.py         # Stage 1-2: Semantic search + graph traversal
├── reranking.py         # Stage 3: Neighbor-aware reranking
├── generation.py        # Stage 4: Context formatting + answer generation
└── pipeline.py          # Main orchestrator coordinating all stages
```

### File Responsibilities

- **utils.py**: Configuration dataclass, constants, cosine similarity, node formatters
- **retrieval.py**: `GraphRetriever` - builds Cypher queries, executes vector + graph search
- **reranking.py**: `GraphReranker` - filters neighbors, applies relationship bonuses, recalculates scores
- **generation.py**: `ContextFormatter` + `AnswerGenerator` - formats retrieved data and generates answers
- **pipeline.py**: `GraphRAGSimilarity` - orchestrates the entire 4-stage pipeline

## Workflow Details

### Stage 0: Pre-Processing

**Dynamic Hop Selection** (optional):
- Analyzes query complexity using rule-based + LLM methods
- Decides optimal graph traversal depth:
  - **0-hop**: Semantic search only (simple lookups)
  - **1-hop**: Primary node + immediate neighbors (moderate complexity)
  - **2-hop**: Primary + 1-hop + 2-hop neighbors (complex relationships)

**Relationship Prediction** (optional):
- Uses LLM + schema to predict which relationship types are relevant
- Predicted relationships get bonus scores during reranking
- Limits traversal to top N relationship types per node

### Stage 1-2: Retrieval

**Stage 1 - Semantic Search**:
- Embed query using Ollama (`nomic-embed-text`)
- Search Neo4j vector index for top-k similar nodes
- Initial candidates fetched for reranking (multiplier applied)

**Stage 2 - Graph Traversal**:
- For each candidate node, retrieve connected neighbors
- Collect relationship types and neighbor content
- Support for 1-hop and 2-hop traversal
- Cypher queries dynamically built based on hop depth

### Stage 3: Reranking

**Neighbor Filtering**:
- Group neighbors by relationship type
- Keep top 2 most similar per relationship type
- Apply same filtering to 2-hop neighbors

**Score Recalculation**:
- Recompute similarity between query and all node embeddings
- Primary score: Direct similarity to primary node
- Neighbor contribution: Average of top-3 neighbor similarities
- **Final Score** = `(0.7 × primary) + (0.3 × neighbors)`
- Add bonus for predicted relationships

**Result Selection**:
- Sort by reranked scores
- Return top-k results

### Stage 4: Generation

**Context Formatting**:
- Format nodes and relationships into structured text
- Include primary nodes, 1-hop relationships, 2-hop connections
- Preserve cybersecurity-specific attributes (CVE IDs, CWE IDs, etc.)

**Answer Generation**:
- Use ChatOllama (`llama3:8b`) with specialized prompt
- Prompt instructs LLM to:
  - Focus on primary node's relationship tree
  - Use 2-hop information for deeper insights
  - Include technical details and identifiers
  - Format with markdown (bold, bullets)
  - Keep response compact (2-4 paragraphs)

## Usage

### Basic Usage

```python
from graphrag import GraphRAGSimilarity

# Initialize with default configuration
rag = GraphRAGSimilarity()

# Run a query
result = rag.run("What is SQL injection?")

print(result["answer"])         # Natural language answer
print(result["sources"])         # Ranked source nodes
print(result["hop_selection"])   # Hop decision metadata
```

### Custom Configuration

```python
from graphrag import GraphRAGSimilarity, GraphRAGConfig

# Customize pipeline behavior
config = GraphRAGConfig(
    enable_second_hop=True,              # Enable 2-hop traversal
    enable_relationship_prediction=True,  # Use LLM for relationship prediction
    enable_dynamic_hop_selection=True,    # Adapt hop depth to query
    final_top_k=3,                       # Return top 3 results
    rerank_weight_primary=0.7,           # Increase primary node weight
    rerank_weight_neighbor=0.3           # Neighbor contribution weight
)

rag = GraphRAGSimilarity(config)
result = rag.run("What vulnerabilities are related to improper input validation?")
```

### Configuration Options

Key parameters in `GraphRAGConfig`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `final_top_k` | 2 | Final results after reranking |
| `zero_hop_top_k` | 3 | Results for 0-hop (semantic only) |
| `max_neighbors_per_node` | 5 | Max 1-hop neighbors to retrieve |
| `enable_second_hop` | True | Enable 2-hop graph traversal |
| `max_second_hop_per_first` | 3 | Max 2-hop per 1-hop neighbor |
| `rerank_weight_primary` | 0.7 | Weight for primary node score |
| `rerank_weight_neighbor` | 0.3 | Weight for neighbor scores |
| `enable_relationship_prediction` | True | Use LLM for relationship prediction |
| `prediction_bonus_score` | 10.0 | Bonus for predicted relationships |
| `enable_dynamic_hop_selection` | True | Adaptive hop depth |

## Dependencies

- **Neo4j**: Graph database with vector index support
- **neo4j-graphrag**: Neo4j GraphRAG library for retrievers
- **Ollama**: Local LLM inference (embeddings + generation)
- **LangChain**: LLM orchestration (ChatOllama)
- **python-dotenv**: Environment variable management from .env files

## Return Format

```python
{
    "answer": "Natural language answer...",
    "mode": "graphrag",
    "sources": [
        {
            "primarySource": {...},
            "firstHopNeighbors": [...],
            "score": 0.85
        }
    ],
    "context": "Formatted context given to LLM...",
    "hop_selection": {
        "hop_depth": 1,
        "reasoning": "...",
        "confidence": 0.92,
        "method": "rule"
    },
    "enhanced_metadata": {
        "node_types": ["UcoCWE", "UcoCVE"],
        "relationship_types": ["UCOEXPLOIT"],
        "score_statistics": {...}
    }
}
```