# GraphRAG Pipeline

A modular pipeline for cybersecurity knowledge graph question answering. It combines hybrid BM25+vector retrieval with two-pass cross-encoder reranking (KGPR, G-RAG, PankRAG) to find and rank relevant nodes in a Neo4j knowledge graph, then generates answers with a local LLM. Supports Ollama and sentence-transformers embedding backends.

## Quick Start

### Environment Setup

Create a `.env` file in the `qa-engine/` directory:

```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password_here
INDEX_NAME=global_embedding_idx
```

### Basic Usage

```python
from graphrag import GraphRAGSimilarity

rag = GraphRAGSimilarity()
result = rag.run("What is SQL injection?")

print(result["answer"])
print(result["sources"])
```

## Architecture

```
Stage 1–2: Retrieval  (Hybrid BM25+Vector → Graph Traversal / PPR)
              ↓
Stage 2.5: Entity Name Boosting + Relationship Retrieval injection
              ↓
Stage 3: Two-Pass Reranking  (KGPR Pass 1 → G-RAG + PankRAG Pass 2)
              ↓
Stage 3.5: Subgraph Pruning  (PCST-style, optional)
              ↓
Stage 4: Generation  (Context Formatting → LLM Answer)
```

## Module Structure

```
graphrag/
├── __init__.py          # Public API: GraphRAGSimilarity, GraphRAGConfig, RAGMode, ...
├── utils.py             # GraphRAGConfig dataclass, helpers, constants
├── pipeline.py          # Main orchestrator (GraphRAGSimilarity)
├── generation.py        # ContextFormatter, AnswerGenerator
├── retrieval/
│   ├── vector.py        # Stage 1-2: Semantic search + BFS graph traversal
│   ├── hybrid.py        # BM25 + Vector RRF fusion
│   ├── bm25.py          # BM25 keyword retriever (with disk cache)
│   ├── ppr.py           # Personalized PageRank neighbor selection
│   └── relationship.py  # Relationship-level vector search
├── reranking/
│   ├── cross_encoder.py # Two-pass KGPR + G-RAG + PankRAG reranker
│   ├── cosine.py        # Legacy cosine-similarity reranker (fallback)
│   └── pruner.py        # PCST-style subgraph pruner
├── tests/               # Unit + integration tests
└── docs/                # Feature-specific documentation
```

## Pipeline Stages

### Stage 1–2: Retrieval

**Hybrid BM25 + Vector Search**:
- BM25 keyword search and vector similarity search run in parallel
- Results fused via Reciprocal Rank Fusion (RRF) before graph traversal
- BM25 index is disk-cached for fast repeated queries

**Graph Traversal / PPR**:
- For each seed candidate, retrieve 1-hop and 2-hop neighbors via BFS
- Optionally replace BFS with Personalized PageRank (PPR) for more precise neighbor selection
- Cypher queries are dynamically generated based on hop depth

**Entity Name Boosting** (Stage 2.5):
- Exact entity name matches are injected into the candidate pool to prevent vector search from missing obvious hits

**Relationship Retrieval** (Stage 2.5, optional):
- Relationship-level vector search finds additional relevant edges and injects them into the context pool

### Stage 3: Two-Pass Reranking

**Pass 1 — KGPR (Knowledge Graph-enriched Passage Reranking)**:
- Each candidate is scored using a cross-encoder on enriched text (primary content + top neighbors concatenated)
- Pool is pruned to `rerank_pass1_top_k` survivors

**Pass 2 — G-RAG + PankRAG composite**:
- **G-RAG**: each neighbor is individually scored by the cross-encoder; neighbor CE scores provide a structural signal
- **PankRAG**: final score = `α × primary_CE + β × neighbor_CE_signal + γ × structural_diversity`
- Final `final_top_k` results are selected

**Fallback**: if `enable_cross_encoder=False`, a legacy cosine-similarity reranker is used.

### Stage 3.5: Subgraph Pruning (optional)

When `enable_subgraph_pruning=True`, a PCST-style pruner trims the neighbor graph post-reranking:
- Assigns a prize to each neighbor node (lexical overlap + parent relevance + relation-type signal)
- Keeps nodes within a budget (`subgraph_prune_budget_hop1` / `subgraph_prune_budget_hop2`)
- Diagnostics are included in `pruning_metadata` when `subgraph_prune_enable_diagnostics=True`

### Stage 4: Generation

**Context Formatting**:
- Format primary nodes, 1-hop relationships, and 2-hop connections into structured text
- Preserve cybersecurity-specific attributes (CVE IDs, CWE IDs, CVSS scores, etc.)

**Answer Generation**:
- Use ChatOllama (`llama3:8b`) with a specialized cybersecurity prompt
- Focus on the primary node's relationship tree with technical details

## Configuration

```python
from graphrag import GraphRAGSimilarity, GraphRAGConfig

config = GraphRAGConfig(
    final_top_k=3,
    enable_hybrid_retrieval=True,
    enable_cross_encoder=True,
    enable_subgraph_pruning=False,
)

rag = GraphRAGSimilarity(config)
```

### Core Retrieval

| Parameter | Default | Description |
|---|---|---|
| `enable_graph_traversal` | `True` | `False` = 0-hop pure vector search |
| `final_top_k` | `3` | Results returned after reranking |
| `max_neighbors_per_node` | `5` | Max 1-hop neighbors per node |
| `enable_second_hop` | `True` | Enable 2-hop graph traversal |
| `max_second_hop_per_first` | `3` | Max 2-hop per 1-hop neighbor |
| `initial_top_k_multiplier` | `10` | Over-fetch multiplier for reranking |

### Hybrid Retrieval (BM25 + Vector)

| Parameter | Default | Description |
|---|---|---|
| `enable_hybrid_retrieval` | `True` | RRF fusion of BM25 + vector search |

### Two-Pass Reranking

| Parameter | Default | Description |
|---|---|---|
| `enable_cross_encoder` | `True` | Enable transformer-based reranking |
| `cross_encoder_model` | `cross-encoder/ms-marco-MiniLM-L-6-v2` | Model for CE scoring |
| `rerank_pass1_top_k` | `20` | Survivors after Pass 1 |
| `rerank_alpha` | `0.65` | Weight: primary CE score |
| `rerank_beta` | `0.25` | Weight: neighbor CE signal |
| `rerank_gamma` | `0.10` | Weight: structural diversity |

### Subgraph Pruning (optional)

| Parameter | Default | Description |
|---|---|---|
| `enable_subgraph_pruning` | `False` | PCST-style post-rerank pruning |
| `subgraph_prune_budget_hop1` | `25` | Max nodes for 1-hop queries |
| `subgraph_prune_budget_hop2` | `35` | Max nodes for 2-hop queries |

### Embedding Backend

| Parameter | Default | Description |
|---|---|---|
| `embedding_backend` | `"ollama"` | `"ollama"` or `"sentence_transformers"` |
| `embedding_model` | `"nomic-embed-text:latest"` | Embedding model name |

### Optional Features

| Parameter | Default | Description |
|---|---|---|
| `enable_entity_name_boosting` | `True` | Inject exact name matches into pool |
| `enable_hyde` | `False` | HyDE query expansion via LLM |
| `enable_ppr` | `False` | PPR-based neighbor selection |
| `enable_relationship_retrieval` | `False` | Relationship-level vector search |

## Return Format

```python
{
    "answer": "Natural language answer...",
    "mode": "graphrag",
    "sources": [
        {
            "primarySource": {
                "nodeLabel": "SQL Injection",
                "nodeType": "UcoCWE",
                "score": 5.346,
                "crossEncoderScore": 5.346,
                ...
            },
            "firstHopNeighbors": [...],
            "score": 5.346
        }
    ],
    "context": "Formatted context given to LLM...",
    "key_entities": ["SQL Injection", "CWE-89", ...],
    "enhanced_metadata": {
        "node_types": ["UcoCWE", "UcoCVE"],
        "relationship_types": ["UCOEXPLOIT"],
        "score_statistics": {...}
    },
    "pruning_metadata": {
        "nodes_before": 42,
        "nodes_after": 25,
        "budget_used": 25,
        ...
    }
}
```

`pruning_metadata` is only present when `enable_subgraph_pruning=True` and `subgraph_prune_enable_diagnostics=True`.

## Dependencies

- **Neo4j**: Graph database with vector index
- **neo4j-graphrag**: Neo4j GraphRAG library
- **Ollama**: Local LLM (embeddings + generation)
- **sentence-transformers**: Cross-encoder models + optional embedding backend
- **LangChain**: LLM orchestration
- **rank-bm25**: BM25 keyword retrieval
- **scipy**: Subgraph pruning (sparse graph operations)
- **python-dotenv**: Environment variables

## Further Reading

Feature-specific documentation in `docs/`:

- [`docs/HYBRID_RETRIEVAL_README.md`](docs/HYBRID_RETRIEVAL_README.md) — BM25 + RRF fusion details
- [`docs/BM25_CACHE_README.md`](docs/BM25_CACHE_README.md) — BM25 disk caching
- [`docs/DYNAGRAG_DSA_BFS.md`](docs/DYNAGRAG_DSA_BFS.md) — PPR neighbor selection design
- [`docs/IMPROVEMENT_PLAN.md`](docs/IMPROVEMENT_PLAN.md) — roadmap
