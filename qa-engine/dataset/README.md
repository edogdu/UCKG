# GraphRAG Evaluation Dataset

Evaluate and compare GraphRAG retrieval configurations using node coverage metrics.

## Directory Structure

```
qa-engine/dataset/
├── README.md                      # This file
├── experiment_config.py           # Experiment configurations
├── create_evaluation_dataset.py   # Generate datasets
├── evaluate_node_coverage.py      # Calculate metrics
├── compare_experiments.py         # Compare experiments
├── experiment_analysis.ipynb      # Visualize results
└── experiments/                   # Output directory
    ├── baseline_vector/
    │   ├── config.json
    │   ├── evaluation_dataset.json
    │   ├── retrieval_metrics_results.json
    │   └── retrieval_metrics_detailed.csv
    ├── hybrid_bm25_04/
    │   └── ...
    └── comparison_report.json
```

## Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Generate Dataset                                                │
│     python create_evaluation_dataset.py --experiment <name>         │
│                          │                                          │
│                          ▼                                          │
│  2. Evaluate Metrics                                                │
│     python evaluate_node_coverage.py --experiment <name>            │
│                          │                                          │
│                          ▼                                          │
│  3. Compare Results                                                 │
│     python compare_experiments.py                                   │
│                          │                                          │
│                          ▼                                          │
│  4. Visualize                                                       │
│     jupyter notebook experiment_analysis.ipynb                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
cd qa-engine
source venv/bin/activate

# List available experiments
python dataset/create_evaluation_dataset.py --list

# Run an experiment
python dataset/create_evaluation_dataset.py --experiment baseline_vector
python dataset/evaluate_node_coverage.py --experiment baseline_vector

# Compare all experiments
python dataset/compare_experiments.py
```

## Evaluation Metrics

Based on Zhu et al. (2025) "Knowledge graph based question-answering model with subgraph retrieval optimization"

| Metric | Formula | Description |
|--------|---------|-------------|
| **Recall** | `\|G ∩ E\| / \|G\|` | % of gold nodes retrieved |
| **Precision** | `\|G ∩ E\| / \|E\|` | % of retrieved nodes that are relevant |
| **F1** | `2×P×R / (P+R)` | Balanced retrieval quality |

**Ground Truth (G)**: Nodes from question file
- 0-hop: `first_node`
- 1-hop: `first_node`, `second_node`
- 2-hop: `first_node`, `second_node`, `third_node`

**Retrieved (E)**: `key_entities` - URIs of all visited nodes

## Experiment Configurations

Naming convention: `{embedding}_{retrieval_method}`

### Embedding Models

| Prefix | Backend | Model |
|--------|---------|-------|
| `nomic_` | Ollama | nomic-embed-text:latest |
| `gemma_ollama_` | Ollama | embeddinggemma:latest |
| `gemma_` | Sentence-Transformers | google/embeddinggemma-300M |
| `securebert_` | Sentence-Transformers | cisco-ai/SecureBERT2.0-biencoder |

**Note:** Sentence-transformers models require: `pip install sentence-transformers`

### Retrieval Methods

| Suffix | Description |
|--------|-------------|
| `baseline` | Vector search only (2-hop) |
| `hybrid_04` | Hybrid: 40% BM25 + 60% vector |
| `hybrid_05` | Hybrid: 50% BM25 + 50% vector |
| `hybrid_06` | Hybrid: 60% BM25 + 40% vector |
| `cross_encoder` | Vector + cross-encoder reranking |
| `hybrid_cross_encoder` | Hybrid + cross-encoder |
| `1hop` | 1-hop traversal only |
| `topk3` / `topk5` | Different top-k values |

### Examples

```bash
# Nomic baseline
python dataset/create_evaluation_dataset.py --experiment nomic_baseline

# Gemma with hybrid retrieval
python dataset/create_evaluation_dataset.py --experiment gemma_hybrid_04
```

Run `python dataset/create_evaluation_dataset.py --list` for all configurations.

## Adding New Experiments

Edit `experiment_config.py`:

```python
EXPERIMENTS = {
    "my_experiment": {
        "description": "Description of the experiment",
        "config": {
            "enable_hybrid_retrieval": True,
            "bm25_weight": 0.4,
            "vector_weight": 0.6,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
        }
    }
}
```
