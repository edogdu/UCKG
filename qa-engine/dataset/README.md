# GraphRAG Evaluation Dataset

Evaluate and compare GraphRAG retrieval configurations using sub-graph coverage metrics on a cybersecurity knowledge graph (CWE/CVE/CAPEC).

## Directory Structure

```
qa-engine/dataset/
├── README.md                      # This file
├── experiment_config.py           # Experiment configurations (embedding x retrieval combos)
├── create_evaluation_dataset.py   # Step 1: Generate datasets by running questions through pipeline
├── evaluate_coverage.py           # Step 2: Calculate recall/precision/F1 metrics
├── compare_experiments.py         # Step 3: Compare experiments, generate reports
├── experiment_analysis.ipynb      # Step 4: Visualize results (plots, tables)
├── evaluation_dataset.json        # Root-level generated dataset
├── test_evaluation_dataset.py     # Tests for evaluation logic
├── test_evaluation_output.json    # Test output data
├── explore_node_coverage.ipynb    # Notebook for exploring node coverage
└── experiments/                   # Output directory (one folder per experiment)
    ├── <experiment_name>/
    │   ├── config.json
    │   ├── evaluation_dataset.json
    │   ├── retrieval_metrics_results.json
    │   └── retrieval_metrics_detailed.csv
    ├── comparison_report.json
    ├── summary_table.csv
    ├── precision_recall.png
    ├── precision_recall_by_model.png
    ├── precision_recall_by_model_lines.png
    ├── overall_comparison.png
    └── hop_comparison.png
```

## Workflow

```
1. Generate Dataset          python create_evaluation_dataset.py --experiment <name>
        │                    Reads questions from shared/question_set/ (0/1/2-hop),
        │                    runs each through GraphRAG, captures context + key entity URIs.
        ▼
2. Evaluate Metrics          python evaluate_coverage.py --experiment <name>
        │                    Compares retrieved key_entities against gold-standard nodes.
        │                    Outputs recall, precision, F1 per sample and aggregated.
        ▼
3. Compare Results           python compare_experiments.py
        │                    Loads all experiment results, groups by embedding model,
        │                    ranks by F1, exports comparison_report.json + summary_table.csv.
        ▼
4. Visualize                 jupyter notebook experiment_analysis.ipynb
                             Generates precision-recall plots, hop-wise comparisons.
```

## Quick Start

```bash
cd qa-engine
source venv/bin/activate

# List available experiments
python dataset/create_evaluation_dataset.py --list

# Run an experiment (supports checkpoint/resume and Ctrl+C graceful shutdown)
python dataset/create_evaluation_dataset.py --experiment nomic_baseline
python dataset/evaluate_coverage.py --experiment nomic_baseline

# Compare all completed experiments
python dataset/compare_experiments.py
```

## Evaluation Metrics

Based on Zhu et al. (2025) "Knowledge graph based question-answering model with subgraph retrieval optimization".

| Metric | Formula | Description |
|--------|---------|-------------|
| **Recall** | `\|G ∩ E\| / \|G\|` | % of gold nodes retrieved |
| **Precision** | `\|G ∩ E\| / \|E\|` | % of retrieved nodes that are relevant |
| **F1** | `2 x P x R / (P + R)` | Balanced retrieval quality |

**Ground Truth (G)**: Nodes from question file
- 0-hop: `first_node`
- 1-hop: `first_node`, `second_node`
- 2-hop: `first_node`, `second_node`, `third_node`

**Retrieved (E)**: `key_entities` - URIs of all visited nodes during retrieval

## Experiment Configurations

Naming convention: `{embedding}_{retrieval_method}`

Configurations are generated as a cross-product of embedding models and retrieval methods in `experiment_config.py`.

### Embedding Models

| Prefix | Backend | Model |
|--------|---------|-------|
| `nomic_` | Ollama | nomic-embed-text:latest |
| `gemma_ollama_` | Ollama | embeddinggemma:latest |
| `gemma_` | Sentence-Transformers | google/embeddinggemma-300M |
| `securebert_` | Sentence-Transformers | cisco-ai/SecureBERT2.0-biencoder |

Sentence-transformers models require: `pip install sentence-transformers`

### Retrieval Methods

| Suffix | Description |
|--------|-------------|
| `baseline` | Vector search only (2-hop traversal) |
| `hybrid_04` | Hybrid: 40% BM25 + 60% vector |
| `hybrid_05` | Hybrid: 50% BM25 + 50% vector |
| `hybrid_06` | Hybrid: 60% BM25 + 40% vector |
| `cross_encoder` | Vector + cross-encoder reranking (ms-marco-MiniLM-L-6-v2) |
| `hybrid_cross_encoder` | Hybrid (40/60) + cross-encoder reranking |
| `1hop` | 1-hop traversal only |
| `topk3` / `topk5` | Different final_top_k values |

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

Or add a new embedding model to `EMBEDDING_CONFIGS` and/or a new retrieval method to `RETRIEVAL_CONFIGS` - all cross-product combinations are generated automatically.

Run `python dataset/create_evaluation_dataset.py --list` to see all available configurations.
