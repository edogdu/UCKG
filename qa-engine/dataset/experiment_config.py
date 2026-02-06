"""
Experiment Configuration for GraphRAG Evaluation

Defines different GraphRAG configurations to compare retrieval methods.
Each experiment has a unique name and a set of GraphRAGConfig parameters.

Naming convention: {embedding}_{retrieval_method}
  - embedding: nomic, gemma, securebert
  - retrieval_method: baseline, hybrid_04, cross_encoder, etc.

Usage:
    from experiment_config import EXPERIMENTS, get_experiment_config

    config = get_experiment_config("nomic_baseline")
    rag = GraphRAGSimilarity(config)
"""

from dataclasses import asdict
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from graphrag.utils import GraphRAGConfig


# ==================== Embedding Model Configurations ====================

EMBEDDING_CONFIGS = {
    # Ollama-based embeddings
    "nomic": {
        "embedding_backend": "ollama",
        "embedding_model": "nomic-embed-text:latest",
        "embedding_query_prefix": "search_query: ",
        "embedding_query_prompt": "",
        "embedding_doc_prompt": "",
    },
    "gemma_ollama": {
        "embedding_backend": "ollama",
        "embedding_model": "embeddinggemma:latest",
        "embedding_query_prefix": "",
        "embedding_query_prompt": "",
        "embedding_doc_prompt": "",
    },

    # Sentence-transformers based embeddings (requires: pip install sentence-transformers)
    "gemma": {
        "embedding_backend": "sentence_transformers",
        "embedding_model": "google/embeddinggemma-300M",
        "embedding_query_prefix": "",
        "embedding_query_prompt": "Retrieval-query",
        "embedding_doc_prompt": "Retrieval-document",
    },
    "securebert": {
        "embedding_backend": "sentence_transformers",
        "embedding_model": "cisco-ai/SecureBERT2.0-biencoder",
        "embedding_query_prefix": "",
        "embedding_query_prompt": "",  # SecureBERT doesn't use special prompts
        "embedding_doc_prompt": "",
    },
}


# ==================== Retrieval Method Configurations ====================

RETRIEVAL_CONFIGS = {
    # Baseline: Vector search only
    "baseline": {
        "description": "Vector search only with 2-hop traversal",
        "config": {
            "enable_hybrid_retrieval": False,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
            "enable_dynamic_hop_selection": False,
            "enable_relationship_prediction": False,
        }
    },

    # Hybrid retrieval variants
    "hybrid_04": {
        "description": "Hybrid BM25+Vector (0.4/0.6)",
        "config": {
            "enable_hybrid_retrieval": True,
            "bm25_weight": 0.4,
            "vector_weight": 0.6,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
        }
    },
    "hybrid_05": {
        "description": "Hybrid BM25+Vector (0.5/0.5)",
        "config": {
            "enable_hybrid_retrieval": True,
            "bm25_weight": 0.5,
            "vector_weight": 0.5,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
        }
    },
    "hybrid_06": {
        "description": "Hybrid BM25+Vector (0.6/0.4)",
        "config": {
            "enable_hybrid_retrieval": True,
            "bm25_weight": 0.6,
            "vector_weight": 0.4,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
        }
    },

    # Cross-encoder reranking
    "cross_encoder": {
        "description": "Vector + Cross-encoder reranking",
        "config": {
            "enable_hybrid_retrieval": False,
            "enable_cross_encoder": True,
            "cross_encoder_model": "cross-encoder/ms-marco-MiniLM-L-6-v2",
            "enable_second_hop": True,
        }
    },
    "hybrid_cross_encoder": {
        "description": "Hybrid + Cross-encoder reranking",
        "config": {
            "enable_hybrid_retrieval": True,
            "bm25_weight": 0.4,
            "vector_weight": 0.6,
            "enable_cross_encoder": True,
            "cross_encoder_model": "cross-encoder/ms-marco-MiniLM-L-6-v2",
            "enable_second_hop": True,
        }
    },

    # Hop depth variants
    "1hop": {
        "description": "Vector search with 1-hop traversal only",
        "config": {
            "enable_hybrid_retrieval": False,
            "enable_cross_encoder": False,
            "enable_second_hop": False,
        }
    },

    # Top-k variants
    "topk3": {
        "description": "Vector search with final_top_k=3",
        "config": {
            "enable_hybrid_retrieval": False,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
            "final_top_k": 3,
        }
    },
    "topk5": {
        "description": "Vector search with final_top_k=5",
        "config": {
            "enable_hybrid_retrieval": False,
            "enable_cross_encoder": False,
            "enable_second_hop": True,
            "final_top_k": 5,
        }
    },
}


# ==================== Generate Combined Experiments ====================

def _generate_experiments():
    """Generate all experiment combinations (embedding × retrieval method)"""
    experiments = {}

    for emb_name, emb_config in EMBEDDING_CONFIGS.items():
        for ret_name, ret_config in RETRIEVAL_CONFIGS.items():
            exp_name = f"{emb_name}_{ret_name}"

            # Merge configs
            combined_config = {**ret_config["config"], **emb_config}

            experiments[exp_name] = {
                "description": f"[{emb_name}] {ret_config['description']}",
                "embedding_model": emb_config["embedding_model"],
                "config": combined_config,
            }

    return experiments


EXPERIMENTS = _generate_experiments()


# ==================== Helper Functions ====================

def get_experiment_config(experiment_name: str) -> GraphRAGConfig:
    """
    Get GraphRAGConfig for a named experiment.

    Args:
        experiment_name: Name of the experiment (must be in EXPERIMENTS dict)

    Returns:
        GraphRAGConfig with the experiment settings applied

    Raises:
        ValueError: If experiment_name is not found
    """
    if experiment_name not in EXPERIMENTS:
        available = ", ".join(sorted(EXPERIMENTS.keys()))
        raise ValueError(
            f"Unknown experiment: '{experiment_name}'. "
            f"Available experiments: {available}"
        )

    experiment = EXPERIMENTS[experiment_name]
    config_overrides = experiment.get("config", {})

    # Create config with overrides
    return GraphRAGConfig(**config_overrides)


def get_experiment_metadata(experiment_name: str) -> dict:
    """
    Get full metadata for an experiment including description and config.

    Args:
        experiment_name: Name of the experiment

    Returns:
        Dictionary with experiment metadata
    """
    if experiment_name not in EXPERIMENTS:
        raise ValueError(f"Unknown experiment: '{experiment_name}'")

    experiment = EXPERIMENTS[experiment_name]
    config = get_experiment_config(experiment_name)

    return {
        "name": experiment_name,
        "description": experiment.get("description", ""),
        "embedding_model": experiment.get("embedding_model", ""),
        "config": asdict(config),
    }


def list_experiments() -> None:
    """Print all available experiments with descriptions."""
    print("Available Experiments:")
    print("=" * 80)

    # Group by embedding model
    current_embedding = None
    for name in sorted(EXPERIMENTS.keys()):
        exp = EXPERIMENTS[name]
        emb = name.split("_")[0]

        if emb != current_embedding:
            if current_embedding is not None:
                print()
            print(f"\n[{emb.upper()}] {EMBEDDING_CONFIGS.get(emb, {}).get('embedding_model', 'unknown')}")
            print("-" * 80)
            current_embedding = emb

        desc = exp.get("description", "No description")
        # Remove embedding prefix from description for cleaner output
        desc = desc.replace(f"[{emb}] ", "")
        print(f"  {name:30} - {desc}")

    print("\n" + "=" * 80)


def list_embedding_models() -> None:
    """Print available embedding models."""
    print("Available Embedding Models:")
    print("=" * 50)
    for name, config in EMBEDDING_CONFIGS.items():
        print(f"  {name:15} - {config['embedding_model']}")
    print("=" * 50)


if __name__ == "__main__":
    # If run directly, list all experiments
    list_experiments()
