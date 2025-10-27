"""
GraphRAG-Similarity System

Modular 4-stage pipeline for cybersecurity knowledge graph QA.

USAGE:
    from graphrag import GraphRAGSimilarity, GraphRAGConfig

    # Use default configuration
    rag = GraphRAGSimilarity()
    result = rag.run("What is SQL injection?")

    # Or customize configuration
    config = GraphRAGConfig(
        enable_second_hop=True,
        enable_relationship_prediction=True,
        final_top_k=3
    )
    rag = GraphRAGSimilarity(config)
    result = rag.run("What vulnerabilities are related to improper input validation?")
"""

from .pipeline import GraphRAGSimilarity
from .utils import GraphRAGConfig, RAGMode

__all__ = [
    'GraphRAGSimilarity',
    'GraphRAGConfig',
    'RAGMode'
]

__version__ = '2.0.0'
__author__ = 'UCKG Team'
