"""
GraphRAG Pipeline

Modular 3-stage pipeline for cybersecurity knowledge graph QA.

USAGE:
    from graphrag import GraphRAGPipeline, GraphRAGConfig

    # Use default configuration
    rag = GraphRAGPipeline()
    result = rag.run("What is SQL injection?")

    # Or customize reranking weights
    config = GraphRAGConfig(
        enable_second_hop=True,
        rerank_alpha=0.65,
        rerank_beta=0.25,
        rerank_gamma=0.10,
        final_top_k=3
    )
    rag = GraphRAGPipeline(config)
    result = rag.run("What vulnerabilities are related to improper input validation?")
"""

from .pipeline import GraphRAGPipeline
from .utils import GraphRAGConfig, RAGMode
from .reranking import CrossEncoderReranker
from .reranking import SubgraphPruner
from .retrieval import PPRRetriever

__all__ = [
    'GraphRAGPipeline',
    'GraphRAGConfig',
    'RAGMode',
    'CrossEncoderReranker',
    'SubgraphPruner',
    'PPRRetriever',
]

__version__ = '3.0.0'
__author__ = 'UCKG Team'
