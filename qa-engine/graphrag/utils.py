"""
Utilities for GraphRAG Pipeline
Contains configuration, enums, and helper functions
"""

import os
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict
import numpy as np
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# ==================== Configuration ====================

@dataclass
class GraphRAGConfig:
    """Configuration for GraphRAG pipeline stages"""
    # Retrieval configuration
    enable_graph_traversal: bool = True  # False = 0-hop pure vector search (regular RAG)
    initial_top_k_multiplier: int = 10  # Fetch 10x candidates for reranking (e.g., 5 * 10 = 50)
    final_top_k: int = 3  # Return top 3 after reranking (for answer generation and visualization)
    zero_hop_top_k: int = 3  # Return top 3 for 0-hop semantic search (no reranking needed)
    max_neighbors_per_node: int = 5  # Safety cap on 1-hop neighbors from DB (soft-pruned by cross-encoder)

    # 2-hop traversal configuration
    enable_second_hop: bool = True  # Enable 2-hop graph traversal
    max_second_hop_per_first: int = 3  # Safety cap on 2-hop neighbors per 1-hop (soft-pruned by cross-encoder)

    # Similarity-ordered neighbor selection
    enable_similarity_neighbor_ordering: bool = False  # Sort neighbors by cosine sim to query before applying cap
    similarity_neighbor_fetch_multiplier: int = 3      # Prefetch N * multiplier neighbors from DB, keep best N after sorting

    # Cross-encoder reranking configuration
    enable_cross_encoder: bool = True  # Use cross-encoder for reranking (replaces cosine similarity)
    cross_encoder_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"  # Cross-encoder model to use

    # Two-pass graph-aware reranking (KGPR + G-RAG + PankRAG)
    rerank_pass1_top_k: int = 20  # Candidates to keep after Pass 1 (graph-enriched CE)
    rerank_enriched_neighbor_count: int = 5  # Neighbors included in Pass 1 enriched text
    rerank_alpha: float = 0.65  # Weight for primary cross-encoder score
    rerank_beta: float = 0.25  # Weight for neighbor cross-encoder signal
    rerank_gamma: float = 0.10  # Weight for structural diversity
    rerank_enriched_max_length: int = 512  # Max chars for enriched text input

    # Subgraph pruning (post-reranking, pre-generation)
    enable_subgraph_pruning: bool = False  # Keep disabled by default for A/B evaluation
    subgraph_prune_budget_hop1: int = 25  # Max total nodes to keep for 1-hop queries
    subgraph_prune_budget_hop2: int = 35  # Max total nodes to keep for 2-hop queries
    subgraph_prune_keep_all_primary: bool = True  # Always keep selected primary nodes
    subgraph_prune_min_first_hop_per_primary: int = 1  # Keep at least N first-hop neighbors per primary
    subgraph_prune_first_hop_edge_cost: float = 1.0  # Cost for keeping a first-hop edge
    subgraph_prune_second_hop_edge_cost: float = 1.4  # Cost for keeping a second-hop edge
    subgraph_prune_weight_lexical: float = 0.55  # Weight for lexical overlap signal
    subgraph_prune_weight_parent: float = 0.35  # Weight for parent primary relevance signal
    subgraph_prune_weight_relation: float = 0.10  # Weight for relation-type overlap signal
    subgraph_prune_second_hop_decay: float = 0.85  # Downweight second-hop prize contribution
    subgraph_prune_enable_diagnostics: bool = True  # Include pruning diagnostics in outputs

    # Hybrid retrieval configuration (BM25 + Vector)
    enable_hybrid_retrieval: bool = True  # Use hybrid retrieval (BM25 + Vector)
    bm25_weight: float = 0.4  # Weight for BM25 scores in hybrid retrieval
    vector_weight: float = 0.6  # Weight for Vector scores in hybrid retrieval
    enable_late_graph_expansion: bool = False  # BM25+Vector flat → RRF top-k → expand seeds only (requires hybrid)
    late_expand_flat_k: int = 0  # Flat pool size per retriever in late-expand (0 = auto: max(top_k*3, 20))

    # Entity name boosting
    enable_entity_name_boosting: bool = True  # Inject exact name matches into candidate pool

    # HyDE (Hypothetical Document Embedding) query expansion
    enable_hyde: bool = False  # Opt-in, adds ~200-500ms latency per query
    hyde_llm_model: str = "llama3:8b"  # Model for generating hypothetical documents

    # Personalized PageRank (PPR) neighbor selection
    enable_ppr: bool = False                   # Replace BFS with PPR (opt-in)
    ppr_damping: float = 0.85                  # Teleport probability = 1 - damping
    ppr_max_iterations: int = 50
    ppr_convergence_tol: float = 1e-6
    ppr_top_k_neighbors: int = 15             # PPR-ranked 1-hop neighbors per seed
    ppr_top_k_second_hop: int = 8             # PPR-ranked 2-hop per 1-hop neighbor
    ppr_min_score_threshold: float = 1e-5     # Floor for inclusion
    ppr_edge_weight_strategy: str = "inv_sqrt_degree"  # "uniform"|"inv_degree"|"inv_sqrt_degree"
    ppr_max_node_degree: int = 5000           # Hub degree cap

    # Embedding model configuration
    embedding_backend: str = "ollama"  # "ollama" or "sentence_transformers"
    embedding_model: str = "nomic-embed-text:latest"  # Model name (Ollama or HuggingFace)
    embedding_query_prefix: str = "search_query: "  # Prefix for query (Ollama models)
    embedding_query_prompt: str = ""  # Prompt name for query (sentence-transformers: "Retrieval-query")
    embedding_doc_prompt: str = ""  # Prompt name for documents (sentence-transformers: "Retrieval-document")

    # Relationship-level retrieval configuration
    enable_relationship_retrieval: bool = False   # Off by default; requires relationship embeddings
    relationship_retrieval_top_k: int = 5         # Number of relationship candidates to retrieve
    relationship_retrieval_weight: float = 0.3    # RRF blending weight for relationship results


# ==================== Neo4j Constants ====================

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
INDEX_NAME = os.getenv("INDEX_NAME")

# Validate required credentials
if not NEO4J_PASSWORD:
    raise ValueError(
        "NEO4J_PASSWORD environment variable is required. "
        "Please set it in your .env file or environment."
    )


# ==================== Enums ====================

class RAGMode(str, Enum):
    """Retrieval modes for GraphRAG"""
    graphrag = "graphrag"


# ==================== Node Type Mappings (Single Source of Truth) ====================
# These define how to extract labels and content for each node type.
# Used to generate both Cypher CASE expressions and Python extraction logic.
# In Cypher templates, {n} is replaced with the actual node variable at generation time.

_LABEL_MAPPING = [
    ('UcoCWE', '{n}.ucocweName'),
    ('UcoCVE', '{n}.label'),
    ('UcoVulnerability', 'COALESCE({n}.label, {n}.uri)'),
    ('UcoexCAPEC', '{n}.label'),
    ('UcoexMITREATTACK', '{n}.ucoexNAME'),
    ('UcoexMITIGATIONS', '{n}.ucoexNAME'),
    ('UcoexSOFTWARE', '{n}.label'),
    ('UcoexGROUPS', '{n}.ucoexNAME'),
    ('UcoexCAMPAIGNS', '{n}.ucoexNAME'),
    ('UcoexCPE', '{n}.cpeName'),
    ('UcoexObservedExample', 'COALESCE({n}.label, {n}.uri)'),
    ('UcoexTACTICS', '{n}.ucoexNAME'),
    ('UcoexMITRED3FEND', '{n}.ucoexMITRED3FEND_LABEL'),
]

_PRIMARY_CONTENT_MAPPING = [
    ('UcoCWE', "COALESCE({n}.ucocweExtendedSummary, {n}.ucocweSummary, '')"),
    ('UcoCVE', "COALESCE({n}.ucosummary, {n}.ucobaseSeverity, '')"),
    ('UcoVulnerability', "COALESCE({n}.ucosummary, '')"),
    ('UcoexCAPEC', "COALESCE({n}.ucoexDescription, '')"),
    ('UcoexMITREATTACK', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexMITIGATIONS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexSOFTWARE', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexGROUPS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexCAMPAIGNS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexCPE', "COALESCE({n}.cpeName, '')"),
    ('UcoexObservedExample', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexTACTICS', "COALESCE({n}.ucoexDESCRIPTION, {n}.ucoexDOMAIN, {n}.ucoexNAME, '')"),
    ('UcoexMITRED3FEND', "COALESCE({n}.ucoexMITRED3FEND_DEFINITION, {n}.ucoexMITRED3FEND_LABEL, '')"),
]

_NEIGHBOR_CONTENT_MAPPING = [
    ('UcoCWE', "COALESCE({n}.ucocweSummary, '')"),
    ('UcoCVE', "COALESCE({n}.ucosummary, '')"),
    ('UcoVulnerability', "COALESCE({n}.ucosummary, '')"),
    ('UcoexCAPEC', "COALESCE({n}.ucoexDescription, '')"),
    ('UcoexMITREATTACK', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexMITIGATIONS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexSOFTWARE', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexGROUPS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexCAMPAIGNS', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexCPE', "COALESCE({n}.cpeName, '')"),
    ('UcoexObservedExample', "COALESCE({n}.ucoexDESCRIPTION, '')"),
    ('UcoexTACTICS', "COALESCE({n}.ucoexDESCRIPTION, {n}.ucoexDOMAIN, {n}.ucoexNAME, '')"),
    ('UcoexMITRED3FEND', "COALESCE({n}.ucoexMITRED3FEND_DEFINITION, {n}.ucoexMITRED3FEND_LABEL, '')"),
]

SEARCHABLE_TEXT_PROPERTIES = {
    'UcoCWE': ['ucocweSummary', 'ucocweExtendedSummary', 'ucocweName'],
    'UcoCVE': ['label', 'ucobaseSeverity', 'ucosummary'],
    'UcoVulnerability': ['ucosummary', 'label', 'uri'],
    'UcoexCAPEC': ['label', 'ucoexDescription'],
    'UcoexSOFTWARE': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME', 'label'],
    'UcoexGROUPS': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
    'UcoexCAMPAIGNS': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
    'UcoexMITIGATIONS': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
    'UcoexMITREATTACK': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
    'UcoexObservedExample': ['ucoexDESCRIPTION', 'label', 'uri'],
    'UcoexTACTICS': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
    'UcoexMITRED3FEND': ['ucoexMITRED3FEND_DEFINITION', 'ucoexMITRED3FEND_LABEL'],
    'UcoexCPE': ['cpeName'],
}


# ==================== Cypher Generation Functions ====================

def cypher_label_case(node_var: str, type_expr: str) -> str:
    """Generate Cypher CASE expression for extracting a node's display label.

    Args:
        node_var: Cypher variable for property access (e.g., 'neighbor', 'allNodeProperties')
        type_expr: Cypher expression that yields the node type string
    """
    lines = [f"CASE {type_expr}"]
    for type_name, expr_template in _LABEL_MAPPING:
        expr = expr_template.format(n=node_var)
        lines.append(f"    WHEN '{type_name}' THEN {expr}")
    lines.append(f"    ELSE COALESCE({node_var}.label, {node_var}.uri)")
    lines.append("END")
    return "\n".join(lines)


def cypher_content_case(node_var: str, type_expr: str, primary: bool = True) -> str:
    """Generate Cypher CASE expression for extracting a node's content.

    Args:
        node_var: Cypher variable for property access
        type_expr: Cypher expression that yields the node type string
        primary: True for detailed content (primary nodes), False for compact (neighbors)
    """
    mapping = _PRIMARY_CONTENT_MAPPING if primary else _NEIGHBOR_CONTENT_MAPPING
    lines = [f"CASE {type_expr}"]
    for type_name, expr_template in mapping:
        expr = expr_template.format(n=node_var)
        lines.append(f"    WHEN '{type_name}' THEN {expr}")
    lines.append("    ELSE ''")
    lines.append("END")
    return "\n".join(lines)


# ==================== Item Normalization ====================

def normalize_retrieval_item(item: Dict) -> Dict:
    """Normalize a retrieval item to a flat dict format.

    Retrieval modules return items wrapped in a metadata envelope:
        {"content": ..., "metadata": {"primarySource": {...}, "firstHopNeighbors": [...]}}
    Rerankers and downstream stages expect a flat format:
        {"primarySource": {...}, "firstHopNeighbors": [...], "score": ...}

    Calling this after retrieval ensures all downstream stages see a single format.
    """
    if isinstance(item, dict) and 'metadata' in item:
        metadata = item['metadata']
        primary = metadata.get('primarySource', {})
        neighbors = metadata.get('firstHopNeighbors', [])
        return {
            'primarySource': primary,
            'firstHopNeighbors': neighbors,
            'score': primary.get('score', 0.0),
        }
    # Already flat or unknown format -- pass through
    return item


# ==================== Helper Functions ====================

def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors"""
    if not vec1 or not vec2:
        return 0.0
    v1 = np.array(vec1)
    v2 = np.array(vec2)
    return float(np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2)))


def get_node_label(node_type: str, props: Dict) -> str:
    """Extract display label from node based on type (Python-side extraction)"""
    label_map = {
        'UcoCWE': props.get('ucocweName', ''),
        'UcoCVE': props.get('label', ''),
        'UcoVulnerability': props.get('label', props.get('uri', '')),
        'UcoexCAPEC': props.get('label', ''),
        'UcoexMITREATTACK': props.get('ucoexNAME', ''),
        'UcoexMITIGATIONS': props.get('ucoexNAME', ''),
        'UcoexSOFTWARE': props.get('label', ''),
        'UcoexGROUPS': props.get('ucoexNAME', ''),
        'UcoexCAMPAIGNS': props.get('ucoexNAME', ''),
        'UcoexCPE': props.get('cpeName', ''),
        'UcoexObservedExample': props.get('label', props.get('uri', '')),
        'UcoexTACTICS': props.get('ucoexNAME', ''),
        'UcoexMITRED3FEND': props.get('ucoexMITRED3FEND_LABEL', ''),
    }
    return label_map.get(node_type, props.get('label', props.get('uri', 'Unknown')))


def get_node_content(node_type: str, props: Dict) -> str:
    """Extract content from node based on type (Python-side extraction)"""
    content_map = {
        'UcoCWE': props.get('ucocweExtendedSummary', props.get('ucocweSummary', '')),
        'UcoCVE': props.get('ucosummary', props.get('ucobaseSeverity', '')),
        'UcoVulnerability': props.get('ucosummary', ''),
        'UcoexCAPEC': props.get('ucoexDescription', ''),
        'UcoexMITREATTACK': props.get('ucoexDESCRIPTION', ''),
        'UcoexMITIGATIONS': props.get('ucoexDESCRIPTION', ''),
        'UcoexSOFTWARE': props.get('ucoexDESCRIPTION', ''),
        'UcoexGROUPS': props.get('ucoexDESCRIPTION', ''),
        'UcoexCAMPAIGNS': props.get('ucoexDESCRIPTION', ''),
        'UcoexCPE': props.get('cpeName', ''),
        'UcoexObservedExample': props.get('ucoexDESCRIPTION', ''),
        'UcoexTACTICS': ' | '.join(filter(None, [
            props.get('ucoexDESCRIPTION', ''),
            props.get('ucoexDOMAIN', ''),
            props.get('ucoexNAME', '')
        ])) or '',
        'UcoexMITRED3FEND': ' | '.join(filter(None, [
            props.get('ucoexMITRED3FEND_DEFINITION', ''),
            props.get('ucoexMITRED3FEND_LABEL', '')
        ])) or '',
    }
    return content_map.get(node_type, '')
