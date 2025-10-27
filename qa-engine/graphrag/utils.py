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
    initial_top_k_multiplier: int = 1
    final_top_k: int = 2  # Return top 2 after reranking (for answer generation and visualization)
    zero_hop_top_k: int = 3  # Return top 3 for 0-hop semantic search (no reranking needed)
    max_neighbors_per_node: int = 5  # Max 1-hop neighbors to retrieve

    # Reranking weights
    rerank_weight_primary: float = 0.7  # Weight for primary node score
    rerank_weight_neighbor: float = 0.3  # Weight for neighbor scores
    top_neighbor_count_for_scoring: int = 3  # Top N neighbors to include in scoring

    # 2-hop traversal configuration
    enable_second_hop: bool = True  # Enable 2-hop graph traversal
    max_second_hop_per_first: int = 3  # Max 2-hop neighbors per 1-hop neighbor

    # Schema-guided traversal configuration
    enable_relationship_prediction: bool = True  # Use LLM to predict relevant relationships
    prediction_bonus_score: float = 10.0  # Bonus points for predicted relationships
    max_relationships_per_hop: int = 2  # Max relationship types to traverse per node
    llm_model: str = "llama3.1:8b"  # Model for relationship prediction

    # Dynamic hop selection configuration
    enable_dynamic_hop_selection: bool = True  # Dynamically adjust hop depth based on query complexity
    hop_selection_llm_threshold: float = 0.7  # Confidence threshold to use LLM (vs rule-based)
    hop_selection_enable_llm: bool = True  # Use LLM for ambiguous queries


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
    hybrid = "hybrid"


# ==================== Helper Functions ====================

def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors"""
    if not vec1 or not vec2:
        return 0.0
    v1 = np.array(vec1)
    v2 = np.array(vec2)
    return float(np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2)))


def get_node_label(node_type: str, props: Dict) -> str:
    """Extract display label from node based on type"""
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
    """Extract content from node based on type"""
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
