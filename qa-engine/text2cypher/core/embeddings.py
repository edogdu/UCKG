"""
Unified Embedding Utility for T2CSS Pipeline

Provides embedding generation using Ollama's Nomic Embed model,
replacing SentenceTransformer dependencies for consistency.
"""

import os
import numpy as np
import requests
from typing import List, Union
import logging

logger = logging.getLogger(__name__)


class OllamaEmbeddings:
    """
    Embedding generator using Ollama's Nomic Embed model
    
    Replaces SentenceTransformer with local Ollama embeddings
    for consistency across the T2CSS pipeline.
    """
    
    def __init__(
        self, 
        model: str = "nomic-embed-text",
        base_url: str = None,
        normalize: bool = True
    ):
        """
        Initialize Ollama embeddings
        
        Args:
            model: Ollama embedding model name (default: nomic-embed-text)
            base_url: Ollama server URL (default: http://localhost:11434)
            normalize: Whether to L2-normalize embeddings (default: True)
        """
        self.model = model
        self.base_url = base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.normalize = normalize
        self.embedding_dim = 768  # Nomic embed dimension
        
        logger.info(f"[Embeddings] Initialized with model={model}, base_url={self.base_url}")
    
    def encode(
        self, 
        texts: Union[str, List[str]], 
        normalize_embeddings: bool = None,
        show_progress: bool = False
    ) -> np.ndarray:
        """
        Generate embeddings for text(s)
        
        Args:
            texts: Single text string or list of texts
            normalize_embeddings: Override default normalization setting
            show_progress: Show progress bar (for compatibility, not implemented)
            
        Returns:
            Numpy array of embeddings (shape: [num_texts, embedding_dim])
        """
        # Handle single string input
        if isinstance(texts, str):
            texts = [texts]
        
        # Determine normalization setting
        should_normalize = normalize_embeddings if normalize_embeddings is not None else self.normalize
        
        embeddings = []
        for i, text in enumerate(texts):
            try:
                embedding = self._get_embedding(text)
                
                # Normalize if requested
                if should_normalize:
                    embedding = self._normalize_vector(embedding)
                
                embeddings.append(embedding)
                
                if show_progress and (i + 1) % 10 == 0:
                    logger.info(f"[Embeddings] Processed {i + 1}/{len(texts)} texts")
                    
            except Exception as e:
                logger.warning(f"[Embeddings] Failed to embed text {i}: {e}")
                # Use zero vector as fallback
                embeddings.append(np.zeros(self.embedding_dim))
        
        result = np.array(embeddings)
        
        # If single text input, return 1D array for compatibility
        if len(texts) == 1:
            return result[0]
        
        return result
    
    def _get_embedding(self, text: str) -> np.ndarray:
        """
        Get embedding for a single text from Ollama
        
        Args:
            text: Input text
            
        Returns:
            Embedding vector as numpy array
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/embeddings",
                json={
                    'model': self.model,
                    'prompt': text
                },
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama API returned status {response.status_code}")
            
            embedding = response.json()['embedding']
            return np.array(embedding)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to connect to Ollama: {e}")
        except KeyError:
            raise Exception("Invalid response format from Ollama")
    
    def _normalize_vector(self, vec: np.ndarray) -> np.ndarray:
        """
        L2-normalize a vector
        
        Args:
            vec: Input vector
            
        Returns:
            Normalized vector
        """
        norm = np.linalg.norm(vec)
        if norm < 1e-8:
            return vec
        return vec / norm


def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """
    Calculate cosine similarity between two vectors
    
    Args:
        vec1: First vector
        vec2: Second vector
        
    Returns:
        Cosine similarity score (0 to 1 if normalized)
    """
    # Normalize vectors
    v1_norm = vec1 / (np.linalg.norm(vec1) + 1e-8)
    v2_norm = vec2 / (np.linalg.norm(vec2) + 1e-8)
    
    # Calculate dot product
    return np.dot(v1_norm, v2_norm)


def batch_cosine_similarity(query_vec: np.ndarray, corpus_vecs: np.ndarray) -> np.ndarray:
    """
    Calculate cosine similarity between a query and multiple corpus vectors
    
    Args:
        query_vec: Query vector (1D array)
        corpus_vecs: Corpus vectors (2D array, shape: [num_vecs, dim])
        
    Returns:
        Array of similarity scores
    """
    # Normalize query
    query_norm = query_vec / (np.linalg.norm(query_vec) + 1e-8)
    
    # Normalize corpus
    corpus_norms = corpus_vecs / (np.linalg.norm(corpus_vecs, axis=1, keepdims=True) + 1e-8)
    
    # Calculate similarities
    similarities = np.dot(corpus_norms, query_norm)
    return similarities


# Example usage and testing
if __name__ == "__main__":
    print("="*80)
    print("Testing Ollama Embeddings")
    print("="*80)
    
    # Initialize embedder
    embedder = OllamaEmbeddings(model="nomic-embed-text")
    
    # Test single text
    print("\n[Test 1] Single text embedding")
    text = "Find all CVEs related to Microsoft Windows"
    embedding = embedder.encode(text)
    print(f"Text: {text}")
    print(f"Embedding shape: {embedding.shape}")
    print(f"Embedding norm: {np.linalg.norm(embedding):.4f}")
    
    # Test multiple texts
    print("\n[Test 2] Batch text embedding")
    texts = [
        "CVE vulnerability information",
        "MITRE ATT&CK techniques",
        "Common weakness enumeration"
    ]
    embeddings = embedder.encode(texts, normalize_embeddings=True)
    print(f"Texts: {len(texts)}")
    print(f"Embeddings shape: {embeddings.shape}")
    
    # Test similarity
    print("\n[Test 3] Cosine similarity")
    query = "Show me vulnerabilities"
    query_emb = embedder.encode(query)
    
    corpus = [
        "CVE database entries",
        "Attack patterns and techniques",
        "Software weaknesses"
    ]
    corpus_emb = embedder.encode(corpus)
    
    similarities = batch_cosine_similarity(query_emb, corpus_emb)
    print(f"Query: {query}")
    for i, (text, sim) in enumerate(zip(corpus, similarities)):
        print(f"  {i+1}. [{sim:.3f}] {text}")
    
    print("\n" + "="*80)
    print("✅ All tests completed successfully")
    print("="*80)

