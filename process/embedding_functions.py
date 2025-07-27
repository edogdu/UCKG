#!/usr/bin/env python3
"""
UCKG Embedding Functions

Essential embedding processor for cybersecurity knowledge graphs.
Optimized for nomic-embed-text performance with property-aware chunking.

Core features:
- Content size classification (small/medium/large nodes)
- Property-aware text generation for better embeddings
- Batch processing with Ollama API
- Optimized chunking (1200 chars ≈ 300 tokens) with context preservation
- Property metadata extraction for precise RAG queries
- Connection pooling and error recovery

Environment variables:
- EMBEDDING_BATCH_SIZE: Batch size for embedding requests (default: 100)

Chunk storage includes:
- text: Full chunk content with property names
- embedding: Vector representation
- properties: List of property names for targeted queries
- chunkIndex: Sequential position
"""

import os
import logging
import requests
from typing import List, Tuple, Optional
from contextlib import contextmanager

from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO').upper())
logger = logging.getLogger(__name__)

# Simplified error handling for essential cases
class EmbeddingError(Exception):
    """Base embedding error for operational issues"""
    pass

class ConfigError(ValueError):
    """Configuration validation error - critical failure"""
    pass

# Environment configuration
def get_config():
    """Load and validate configuration from environment variables"""
    config = {
        'neo4j_uri': os.getenv('NEO4J_URI', 'bolt://neo4j:7687'),
        'neo4j_user': os.getenv('NEO4J_USER', 'neo4j'),
        'neo4j_password': os.getenv('NEO4J_PASSWORD', 'abcd90909090'),
        'ollama_url': os.getenv('OLLAMA_URL', 'http://ollama:11434').rstrip('/'),
        'embedding_model': os.getenv('EMBEDDING_MODEL', 'nomic-embed-text'),
        'embed_enabled': os.getenv('EMBED_ENV', 'false').lower() in ['true', '1', 'yes']
    }
    
    # Validate critical configuration
    if not all([config['neo4j_uri'], config['ollama_url']]):
        raise ConfigError("Missing required configuration: NEO4J_URI or OLLAMA_URL")
    
    return config

class UCKGEmbedder:
    """
    UCKG embedding processor with conditional processing strategy.
    
    Processing approach:
    - Small/medium nodes: Direct summary embedding
    - Large nodes: Text chunking with multiple embeddings
    """
    
    def __init__(self):
        self.config = get_config()
        self._driver = None
        self._session = requests.Session()
        self._session.headers.update({'Content-Type': 'application/json'})
        
        # Essential performance settings optimized for embeddings
        self.batch_size = int(os.getenv('EMBEDDING_BATCH_SIZE', '100'))
        self.chunk_size = 1200  # ~300 tokens - optimal for nomic-embed-text
        self.chunk_overlap = 240  # 20% overlap for context preservation
        
    @contextmanager
    def _neo4j_driver(self):
        """Neo4j driver context manager with connection pooling"""
        if not self._driver:
            try:
                self._driver = GraphDatabase.driver(
                    self.config['neo4j_uri'],
                    auth=(self.config['neo4j_user'], self.config['neo4j_password'])
                )
                # Validate connection
                with self._driver.session() as session:
                    session.run("RETURN 1").single()
            except Exception as e:
                raise EmbeddingError(f"Neo4j connection failed: {e}")
        
        try:
            yield self._driver
        finally:
            pass  # Keep connection alive for reuse
    
    def _create_embedding(self, text: str) -> List[float]:
        """Generate single embedding vector via Ollama API"""
        try:
            response = self._session.post(
                f"{self.config['ollama_url']}/api/embed",
                json={"model": self.config['embedding_model'], "input": text},
                timeout=30
            )
            response.raise_for_status()
            
            embeddings = response.json().get('embeddings', [])
            if not embeddings or not embeddings[0]:
                raise EmbeddingError("Empty embedding response from Ollama")
            return embeddings[0]
            
        except requests.RequestException as e:
            raise EmbeddingError(f"Ollama API request failed: {e}")
    
    def _create_batch_embeddings_bulk(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using batch API with fallback"""
        if not texts:
            return []
            
        try:
            response = self._session.post(
                f"{self.config['ollama_url']}/api/embed",
                json={"model": self.config['embedding_model'], "input": texts},
                timeout=max(60, len(texts) * 2)
            )
            response.raise_for_status()
            
            embeddings = response.json().get('embeddings', [])
            if len(embeddings) == len(texts):
                return embeddings
            
            logger.warning(f"Batch size mismatch, using individual fallback")
            return self._create_batch_embeddings(texts)
            
        except requests.RequestException as e:
            logger.warning(f"Batch API failed: {e}")
            return self._create_batch_embeddings(texts)
    
    def _create_batch_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts with error tolerance"""
        embeddings = []
        failed = 0
        
        for i, text in enumerate(texts):
            try:
                embedding = self._create_embedding(text)
                embeddings.append(embedding)
                
                if (i + 1) % 50 == 0:
                    logger.info(f"Processed {i + 1}/{len(texts)} embeddings")
                    
            except EmbeddingError as e:
                logger.warning(f"Embedding failed for text {i + 1}: {e}")
                embeddings.append([])  # Maintain list alignment
                failed += 1
        
        if failed > 0:
            logger.warning(f"Failed to generate {failed}/{len(texts)} embeddings")
        
        return embeddings
    
    def _chunk_text(self, text: str, node_type: str = None) -> List[str]:
        """Split text into chunks with optional node context"""
        try:
            from langchain_text_splitters import RecursiveCharacterTextSplitter
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
                length_function=len,
                separators=[". ", "\n\n", "\n", " ", ""]  # Property-aware separators
            )
            chunks = splitter.split_text(text)
            
            # Add node context if provided and not already present
            if node_type and chunks:
                context_prefix = f"{node_type} node. "
                enhanced_chunks = []
                for chunk in chunks:
                    if not chunk.strip().startswith(f"{node_type} node"):
                        enhanced_chunks.append(context_prefix + chunk.strip())
                    else:
                        enhanced_chunks.append(chunk)
                chunks = enhanced_chunks
                
            return chunks
        except ImportError:
            # Simple fallback chunking
            context_prefix = f"{node_type} node. " if node_type else ""
            if len(text) <= self.chunk_size:
                if node_type and not text.startswith(f"{node_type} node"):
                    return [context_prefix + text]
                return [text]
            
            chunks = []
            for i in range(0, len(text), self.chunk_size - self.chunk_overlap):
                chunk = text[i:i + self.chunk_size]
                chunks.append(context_prefix + chunk if node_type else chunk)
            
            return chunks
    
    def _extract_properties_from_chunk(self, chunk_text: str) -> List[str]:
        """Extract property names from chunk text for metadata"""
        import re
        # Find all patterns like "property_name:" in the text
        property_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:'
        properties = re.findall(property_pattern, chunk_text)
        return list(set(properties))
    
    def _process_single_large_node(self, session, node_id: str, node_type: str, content: str) -> int:
        """Process a single large node with chunking and embedding"""
        chunks = self._chunk_text(content, node_type)
        if not chunks:
            return 0
        
        chunks_created = 0
        chunk_batch_size = min(self.batch_size // 4, 20)
        
        for i in range(0, len(chunks), chunk_batch_size):
            chunk_batch = chunks[i:i + chunk_batch_size]
            embeddings = self._create_batch_embeddings_bulk(chunk_batch)
            
            # Store chunks with embeddings and property metadata
            for chunk_idx, (chunk_text, embedding) in enumerate(zip(chunk_batch, embeddings)):
                if embedding:
                    # Extract property names for metadata
                    properties = self._extract_properties_from_chunk(chunk_text)
                    
                    session.run(f"""
                        MATCH (original) WHERE elementId(original) = $node_id
                        CREATE (chunk:{node_type}Chunk {{
                            text: $chunk_text,
                            embedding: $embedding,
                            chunkIndex: $chunk_idx,
                            properties: $properties
                        }})
                        CREATE (original)-[:HAS_CHUNK]->(chunk)
                    """, {
                        'node_id': node_id,
                        'chunk_text': chunk_text,
                        'embedding': embedding,
                        'chunk_idx': i + chunk_idx,
                        'properties': properties
                    })
                    chunks_created += 1
        
        return chunks_created
    
    def _classify_content_size(self):
        """Classify nodes by estimated content size using memory-efficient batch processing"""
        logger.info("Starting content size classification for unprocessed nodes")
        
        with self._neo4j_driver() as driver:
            with driver.session() as session:
                try:
                    total_classified = 0
                    batch_size = 500  # Optimized batch size for efficient processing
                    next_milestone = 50000  # Log every 50k nodes for large datasets
                    
                    while True:
                        result = session.run("""
                            MATCH (n)
                            WHERE n.embedding IS NULL 
                              AND NOT labels(n)[0] = '_GraphConfig'
                              AND n.contentSize IS NULL
                            WITH n LIMIT $batch_size
                            WITH n, reduce(totalChars = 0, prop IN keys(n) | 
                                CASE WHEN NOT (prop IN ['embedding', 'contentSize', 'estimatedTokens'])
                                     AND n[prop] IS NOT NULL
                                THEN totalChars + size(
                                    CASE 
                                        WHEN valueType(n[prop]) STARTS WITH 'LIST' 
                                        THEN reduce(listStr = '', item IN n[prop] | listStr + ' ' + toString(item))
                                        ELSE toString(n[prop]) 
                                    END
                                )
                                ELSE totalChars END
                            ) as charCount
                            SET n.contentSize = 
                                CASE 
                                    WHEN charCount * 0.75 <= 200 THEN 'small'
                                    WHEN charCount * 0.75 <= 400 THEN 'medium'
                                    ELSE 'large'
                                END
                            RETURN count(n) as batch_count
                        """, {'batch_size': batch_size})
                        
                        batch_count = result.single()['batch_count']
                        if batch_count == 0:
                            break
                            
                        total_classified += batch_count
                        
                        # Progress logging at defined milestones
                        if total_classified >= next_milestone:
                            logger.info(f"Content classification progress: {total_classified:,} nodes processed")
                            next_milestone += 50000
                    
                    logger.info(f"Content classification completed: {total_classified:,} nodes processed")
                    
                except Exception as e:
                    raise EmbeddingError(f"Content classification failed: {e}")
    
    def _process_small_medium_nodes(self) -> Tuple[int, int]:
        """Process small and medium nodes using memory-efficient streaming"""
        logger.info("Processing small and medium nodes with improved batch processing")
        
        small_count = medium_count = 0
        batch_size = min(self.batch_size, 50)  # Use configurable batch size with upper limit
        
        with self._neo4j_driver() as driver:
            with driver.session() as session:
                try:
                    while True:
                        # Get batch of nodes with property-aware summaries
                        result = session.run("""
                            MATCH (n)
                            WHERE n.embedding IS NULL 
                              AND n.contentSize IN ['small', 'medium']
                            WITH n, elementId(n) as nodeId, n.contentSize as size, labels(n)[0] as nodeType,
                                 reduce(summary = '', prop IN keys(n) | 
                                     CASE WHEN NOT (prop IN ['embedding', 'contentSize', 'estimatedTokens'])
                                          AND n[prop] IS NOT NULL
                                     THEN summary + ' ' + prop + ': ' + 
                                         CASE 
                                             WHEN valueType(n[prop]) STARTS WITH 'LIST' 
                                             THEN reduce(listStr = '', item IN n[prop] | listStr + ' ' + toString(item))
                                             ELSE toString(n[prop]) 
                                         END + '.'
                                     ELSE summary END
                                 ) as summary
                            RETURN nodeId, size, nodeType + ' node. ' + summary as summary
                            LIMIT $batch_size
                        """, {'batch_size': batch_size})
                        
                        nodes = [(r['nodeId'], r['size'], r['summary']) for r in result]
                        if not nodes:
                            break
                        
                        # Process batch with embeddings using bulk method
                        summaries = [node[2] for node in nodes]
                        embeddings = self._create_batch_embeddings_bulk(summaries)
                        
                        # Store results in streaming transaction
                        for (node_id, size, _), embedding in zip(nodes, embeddings):
                            if embedding:
                                session.run("""
                                    MATCH (n) WHERE elementId(n) = $node_id
                                    SET n.embedding = $embedding
                                """, {'node_id': node_id, 'embedding': embedding})
                                
                                if size == 'small':
                                    small_count += 1
                                else:
                                    medium_count += 1
                        
                        logger.info(f"Processed batch: {len(nodes)} nodes (total: {small_count + medium_count})")
                    
                    logger.info(f"Completed processing: {small_count} small, {medium_count} medium nodes")
                    return small_count, medium_count
                    
                except Exception as e:
                    raise EmbeddingError(f"Small/medium node processing failed: {e}")
    
    def _process_large_nodes(self) -> int:
        """Process large nodes using memory-efficient chunking with streaming"""
        logger.info("Processing large nodes with improved chunking")
        
        chunks_created = 0
        batch_size = min(self.batch_size // 10, 10)  # Smaller batch for large nodes
        
        with self._neo4j_driver() as driver:
            with driver.session() as session:
                try:
                    while True:
                        # Get small batch of large nodes with property-aware content
                        result = session.run("""
                            MATCH (n)
                            WHERE n.contentSize = 'large' AND n.embedding IS NULL
                            WITH n, elementId(n) as nodeId, labels(n)[0] as nodeType,
                                 reduce(content = '', prop IN keys(n) | 
                                     CASE WHEN NOT (prop IN ['embedding', 'contentSize', 'estimatedTokens'])
                                          AND n[prop] IS NOT NULL
                                     THEN content + ' ' + prop + ': ' + 
                                         CASE 
                                             WHEN valueType(n[prop]) STARTS WITH 'LIST' 
                                             THEN reduce(listStr = '', item IN n[prop] | listStr + ' ' + toString(item))
                                             ELSE toString(n[prop]) 
                                         END + '.'
                                     ELSE content END
                                 ) as content
                            RETURN nodeId, nodeType, nodeType + ' node. ' + content as content
                            LIMIT $batch_size
                        """, {'batch_size': batch_size})
                        
                        nodes = [(r['nodeId'], r['nodeType'], r['content']) for r in result]
                        if not nodes:
                            break
                        
                        # Process each node with chunking and embedding
                        for node_id, node_type, content in nodes:
                            node_chunks = self._process_single_large_node(
                                session, node_id, node_type, content.strip()
                            )
                            chunks_created += node_chunks
                        
                        logger.info(f"Processed batch: {len(nodes)} large nodes (total chunks: {chunks_created})")
                    
                    logger.info(f"Completed processing large nodes: {chunks_created} chunks created")
                    return chunks_created
                    
                except Exception as e:
                    raise EmbeddingError(f"Large node processing failed: {e}")
    
    def run_complete_pipeline(self):
        """Execute complete embedding pipeline"""
        logger.info("Starting UCKG embedding pipeline")
        
        try:
            # Phase 1: Content size classification
            self._classify_content_size()
            
            # Phase 2: Process small and medium nodes
            small, medium = self._process_small_medium_nodes()
            
            # Phase 3: Process large nodes with chunking
            chunks = self._process_large_nodes()
            
            logger.info("Embedding pipeline completed successfully")
            logger.info(f"Processing summary: {small:,} small, {medium:,} medium nodes, {chunks:,} chunks")
            
        except (ConfigError, ValueError) as e:
            logger.critical(f"Configuration error: {e}")
            raise
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            raise EmbeddingError(f"Pipeline execution failed: {e}")
    
    def close(self):
        """Clean up database connections and resources"""
        if self._driver:
            self._driver.close()
            self._driver = None
        if self._session:
            self._session.close()

# Docker integration entry point
def run_embedding_processing():
    """Main embedding processing function for Docker container integration"""
    config = get_config()
    
    if not config['embed_enabled']:
        logger.info("Embedding processing disabled via EMBED_ENV configuration")
        return
    
    logger.info("Initializing UCKG embedding processing")
    
    embedder = UCKGEmbedder()
    try:
        embedder.run_complete_pipeline()
    except KeyboardInterrupt:
        logger.info("Embedding processing interrupted by user")
    except Exception as e:
        logger.error(f"Embedding processing failed: {e}")
        # Continue system operation without embeddings
    finally:
        embedder.close()

# Docker health check function
def health_check() -> bool:
    """System health check for Docker container monitoring"""
    try:
        config = get_config()
        
        # Verify Neo4j connectivity
        driver = GraphDatabase.driver(
            config['neo4j_uri'],
            auth=(config['neo4j_user'], config['neo4j_password'])
        )
        with driver.session() as session:
            session.run("RETURN 1").single()
        driver.close()
        
        # Verify Ollama API connectivity
        response = requests.get(f"{config['ollama_url']}/api/tags", timeout=5)
        response.raise_for_status()
        
        return True
    except Exception:
        return False

if __name__ == "__main__":
    run_embedding_processing()