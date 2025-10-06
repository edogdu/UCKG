#!/usr/bin/env python3
"""
UCKG Embedding Processor

Embedding processor for cybersecurity knowledge graphs.
Direct property-based embedding with batch processing via Ollama API.

Features:
- Property-selective text extraction by node type
- Batch processing for performance
- No chunking required (nomic-embed-text 8K context)
- Unified processing pipeline
"""

import os
import logging
import requests
import json
from typing import List, Optional
from contextlib import contextmanager

from neo4j import GraphDatabase

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO').upper())
logger = logging.getLogger(__name__)

class EmbeddingError(Exception):
    """Embedding processing error"""
    pass

class ConfigError(ValueError):
    """Configuration error"""
    pass

def get_config():
    """Load configuration from environment"""
    config = {
        'neo4j_uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'neo4j_user': os.getenv('NEO4J_USER', 'neo4j'),
        'neo4j_password': os.getenv('NEO4J_PASSWORD', 'abcd90909090'),
        'ollama_url': os.getenv('OLLAMA_URL', 'http://localhost:11434').rstrip('/'),
        'embedding_model': os.getenv('EMBEDDING_MODEL', 'nomic-embed-text'),
        'embed_enabled': os.getenv('EMBED_ENV', 'false').lower() in ['true', '1', 'yes']
    }
    
    if not all([config['neo4j_uri'], config['ollama_url']]):
        raise ConfigError("Missing required configuration: NEO4J_URI or OLLAMA_URL")
    
    return config

class UCKGEmbedder:
    """Simplified UCKG embedding processor"""
    
    def __init__(self):
        self.config = get_config()
        
        ensure_ollama_model(self.config['embedding_model'], self.config['ollama_url'])
        self._driver = None
        self._session = requests.Session()
        self._session.headers.update({'Content-Type': 'application/json'})
        self.batch_size = int(os.getenv('EMBEDDING_BATCH_SIZE', '100'))
    
    @contextmanager
    def _neo4j_driver(self):
        """Neo4j driver context manager"""
        if not self._driver:
            try:
                self._driver = GraphDatabase.driver(
                    self.config['neo4j_uri'],
                    auth=(self.config['neo4j_user'], self.config['neo4j_password']),
                    notifications_disabled_categories=['UNRECOGNIZED']
                )
                with self._driver.session() as session:
                    session.run("RETURN 1").single()
            except Exception as e:
                raise EmbeddingError(f"Neo4j connection failed: {e}")
        
        try:
            yield self._driver
        finally:
            pass
    
    def _create_batch_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using Ollama batch API"""
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
            
            logger.warning(f"Batch embedding size mismatch: got {len(embeddings)}, expected {len(texts)}")
            return []
            
        except requests.RequestException as e:
            logger.error(f"Ollama API request failed: {e}")
            return []
    
    def _extract_node_text(self, node_type: str, node_props: dict) -> str:
        """Extract text for embedding based on node type and selected properties"""
        
        # Property selection map based on analysis
        property_map = {
            'UcoCWE': ['ucocweSummary', 'ucocweExtendedSummary', 'ucocweName'],
            'UcoCVE': ['label', 'ucobaseSeverity'],
            'UcoVulnerability': ['ucosummary'],
            'UcoexCAPEC': ['label', 'ucoexDescription'],
            'UcoexSOFTWARE': ['ucoexDESCRIPTION', 'ucoexDOMAIN'],
            'UcoexGROUPS': ['ucoexDESCRIPTION', 'ucoexDOMAIN'],
            'UcoexCAMPAIGNS': ['ucoexDESCRIPTION', 'ucoexDOMAIN'],
            'UcoexMITIGATIONS': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
            'UcoexMITREATTACK': ['ucoexDESCRIPTION', 'ucoexDOMAIN', 'ucoexNAME'],
            'UcoexObservedExample': ['ucoexDESCRIPTION'],
            'UcoexTACTICS': ['ucoexDESCRIPTION', 'ucoexDOMAIN'],
            'UcoexMITRED3FEND': ['ucoexMITRED3FEND_DEFINITION', 'ucoexMITRED3FEND_LABEL'],
            'UcoexCPE': ['cpeName', 'titles'],
        }
        
        properties = property_map.get(node_type, [])
        if not properties:
            # Fallback for unknown node types
            return str(node_props.get('name', node_props.get('label', '')))
        
        # Extract and combine selected properties in natural language format
        text_parts = []
        for prop in properties:
            value = node_props.get(prop)
            if value is not None:
                # Clean property name by removing common prefixes
                clean_prop = self._clean_property_name(prop)
                
                # Special handling for titles property (JSON with language keys)
                if prop == 'titles':
                    try:
                        titles_json = json.loads(value)
                        if isinstance(titles_json, dict):
                            # Prefer English, fallback to any available language
                            title_text = titles_json.get('en')
                            if not title_text and titles_json:
                                # Use first available language if no English
                                title_text = next(iter(titles_json.values()))
                            
                            if title_text:
                                text_parts.append(f"{clean_prop}: {title_text}")
                        # If not a dict or empty, skip titles property
                    except (json.JSONDecodeError, TypeError):
                        # Skip titles if JSON parsing fails
                        pass
                elif isinstance(value, list):
                    # Handle list values
                    list_items = [str(item) for item in value if item]
                    if list_items:
                        text_parts.append(f"{clean_prop}: {' '.join(list_items)}")
                else:
                    text_parts.append(f"{clean_prop}: {str(value)}")
        
        return '. '.join(text_parts).strip()
    
    def _clean_property_name(self, prop: str) -> str:
        """Clean property names by removing common prefixes and formatting"""
        # Remove common prefixes (order matters - longer prefixes first)
        prefixes_to_remove = [
            'ucoexMITRED3FEND_',
            'ucocweExtended',
            'ucocwe',
            'ucoex',
            'ucobase',  # For ucobaseSeverity
            'uco',
            'cpe'
        ]
        
        clean_name = prop
        for prefix in prefixes_to_remove:
            if clean_name.lower().startswith(prefix.lower()):
                clean_name = clean_name[len(prefix):]
                break
        
        # Handle special cases and capitalize
        if clean_name.upper() in ['DESCRIPTION', 'DOMAIN', 'NAME']:
            return clean_name.capitalize()
        elif clean_name in ['summary', 'Summary']:
            return 'Summary'
        elif clean_name in ['DEFINITION', 'LABEL']:
            return clean_name.capitalize()
        elif clean_name == 'Name':  # for cpeName
            return 'Name'
        
        # Default: capitalize first letter
        return clean_name.capitalize() if clean_name else prop
    

    
    def _process_all_nodes(self) -> int:
        """Process all unvectorized nodes with sequential batch embedding by node type"""
        
        # Node types ordered by count (largest first)
        node_types = [
            'UcoCVE', 'UcoVulnerability', 'UcoexCPE', 'UcoexObservedExample', 
            'UcoCWE', 'UcoexMITREATTACK', 'UcoexSOFTWARE', 'UcoexCAPEC',
            'UcoexMITRED3FEND', 'UcoexGROUPS', 'UcoexMITIGATIONS', 
            'UcoexCAMPAIGNS', 'UcoexTACTICS'
        ]
        
        total_processed = 0
        
        with self._neo4j_driver() as driver:
            with driver.session() as session:
                # Count already embedded nodes
                embedded_result = session.run("""
                    MATCH (n) WHERE n.embedding IS NOT NULL
                    RETURN count(n) as embedded_count
                """)
                embedded_count = embedded_result.single()['embedded_count']
                logger.info(f"Found {embedded_count:,} nodes already embedded")
                
                # Process each node type sequentially
                for node_type in node_types:
                    type_processed = self._process_node_type(session, node_type)
                    total_processed += type_processed
        
        return total_processed
    
    def _process_node_type(self, session, node_type: str) -> int:
        """Process all nodes of a specific type"""
        
        # Count remaining nodes for this type
        count_result = session.run("""
            MATCH (n)
            WHERE n.embedding IS NULL 
              AND n.embedding_processed IS NULL
              AND NOT labels(n)[0] = '_GraphConfig'
            WITH n, [label IN labels(n) WHERE label <> 'Resource'][0] as nodeType
            WHERE nodeType = $node_type
            RETURN count(n) as node_count
        """, {'node_type': node_type})
        
        node_count = count_result.single()['node_count']
        if node_count == 0:
            return 0
        
        # Start processing this node type
        estimated_batches = (node_count + self.batch_size - 1) // self.batch_size
        logger.info(f"Starting {node_type}: {node_count:,} nodes (~{estimated_batches} batches)")
        
        processed_count = 0
        batch_num = 0
        
        while True:
            # Get batch of nodes for this specific type
            result = session.run("""
                MATCH (n)
                WHERE n.embedding IS NULL 
                  AND n.embedding_processed IS NULL
                  AND NOT labels(n)[0] = '_GraphConfig'
                WITH n, elementId(n) as nodeId, 
                     [label IN labels(n) WHERE label <> 'Resource'][0] as nodeType
                WHERE nodeType = $node_type
                RETURN nodeId, nodeType, properties(n) as props
                LIMIT $batch_size
            """, {'node_type': node_type, 'batch_size': self.batch_size})
            
            batch_data = [(r['nodeId'], r['nodeType'], r['props']) for r in result]
            if not batch_data:
                break
            
            batch_num += 1
            
            # Extract texts for embedding
            texts = []
            valid_nodes = []
            empty_text_nodes = []
            
            for node_id, node_type_result, props in batch_data:
                text = self._extract_node_text(node_type_result, props)
                if text:
                    texts.append(text)
                    valid_nodes.append((node_id, node_type_result))
                else:
                    # Track nodes with no extractable text
                    empty_text_nodes.append(node_id)
            
            # if not texts:
            #     continue
            
            # Check if we need to limit batch size for large text content
            total_chars = sum(len(text) for text in texts)
            if total_chars > 500000:  # If total characters exceed 500K, use smaller batch
                logger.info(f"{node_type} batch {batch_num} is large ({total_chars:,} chars), using reduced batch size")
                # Process in chunks of 200 for large content
                embeddings = []
                chunk_failed = False
                for i in range(0, len(texts), 200):
                    chunk_texts = texts[i:i + 200]
                    chunk_embeddings = self._create_batch_embeddings(chunk_texts)
                    if len(chunk_embeddings) == len(chunk_texts):
                        embeddings.extend(chunk_embeddings)
                        logger.info(f"{node_type} batch {batch_num} chunk {(i//200)+1}: {len(chunk_embeddings)} embeddings")
                    else:
                        logger.warning(f"{node_type} batch {batch_num} chunk {(i//200)+1} failed")
                        chunk_failed = True
                        break
                
                if chunk_failed:
                    logger.warning(f"{node_type} batch {batch_num} failed due to chunk failure, skipping")
                    continue
            else:
                # Generate embeddings normally
                embeddings = self._create_batch_embeddings(texts)
            
            if len(embeddings) != len(texts):
                logger.warning(f"{node_type} batch {batch_num} failed, skipping {len(texts)} nodes")
                continue
            
            # Process ALL nodes in this batch (mark as processed with or without embeddings)
            def process_batch_tx(tx):
                # Set embeddings for nodes with valid text content
                if valid_nodes and embeddings:
                    embedding_updates = []
                    for (node_id, _), embedding in zip(valid_nodes, embeddings):
                        if embedding:
                            embedding_updates.append({'node_id': node_id, 'embedding': embedding})
                    
                    if embedding_updates:
                        tx.run("""
                            UNWIND $updates as update
                            MATCH (n) WHERE elementId(n) = update.node_id
                            SET n.embedding = update.embedding, n.embedding_processed = true
                        """, {'updates': embedding_updates})
                
                # Mark nodes without text content as processed (no embedding property)
                if empty_text_nodes:
                    tx.run("""
                        UNWIND $node_ids as node_id
                        MATCH (n) WHERE elementId(n) = node_id
                        SET n.embedding_processed = true, n.no_text_content = true
                    """, {'node_ids': empty_text_nodes})
                
                return len(valid_nodes) + len(empty_text_nodes)
            
            if valid_nodes or empty_text_nodes:
                batch_processed = session.execute_write(process_batch_tx)
                processed_count += batch_processed
                
                # Log progress with breakdown - only show when there are empty nodes
                embedding_count = len([e for e in embeddings if e]) if embeddings else 0
                empty_count = len(empty_text_nodes)
                
                if empty_count > 0:
                    logger.info(f"{node_type} batch {batch_num}: processed {batch_processed} nodes ({embedding_count} with embeddings, {empty_count} no content)")
            
            total_processed = len(valid_nodes) + len(empty_text_nodes)
            logger.info(f"{node_type} batch {batch_num}/{estimated_batches}: {total_processed} nodes")
        
        # Completion logging for this node type
        logger.info(f"Completed {node_type}: {processed_count:,} nodes embedded")
        return processed_count
    
    def _create_vector_index(self):
        """Create global vector index for all vectorized nodes"""
        
        logger.info("Creating global vector index")
        
        with self._neo4j_driver() as driver:
            with driver.session() as session:
                
                # Check if index exists using proper syntax
                result = session.run("""
                    SHOW VECTOR INDEXES YIELD name
                    WHERE name = 'global_embedding_idx'
                """)
                
                if list(result):
                    logger.info("Vector index already exists")
                    return
                
                # Create vector index for nodes with embeddings
                session.run("""
                    CREATE VECTOR INDEX global_embedding_idx IF NOT EXISTS
                    FOR (n:Resource) ON (n.embedding)
                    OPTIONS {
                      indexConfig: {
                        `vector.dimensions`: 768,
                        `vector.similarity_function`: 'cosine'
                      }
                    }
                """)
                
                logger.info("Vector index created successfully")
    
    def run_embedding_pipeline(self):
        """Execute complete embedding pipeline"""
        
        logger.info("Starting UCKG embedding pipeline")
        
        try:
            # Process all nodes with direct embedding
            processed_count = self._process_all_nodes()
            
            # Create vector index
            self._create_vector_index()
            
            logger.info(f"Embedding pipeline completed: {processed_count:,} nodes processed")
            return processed_count
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            raise EmbeddingError(f"Embedding pipeline failed: {e}")
    
    def close(self):
        """Clean up resources"""
        if self._driver:
            self._driver.close()
            self._driver = None
        if self._session:
            self._session.close()

def ensure_ollama_model(model_name="nomic-embed-text", base_url="http://localhost:11434"):
    try:
        # Check if the model is available
        resp = requests.get(f"{base_url}/api/tags")
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]

        if model_name not in models:
            logger.info(f"Model '{model_name}' not found. Downloading...")
            pull_resp = requests.post(f"{base_url}/api/pull", json={"name": model_name})
            pull_resp.raise_for_status()
            logger.info(f"Model '{model_name}' downloaded.")
        else:
            logger.info(f"Model '{model_name}' already available.")
    except Exception as e:
        logger.info("Error checking or downloading model:", e)

def run_embedding_processing():
    """Main entry point for embedding processing"""
    
    config = get_config()
    
    if not config['embed_enabled']:
        logger.info("Embedding processing disabled")
        return
    
    logger.info("Initializing UCKG embedding processor")
    
    embedder = UCKGEmbedder()
    try:
        embedder.run_embedding_pipeline()
    except KeyboardInterrupt:
        logger.info("Processing interrupted")
    except Exception as e:
        logger.error(f"Processing failed: {e}")
    finally:
        embedder.close()

def health_check() -> bool:
    """System health check"""
    try:
        config = get_config()
        
        # Test Neo4j connection
        driver = GraphDatabase.driver(
            config['neo4j_uri'],
            auth=(config['neo4j_user'], config['neo4j_password'])
        )
        with driver.session() as session:
            session.run("RETURN 1").single()
        driver.close()
        
        # Test Ollama API
        response = requests.get(f"{config['ollama_url']}/api/tags", timeout=5)
        response.raise_for_status()
        
        return True
    except Exception:
        return False

if __name__ == "__main__":
    run_embedding_processing()