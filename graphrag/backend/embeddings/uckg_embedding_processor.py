#!/usr/bin/env python3
"""
UCKG Embedding Processor

Production-ready embedding processor for large-scale cybersecurity knowledge graphs.
Combines database-level pagination with batch API processing for optimal performance
and scalability.

Features:
- Database-level pagination for unlimited dataset scalability
- Batch API processing with configurable batch sizes
- Comprehensive property extraction and searchContent generation
- Automatic fallback and error handling
- Progress tracking and statistics

Usage:
    python simple_embedder.py --all
    python simple_embedder.py --node-type UcoCVE --limit 1000
    python simple_embedder.py --stats
"""
import asyncio
import json
import logging
import time
import argparse
import signal
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

import requests
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UCKGEmbeddingProcessor:
    """
    Production-ready embedding processor for UCKG cybersecurity knowledge graphs.
    
    Provides efficient, scalable embedding generation with database-level pagination
    and batch API processing for optimal performance on large datasets.
    """
    
    def __init__(self, 
                 neo4j_uri: str = "bolt://localhost:7687",
                 neo4j_auth: tuple = ("neo4j", "abcd90909090"),
                 ollama_url: str = "http://localhost:11434",
                 embedding_model: str = "nomic-embed-text"):
        """
        Initialize the UCKG embedding processor.
        
        Args:
            neo4j_uri: Neo4j database connection URI
            neo4j_auth: Neo4j authentication tuple (username, password)
            ollama_url: Ollama API base URL
            embedding_model: Embedding model name to use
        """
        self.neo4j_uri = neo4j_uri
        self.neo4j_auth = neo4j_auth
        self.ollama_url = ollama_url.rstrip('/')
        self.embedding_model = embedding_model
        
        # Processing statistics tracking
        self.stats = {
            'processed': 0,
            'errors': 0,
            'start_time': None
        }
        
        # Interruption handling
        self.interrupted = False
        
        # Connect to Neo4j
        self.driver = GraphDatabase.driver(neo4j_uri, auth=neo4j_auth)
        logger.info(f"Connected to Neo4j at {neo4j_uri}")
        
        # Validate Ollama connection
        self._validate_ollama_connection()
        
    def _handle_interruption(self, signum, frame):
        """Handle interruption signals gracefully."""
        logger.info("\nInterruption received (Ctrl+C). Finishing current batch...")
        logger.info("The process will stop gracefully after the current batch completes.")
        logger.info("All completed work has been saved to the database.")
        self.interrupted = True
    
    def _validate_ollama_connection(self):
        """Validate Ollama API connection and availability."""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info(f"Connected to Ollama at {self.ollama_url}")
            else:
                raise ConnectionError(f"Ollama responded with status {response.status_code}")
        except Exception as e:
            logger.error(f"Cannot connect to Ollama: {e}")
            raise
    
    def get_all_node_properties(self, node_type: str, limit: Optional[int] = None) -> List[Dict]:
        """
        Retrieve all properties for nodes requiring embedding processing.
        
        Args:
            node_type: Type of cybersecurity node to process
            limit: Optional limit on number of nodes to retrieve
            
        Returns:
            List of node dictionaries with all properties
        """
        
        # Query for nodes requiring embedding processing
        base_query = f"""
        MATCH (n:{node_type})
        WHERE n.embedding IS NULL OR n.searchContent IS NULL
        RETURN n
        """
        
        if limit:
            base_query += f" LIMIT {limit}"
        
        with self.driver.session() as session:
            result = session.run(base_query)
            nodes = []
            
            for record in result:
                node = dict(record['n'])
                nodes.append(node)
            
        logger.info(f"Retrieved {len(nodes)} {node_type} nodes needing embeddings")
        return nodes
    
    def get_batch_from_db(self, node_type: str, batch_size: int, offset: int) -> List[Dict]:
        """
        Retrieve a batch of nodes from database using pagination.
        
        Args:
            node_type: Type of cybersecurity node to process
            batch_size: Number of nodes to retrieve in this batch
            offset: Number of nodes to skip (for pagination) - NOT USED to avoid pagination issues
            
        Returns:
            List of node dictionaries for the requested batch
        """
        # Fix: Always get the first batch of nodes needing processing
        # This avoids pagination issues when nodes are being updated during processing
        query = f"""
        MATCH (n:{node_type})
        WHERE n.embedding IS NULL OR n.searchContent IS NULL
        RETURN n
        ORDER BY id(n)
        LIMIT {batch_size}
        """
        
        with self.driver.session() as session:
            result = session.run(query)
            nodes = []
            
            for record in result:
                node = dict(record['n'])
                nodes.append(node)
            
        return nodes
    
    def create_comprehensive_text(self, node_data: Dict, node_type: str) -> str:
        """Create comprehensive searchContent using hybrid approach with smart ordering."""
        
        # Context mapping for all node types (including missing ones)
        contexts = {
            "UcoCVE": "CYBERSECURITY VULNERABILITY EXPOSURE",
            "UcoVulnerability": "CYBERSECURITY SECURITY VULNERABILITY INFORMATION", 
            "UcoexCPE": "CYBERSECURITY PLATFORM SOFTWARE IDENTIFICATION",
            "UcoCWE": "CYBERSECURITY SOFTWARE WEAKNESS CLASSIFICATION",
            "UcoexMITREATTACK": "CYBERSECURITY ATTACK TECHNIQUE METHODOLOGY",
            "UcoexCAPEC": "CYBERSECURITY ATTACK PATTERN ENUMERATION",
            "UcoexMITRED3FEND": "CYBERSECURITY DEFENSE COUNTERMEASURE",
            "UcoexSOFTWARE": "CYBERSECURITY MALWARE/TOOL",
            "UcoexGROUPS": "CYBERSECURITY THREAT ACTOR GROUP",
            "UcoexMITIGATIONS": "CYBERSECURITY MITIGATION STRATEGY",
            "UcoexCAMPAIGNS": "CYBERSECURITY ATTACK CAMPAIGN",
            "UcoexTACTICS": "CYBERSECURITY ATTACK TACTIC"
        }
        
        text_parts = [contexts.get(node_type, "CYBERSECURITY RESOURCE")]
        
        # Smart ordering: important properties first, but include ALL properties
        important_keywords = ['label', 'name', 'id', 'description', 'summary', 'definition']
        
        # Add important properties first (if they exist)
        for prop, value in node_data.items():
            if any(keyword in prop.lower() for keyword in important_keywords):
                if prop not in ['embedding', 'searchContent'] and value is not None:
                    clean_value = self._clean_property_value(value, prop)
                    if clean_value:
                        text_parts.append(clean_value)
        
        # Add all other properties
        for prop, value in node_data.items():
            if not any(keyword in prop.lower() for keyword in important_keywords):
                if prop not in ['embedding', 'searchContent'] and value is not None:
                    clean_value = self._clean_property_value(value, prop)
                    if clean_value:
                        text_parts.append(clean_value)
        
        # Add metadata
        text_parts.extend([
            f"DOMAIN: {node_type}",
            f"GRAPH: UCKG",
            self._get_keywords(node_type)
        ])
        
        # Truncate if needed
        full_text = " | ".join(text_parts)
        if len(full_text) > 2000:
            full_text = full_text[:1997] + "..."
        
        return full_text
    
    def _clean_property_value(self, value: Any, prop_name: str) -> Optional[str]:
        """Clean property value for embedding."""
        if value is None:
            return None
        
        # Handle different types
        if isinstance(value, (list, tuple)):
            if not value:
                return None
            value = ", ".join(str(v) for v in value if v is not None)
        else:
            value = str(value)
        
        # Clean whitespace
        value = " ".join(value.split())
        
        if not value.strip():
            return None
        
        # Add meaningful prefix for key properties
        if prop_name in ['label', 'ucocweID', 'ucoexCAPEC_id']:
            return f"{prop_name.upper()}: {value}"
        elif prop_name in ['ucocweName', 'ucoexCAPEC_name', 'ucoexNAME']:
            return f"Name: {value}"
        elif prop_name in ['ucosummary', 'ucodescription', 'ucoexDescription']:
            return f"Description: {value}"
        elif prop_name in ['ucobaseSeverity', 'ucoexSeverity']:
            return f"Severity: {value}"
        elif prop_name in ['ucoexploitabilityScore']:
            return f"Exploitability: {value}"
        elif prop_name in ['ucoimpactScore']:
            return f"Impact: {value}"
        elif prop_name in ['ucovectorString']:
            return f"CVSS: {value}"
        else:
            return f"{prop_name}: {value}"
    
    def _get_keywords(self, node_type: str) -> str:
        """Get cybersecurity keywords for node type."""
        keywords = {
            "UcoCVE": "vulnerability, security flaw, exploit, CVSS, severity, patch",
            "UcoVulnerability": "security vulnerability, software flaw, threat, risk",
            "UcoexCPE": "software platform, application, version, configuration",
            "UcoCWE": "software weakness, design flaw, coding error, vulnerability class",
            "UcoexMITREATTACK": "attack technique, adversary tactics, threat actor method",
            "UcoexCAPEC": "attack pattern, attack method, exploitation technique",
            "UcoexMITRED3FEND": "defense, countermeasure, mitigation, security control, protection",
            "UcoexSOFTWARE": "malware, tool, software, threat actor tool, malicious software",
            "UcoexGROUPS": "threat actor group, APT, cybercriminal organization, hacker group",
            "UcoexMITIGATIONS": "mitigation, security measure, defense strategy, protection method",
            "UcoexCAMPAIGNS": "attack campaign, threat campaign, coordinated attack, operation",
            "UcoexTACTICS": "attack tactic, adversary tactic, threat technique, attack method"
        }
        return f"Keywords: {keywords.get(node_type, 'cybersecurity, security, threat')}"
    
    def create_embedding(self, text: str) -> List[float]:
        """Create embedding using Ollama with modern /api/embed endpoint."""
        try:
            payload = {
                "model": self.embedding_model,
                "input": text  # Use "input" for modern /api/embed endpoint
            }
            
            response = requests.post(f"{self.ollama_url}/api/embed", 
                                   json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            embeddings = result.get('embeddings', [])
            
            if not embeddings:
                raise ValueError("No embeddings returned")
            
            # Return first embedding for single text
            return embeddings[0]
            
        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            raise
    
    def create_batch_embeddings(self, texts: List[str], api_batch_size: int = 8) -> List[List[float]]:
        """Create embeddings for multiple texts using true batch API."""
        all_embeddings = []
        
        # Process in micro-batches to balance performance and quality
        for i in range(0, len(texts), api_batch_size):
            batch_texts = texts[i:i + api_batch_size]
            
            try:
                if len(batch_texts) == 1:
                    # Single text - use existing individual method
                    embedding = self.create_embedding(batch_texts[0])
                    all_embeddings.append(embedding)
                else:
                    # Multiple texts - use true batch API with /api/embed
                    payload = {
                        "model": self.embedding_model,
                        "input": batch_texts  # Use "input" for batch processing
                    }
                    
                    response = requests.post(f"{self.ollama_url}/api/embed", 
                                           json=payload, timeout=60)
                    response.raise_for_status()
                    
                    result = response.json()
                    batch_embeddings = result.get('embeddings', [])
                    
                    if not batch_embeddings:
                        raise ValueError("No embeddings returned from batch API")
                    
                    if len(batch_embeddings) != len(batch_texts):
                        raise ValueError(f"Expected {len(batch_texts)} embeddings, got {len(batch_embeddings)}")
                    
                    all_embeddings.extend(batch_embeddings)
                    
            except Exception as e:
                logger.error(f"Batch embedding failed: {e}")
                # Fallback to individual embeddings
                logger.info(f"📝 Falling back to individual embeddings for batch of {len(batch_texts)}")
                for text in batch_texts:
                    try:
                        embedding = self.create_embedding(text)
                        all_embeddings.append(embedding)
                    except Exception as e2:
                        logger.error(f"Individual embedding fallback failed: {e2}")
                        raise
        
        return all_embeddings
    
    def save_node_embedding(self, node_data: Dict, embedding: List[float], 
                           search_content: str, node_type: str) -> bool:
        """Save embedding and searchContent to node."""
        
        # Get node identifier based on type
        if node_type == "UcoexCAPEC":
            node_id = node_data.get("ucoexCAPEC_id")
            query = f"MATCH (n:{node_type} {{ucoexCAPEC_id: $node_id}})"
        elif node_type == "UcoexMITREATTACK":
            node_id = node_data.get("uri")
            query = f"MATCH (n:{node_type} {{uri: $node_id}})"
        elif node_type == "UcoCWE":
            node_id = node_data.get("ucocweID")
            query = f"MATCH (n:{node_type} {{ucocweID: $node_id}})"
        elif node_type in ["UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS", 
                          "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS"]:
            # All new node types use 'uri' as identifier
            node_id = node_data.get("uri")
            query = f"MATCH (n:{node_type} {{uri: $node_id}})"
        else:
            node_id = node_data.get("label") or node_data.get("uri")
            if node_data.get("label"):
                query = f"MATCH (n:{node_type} {{label: $node_id}})"
            else:
                query = f"MATCH (n:{node_type} {{uri: $node_id}})"
        
        if not node_id:
            logger.error(f"No identifier found for {node_type} node")
            return False
        
        query += " SET n.embedding = $embedding, n.searchContent = $search_content RETURN n"
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    'node_id': node_id,
                    'embedding': embedding,
                    'search_content': search_content
                })
                
                if result.single():
                    return True
                else:
                    logger.error(f"Node not found: {node_type}-{node_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"Save failed for {node_type}-{node_id}: {e}")
            return False
    
    def process_node_type(self, node_type: str, batch_size: int = 50, limit: Optional[int] = None, api_batch_size: int = 8):
        """Process all nodes of a specific type using database-level pagination."""
        logger.info(f"Processing {node_type}...")
        
        # Set up signal handler for graceful interruption
        signal.signal(signal.SIGINT, self._handle_interruption)
        
        offset = 0  # Not used anymore, kept for compatibility
        processed = 0
        errors = 0
        
        while True:
            # Check for interruption
            if self.interrupted:
                logger.info(f"Processing interrupted. Processed {processed} {node_type} nodes before interruption.")
                break
                
            # Get batch from database - always gets the next unprocessed nodes
            batch = self.get_batch_from_db(node_type, batch_size, offset)
            if not batch:
                break
            
            # Respect limit if provided
            if limit and processed + len(batch) > limit:
                batch = batch[:limit - processed]
            
            batch_start = time.time()
            
            # Create comprehensive text for all nodes in batch
            texts = []
            for node in batch:
                search_content = self.create_comprehensive_text(node, node_type)
                texts.append(search_content)
            
            # API micro-batching for embeddings (optimal batch size: 8)
            try:
                embeddings = self.create_batch_embeddings(texts, api_batch_size=api_batch_size)
                
                # Save all nodes with their embeddings
                for node, embedding, text in zip(batch, embeddings, texts):
                    try:
                        if self.save_node_embedding(node, embedding, text, node_type):
                            processed += 1
                            self.stats['processed'] += 1
                        else:
                            errors += 1
                            self.stats['errors'] += 1
                    except Exception as e:
                        logger.error(f"Error saving node embedding: {e}")
                        errors += 1
                        self.stats['errors'] += 1
                        
            except Exception as e:
                logger.error(f"Error processing batch: {e}")
                errors += len(batch)
                self.stats['errors'] += len(batch)
            
            # Progress update
            batch_time = time.time() - batch_start
            rate = len(batch) / batch_time if batch_time > 0 else 0
            
            logger.info(f"{node_type}: {processed} processed, "
                       f"Rate: {rate:.1f} nodes/sec, Errors: {errors}")
            
            # Removed: offset += batch_size (no longer needed)
            
            # Check limit
            if limit and processed >= limit:
                break
        
        if self.interrupted:
            logger.info(f"⚡ {node_type} processing interrupted: {processed} processed, {errors} errors")
        else:
            logger.info(f"{node_type} completed: {processed} processed, {errors} errors")
    
    def process_all_types(self, batch_size: int = 50, api_batch_size: int = 8):
        """
        Process all cybersecurity node types in the knowledge graph.
        
        Processes node types in order from smallest to largest datasets
        for optimal resource utilization and progress tracking.
        
        Args:
            batch_size: Database batch size for pagination
            api_batch_size: API batch size for embedding requests
        """
        node_types = [
            # Existing node types
            "UcoexCAPEC",      # Attack patterns (559 nodes)
            "UcoexMITREATTACK", # Attack techniques (884 nodes)
            "UcoCWE",          # Common weaknesses (968 nodes)
            "UcoexCPE",        # Platform enumerations (136,667 nodes)
            "UcoCVE",          # Vulnerabilities (299,050 nodes)
            "UcoVulnerability", # Additional vulnerabilities (299,050 nodes)
            
            # New node types (missing from previous implementation)
            "UcoexTACTICS",    # Attack tactics (38 nodes) - Smallest first
            "UcoexCAMPAIGNS",  # Attack campaigns (50 nodes)
            "UcoexMITIGATIONS", # Security mitigations (108 nodes)
            "UcoexGROUPS",     # Threat actor groups (170 nodes)
            "UcoexMITRED3FEND", # Defense countermeasures (244 nodes)
            "UcoexSOFTWARE",   # Malware/Tools (877 nodes)
        ]
        
        self.stats['start_time'] = time.time()
        logger.info("Starting comprehensive embedding processing for all node types...")
        logger.info("Press Ctrl+C anytime to stop gracefully after the current batch")
        
        completed_types = []
        
        for node_type in node_types:
            try:
                self.process_node_type(node_type, batch_size, api_batch_size=api_batch_size)
                if not self.interrupted:
                    completed_types.append(node_type)
                else:
                    # Interruption occurred
                    break
            except Exception as e:
                logger.error(f"Failed to process {node_type}: {e}")
                continue
        
        # Final summary
        total_time = time.time() - self.stats['start_time']
        rate = self.stats['processed'] / total_time if total_time > 0 else 0
        
        if self.interrupted:
            logger.info("EMBEDDING PROCESSING INTERRUPTED!")
            logger.info(f"Completed types: {', '.join(completed_types) if completed_types else 'None'}")
            logger.info(f"Processed before interruption: {self.stats['processed']} nodes")
            logger.info(f"Errors encountered: {self.stats['errors']}")
            logger.info(f"⏱️  Processing time: {total_time:.1f}s")
            logger.info(f"Average rate: {rate:.1f} nodes/sec")
            logger.info("All completed work has been saved. You can resume by running the command again.")
        else:
            logger.info("EMBEDDING PROCESSING COMPLETE!")
            logger.info(f"Total nodes processed: {self.stats['processed']}")
            logger.info(f"Total errors encountered: {self.stats['errors']}")
            logger.info(f"⏱️  Total processing time: {total_time:.1f}s")
            logger.info(f"Average processing rate: {rate:.1f} nodes/sec")
    
    def get_stats(self) -> Dict:
        """
        Generate comprehensive embedding coverage statistics.
        
        Returns:
            Dictionary containing embedding coverage statistics for all node types
        """
        with self.driver.session() as session:
            stats = {}
            
            node_types = ["UcoCVE", "UcoVulnerability", "UcoexCPE", 
                         "UcoCWE", "UcoexMITREATTACK", "UcoexCAPEC",
                         "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS",
                         "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS"]
            
            total_nodes = 0
            total_embeddings = 0
            total_search_content = 0
            
            for node_type in node_types:
                result = session.run(f"""
                    MATCH (n:{node_type})
                    RETURN count(*) as total,
                           count(n.embedding) as with_embedding,
                           count(n.searchContent) as with_search_content
                """)
                
                record = result.single()
                node_stats = {
                    'total': record['total'],
                    'with_embedding': record['with_embedding'],
                    'with_search_content': record['with_search_content'],
                    'embedding_coverage': record['with_embedding'] / record['total'] * 100 if record['total'] > 0 else 0,
                    'search_content_coverage': record['with_search_content'] / record['total'] * 100 if record['total'] > 0 else 0
                }
                
                stats[node_type] = node_stats
                total_nodes += record['total']
                total_embeddings += record['with_embedding']
                total_search_content += record['with_search_content']
            
            stats['overall'] = {
                'total_nodes': total_nodes,
                'total_embeddings': total_embeddings,
                'total_search_content': total_search_content,
                'embedding_coverage': total_embeddings / total_nodes * 100 if total_nodes > 0 else 0,
                'search_content_coverage': total_search_content / total_nodes * 100 if total_nodes > 0 else 0
            }
            
            return stats
    
    def close(self):
        """Clean up resources and close database connection."""
        if self.driver:
            self.driver.close()
            logger.info("Database connection closed successfully")

def main():
    """Command line interface for UCKG embedding processing."""
    parser = argparse.ArgumentParser(description='UCKG Embedding Processor - Production-ready embedding generation for cybersecurity knowledge graphs')
    parser.add_argument('--all', action='store_true', help='Process all cybersecurity node types')
    parser.add_argument('--node-type', help='Process specific cybersecurity node type (e.g., UcoCVE, UcoCWE)')
    parser.add_argument('--limit', type=int, help='Limit number of nodes to process (for testing)')
    parser.add_argument('--batch-size', type=int, default=50, help='Database batch size for pagination (default: 50)')
    parser.add_argument('--api-batch-size', type=int, default=8, help='API batch size for embedding requests (optimal: 8)')
    parser.add_argument('--stats', action='store_true', help='Display embedding statistics and coverage')
    
    args = parser.parse_args()
    
    # Initialize embedding processor
    embedder = UCKGEmbeddingProcessor()
    
    try:
        if args.stats:
            # Display comprehensive statistics
            stats = embedder.get_stats()
            print("\nEMBEDDING COVERAGE STATISTICS")
            print("=" * 50)
            
            for node_type, node_stats in stats.items():
                if node_type == 'overall':
                    continue
                print(f"{node_type:15} | Total: {node_stats['total']:7,} | "
                      f"Embeddings: {node_stats['with_embedding']:7,} ({node_stats['embedding_coverage']:5.1f}%) | "
                      f"SearchContent: {node_stats['with_search_content']:7,} ({node_stats['search_content_coverage']:5.1f}%)")
            
            overall = stats['overall']
            print("-" * 50)
            print(f"{'TOTAL':15} | Total: {overall['total_nodes']:7,} | "
                  f"Embeddings: {overall['total_embeddings']:7,} ({overall['embedding_coverage']:5.1f}%) | "
                  f"SearchContent: {overall['total_search_content']:7,} ({overall['search_content_coverage']:5.1f}%)")
            
        elif args.all:
            # Process all cybersecurity node types
            embedder.process_all_types(args.batch_size, args.api_batch_size)
            
        elif args.node_type:
            # Process specific cybersecurity node type
            embedder.process_node_type(args.node_type, args.batch_size, args.limit, args.api_batch_size)
            
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        # This shouldn't normally happen due to signal handling, but just in case
        logger.info("\nProcess interrupted by user")
        logger.info("All completed work has been saved to the database")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        embedder.close()

if __name__ == "__main__":
    main()