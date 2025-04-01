import os
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
from dotenv import load_dotenv
import time
from tqdm import tqdm
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import torch
from pathlib import Path
from typing import List, Dict
import numpy as np
from shared_state import SharedState

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
CHECKPOINT_DIR = Path("/app/checkpoints")
CHECKPOINT_DIR.mkdir(exist_ok=True)

# Initialize shared state
shared_state = SharedState()

# Initialize ChromaDB with persistence
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j driver
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

def get_existing_ids():
    """Get all existing IDs from ChromaDB"""
    try:
        return set(collection.get()["ids"])
    except Exception as e:
        logger.warning(f"Error getting existing IDs: {e}")
        return set()

def setup_neo4j_indexes():
    """Create necessary indexes for faster querying"""
    with driver.session() as session:
        # Create indexes for commonly queried properties
        session.run("CREATE INDEX uri_index IF NOT EXISTS FOR (n:Resource) ON (n.uri)")
        session.run("CREATE INDEX summary_index IF NOT EXISTS FOR (n:UcoVulnerability) ON (n.ucosummary)")
        session.run("CREATE INDEX cwe_index IF NOT EXISTS FOR (n:UcoCWE) ON (n.ucocweSummary)")

def fetch_nodes_batch(skip: int, limit: int) -> List[Dict]:
    """Fetch nodes in batches to reduce memory usage"""
    query = """
    MATCH (n)
    WHERE (n:UcoVulnerability OR n:UcoCWE)
    WITH n
    SKIP $skip
    LIMIT $limit
    OPTIONAL MATCH (n)-[r]-(related)
    WHERE related.ucosummary IS NOT NULL 
       OR related.ucocweSummary IS NOT NULL 
       OR related.ucodescription IS NOT NULL
    WITH n, collect({
        uri: related.uri,
        summary: coalesce(related.ucosummary, related.ucocweSummary, related.ucodescription),
        type: labels(related)[0]
    }) as related_nodes
    RETURN {
        uri: n.uri,
        summary: coalesce(n.ucosummary, n.ucocweSummary, n.ucodescription),
        type: labels(n)[0],
        related_nodes: related_nodes
    } as node
    """
    with driver.session() as session:
        result = session.run(query, skip=skip, limit=limit)
        return [r["node"] for r in result]

def get_total_count() -> int:
    """Get total count of nodes to process"""
    query = """
    MATCH (n)
    WHERE (n:UcoVulnerability OR n:UcoCWE)
    RETURN count(n) as count
    """
    with driver.session() as session:
        result = session.run(query)
        return result.single()["count"]

def load_checkpoint():
    """Load checkpoint from shared state"""
    return shared_state.get_progress()

def save_checkpoint(processed_uris, total_records, processed_count):
    """Save checkpoint using shared state"""
    shared_state.update_progress(processed_uris, total_records, processed_count)

def create_text_for_embedding(node):
    # Create rich text representation including relationships
    text_parts = []
    
    # Add main node information
    if node["summary"]:
        text_parts.append(f"{node['type']}: {node['summary']}")
    
    # Add related node information
    for related in node["related_nodes"]:
        if related["summary"]:
            text_parts.append(f"Related {related['type']}: {related['summary']}")
    
    return " ".join(text_parts)

def create_metadata(record):
    metadata = {
        "uri": record["uri"] or "",
        "type": record["type"] or "Unknown"
    }
    
    # Add related URIs only if they exist and are not None
    related_uris = [r["uri"] for r in record["related_nodes"] if r.get("uri")]
    if related_uris:
        metadata["related_uris"] = ",".join(related_uris)
    return metadata

def process_record(record, existing_ids):
    try:
        # Skip if already processed
        if record["uri"] in existing_ids:
            return {"success": False, "uri": record["uri"], "reason": "already_exists"}
            
        text = create_text_for_embedding(record)
        if text:
            embedding = SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)(text)
            metadata = create_metadata(record)
            return {
                "success": True,
                "uri": record["uri"],
                "document": text,
                "metadata": metadata,
                "id": record["uri"]
            }
    except Exception as e:
        logger.error(f"Error processing record {record['uri']}: {str(e)}")
    return {"success": False, "uri": record["uri"], "reason": "processing_failed"}

def process_batch(batch, existing_ids):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_record = {executor.submit(process_record, record, existing_ids): record for record in batch}
        for future in as_completed(future_to_record):
            result = future.result()
            if result["success"]:
                results.append(result)
            elif result.get("reason") == "already_exists":
                logger.debug(f"Skipping existing record: {result['uri']}")
    return results

def embed_and_store():
    # Get existing IDs from ChromaDB first
    logger.info("Checking existing embeddings...")
    existing_ids = get_existing_ids()
    logger.info(f"Found {len(existing_ids)} existing embeddings")
    
    # Get total count of nodes to process
    total_records = get_total_count()
    logger.info(f"Found {total_records} nodes to process")
    
    # Get current progress from shared state
    progress = shared_state.get_progress()
    processed_uris = shared_state.get_processed_uris()
    processed_count = progress["processed_count"]
    
    # Only reset if we're starting fresh
    if processed_count == 0:
        logger.info("Starting fresh embedding process")
        shared_state.reset()
        processed_uris = set()
        processed_count = 0
    else:
        logger.info(f"Resuming from {processed_count} processed records")
    
    if processed_count >= total_records:
        logger.info("All nodes have been processed")
        shared_state.update_progress(processed_uris, total_records, processed_count)
        return
    
    # Setup Neo4j indexes
    logger.info("Setting up Neo4j indexes...")
    setup_neo4j_indexes()
    
    # Calculate estimated time
    start_time = time.time()
    
    try:
        # Process in larger chunks to reduce database calls
        chunk_size = 1000
        for chunk_start in tqdm(range(processed_count, total_records, chunk_size), desc="Processing chunks"):
            chunk_end = min(chunk_start + chunk_size, total_records)
            records = fetch_nodes_batch(chunk_start, chunk_size)
            
            # Process records in smaller batches for memory efficiency
            for i in range(0, len(records), BATCH_SIZE):
                batch = records[i:i + BATCH_SIZE]
                results = process_batch(batch, existing_ids)
                
                # Add successful results to ChromaDB
                if results:
                    collection.add(
                        documents=[r["document"] for r in results],
                        metadatas=[r["metadata"] for r in results],
                        ids=[r["id"] for r in results]
                    )
                
                # Update progress
                processed_count += len(batch)
                processed_uris.update(r["uri"] for r in results if r["success"])
                
                # Update shared state
                shared_state.update_progress(processed_uris, total_records, processed_count)
                
                # Calculate and log progress
                elapsed_time = time.time() - start_time
                avg_time_per_record = elapsed_time / processed_count
                remaining_records = total_records - processed_count
                estimated_remaining_time = remaining_records * avg_time_per_record
                
                logger.info(f"Processed {processed_count}/{total_records} records. "
                           f"Estimated time remaining: {estimated_remaining_time:.2f} seconds")
                
                # Clear CUDA cache if using GPU
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
    
    except Exception as e:
        logger.error(f"Error during processing: {str(e)}")
        raise
    
    logger.info("✅ Completed embedding and storing nodes")

if __name__ == "__main__":
    embed_and_store()