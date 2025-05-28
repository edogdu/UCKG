import os
import re
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
from dotenv import load_dotenv
import logging
from typing import List, Dict, Optional
from model_registry import ModelRegistry
from typing import List, Optional
import torch
import time
from prompts import (
    get_initial_prompt,
    get_technical_analysis_prompt,
    get_graph_context_query,
    get_direct_node_query,
    format_context
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# Initialize ChromaDB
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

# TODO: Add a method to determine if there are multiple cves/cwes in the query
# TODO: Store the cves/cwes in a list and pass it to neo4j to retrieve the context for each cve/cwe.

def get_cve_from_query(query: str) -> Optional[str]:
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_match = re.search(cve_pattern, query, re.IGNORECASE)
    return cve_match.group() if cve_match else None

def get_cwe_from_query(query: str) -> Optional[str]:
    cwe_pattern = r'CWE-\d{1,4}'
    cwe_match = re.search(cwe_pattern, query, re.IGNORECASE)
    return cwe_match.group() if cwe_match else None

def get_graph_context(query: str, driver, nearest_neighbors) -> Optional[str]:
    cypher = get_graph_context_query()
    
    # Check for CVE/CWE patterns in query
    cve_match = get_cve_from_query(query)
    cwe_match = get_cwe_from_query(query)
    cve_uri = None
    cwe_uri = None
    if cve_match:
        logger.info(f"Found CVE: {cve_match}")
        cve_uri = f"http://purl.org/cyber/uco#{cve_match}"
    if cwe_match:
        logger.info(f"Found CWE: {cwe_match}")
        cwe_uri = f"http://purl.org/cyber/uco#{cwe_match}"
    
    with driver.session() as session:
        try:
            if cve_uri:
                logger.info(f"Running query for CVE: {cve_uri}")
                results = session.run(cypher, {"uri": cve_uri, "nearest_neighbors": nearest_neighbors})
            elif cwe_uri:
                logger.info(f"Running query for CWE: {cwe_uri}")
                results = session.run(cypher, {"uri": cwe_uri, "nearest_neighbors": nearest_neighbors})
            else:
                logger.warning(f"No URI found for query: {query}")
                return None
            record = results.single()
            if record and record.get("context"):
                return format_context(record["context"])
        except Exception as e:
            logger.error(f"Error getting graph context: {e}")
    return None

def get_relevant_context(text: str, n_results: int = 5) -> List[Dict]:
    """Get relevant context from ChromaDB"""
    try:
        results = collection.query(
            query_texts=[text],
            n_results=n_results
        )
        return [{
            'id': results['ids'][0][i],
            'document': results['documents'][0][i],
            'metadata': results['metadatas'][0][i],
            'distance': results['distances'][0][i]
        } for i in range(len(results['ids'][0]))]
    except Exception as e:
        logger.error(f"Error getting relevant context: {e}")
        return []

def generate_response(query: str, context: List[Dict], model_registry, model_name: Optional[str] = None, graph_context: Optional[str] = None) -> str:
    """Generate response using the specified LLM"""
    try:
        logger.info("Formatting prompt for generation")
        logger.info(f"Getting model {model_name} from registry")
        # Get model from registry
        model_info = model_registry.get_model(model_name)
        if not model_info:
            return (f"Error: Model {model_name} not available")
            
        model = model_info["model"]
        tokenizer = model_info["tokenizer"]

        # If we have graph context, use it as primary source
        if graph_context:
            logger.info("Using graph context as primary source")
            prompt = get_technical_analysis_prompt(query, graph_context)
        else:
            # If no graph context, use semantic search results
            context_text = ""
            for idx, doc in enumerate(context, 1):
                text = doc["document"]
                if isinstance(text, list):
                    text = " ".join(text)
                context_text += f"- {text.strip()}\n"
            prompt = get_initial_prompt(query, context_text)

        logger.debug(f"Generated prompt:\n{prompt}")

        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        start = time.time()

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.7,
                top_p=0.9,
                do_sample=True
            )

        end = time.time()
        logger.info(f"Generated response in {end - start:.2f} seconds")

        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response.split("Answer:")[-1].strip()
        
    except Exception as e:
        logger.error(f"Error generating response: {e}")
        return f"Error generating response: {e}" 