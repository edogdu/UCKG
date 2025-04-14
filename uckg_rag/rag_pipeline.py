# rag_pipeline.py (patched with semantic-rich multi-hop expansion)

import os
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
from dotenv import load_dotenv
import logging
from shared_state import SharedState
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from prompts import (
    get_initial_prompt,
    get_technical_analysis_prompt,
    get_direct_node_query,
    get_graph_context_query,
    get_neo4j_context_query,
    format_context
)
from aar_processor import AARProcessor
from rag_utils import get_relevant_context, generate_response

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
GEN_LLM_MODEL = os.getenv("GEN_LLM_MODEL", "microsoft/phi-2")

# Initialize FastAPI app
app = FastAPI(title="UCKG RAG Service")

# Initialize shared state
shared_state = SharedState()

# Initialize ChromaDB with persistence
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j driver
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

# Initialize LLM
logger.info(f"Loading LLM model: {GEN_LLM_MODEL}")
model_name = GEN_LLM_MODEL
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Log CUDA availability and device info
logger.info(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    logger.info(f"CUDA device count: {torch.cuda.device_count()}")
    logger.info(f"Current CUDA device: {torch.cuda.current_device()}")
    logger.info(f"CUDA device name: {torch.cuda.get_device_name()}")

# Load model with more robust device handling
try:
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )
except Exception as e:
    logger.warning(f"Failed to load model with device_map='auto': {str(e)}")
    logger.info("Attempting to load model without device mapping...")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        trust_remote_code=True
    )

# Log model device and dtype after loading
logger.info(f"Model device after loading: {model.device}")
logger.info(f"Model dtype: {model.dtype}")

# Try to get device map info safely
try:
    if hasattr(model.config, 'device_map'):
        logger.info(f"Model config device_map: {model.config.device_map}")
    else:
        logger.info("Model config does not have device_map attribute")
except Exception as e:
    logger.warning(f"Could not access device_map from config: {str(e)}")

# Set padding token if not set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
    model.config.pad_token_id = model.config.eos_token_id

# Configure tokenizer to handle padding properly
tokenizer.padding_side = 'left'
tokenizer.truncation_side = 'left'

@app.get("/")
async def root():
    """Root endpoint with service information and usage instructions"""
    return {
        "status": "running",
        "service": "UCKG RAG Service",
        "endpoints": {
            "/": "This help message",
            "/health": "Service health and embedding progress",
            "/query": "Query the knowledge graph"
        },
        "usage": {
            "query_endpoint": {
                "url": "/query",
                "method": "POST",
                "example_request": {
                    "query": "What is CVE-2023-1234?",
                    "graph_context": True  # Optional: Include related nodes in the response
                },
                "graph_context": {
                    "description": "When set to true, includes related nodes up to 3 hops away in the response",
                    "example": "For a CVE, this will include related CWEs, attack patterns, and other connected vulnerabilities"
                }
            }
        }
    }

class QueryRequest(BaseModel):
    query: str
    graph_context: bool = False

class QueryResponse(BaseModel):
    response: str
    source_node: Optional[Dict] = None
    context: Optional[List[Dict]] = None
    embedding_progress: Dict
    graph_expansion: Optional[str] = None

class AARRequest(BaseModel):
    pdf_url: str
    store_in_neo4j: bool = True

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process a query and return a response"""
    try:
        # Get relevant context
        context = get_relevant_context(request.query)
        
        # Generate response
        response = generate_response(
            query=request.query,
            context=context,
            graph_context=request.graph_context
        )
        
        return {
            "response": response,
            "source_node": context[0] if context else None,
            "context": context,
            "embedding_progress": {"status": "complete"},
            "graph_expansion": None
        }
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/process-aar")
async def process_aar(request: AARRequest):
    """Process an AAR PDF and extract triples"""
    try:
        processor = AARProcessor()
        result = processor.process_pdf(
            pdf_url=request.pdf_url,
            store_in_neo4j=request.store_in_neo4j
        )
        return result
    except Exception as e:
        logger.error(f"Error processing AAR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8051)