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
from rag_utils import get_graph_context
from aar_processor import AARProcessor
from rag_utils import get_relevant_context, generate_response
from model_registry import ModelRegistry
from evaluation import ModelEvaluator
import json
from pathlib import Path
import time
from datetime import datetime

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

# Initialize Model Registry
model_registry = ModelRegistry()

# Initialize LLM
logger.info(f"Default LLM model: {GEN_LLM_MODEL}")
model_name = GEN_LLM_MODEL

# Log CUDA availability and device info
logger.info(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    logger.info(f"CUDA device count: {torch.cuda.device_count()}")
    logger.info(f"Current CUDA device: {torch.cuda.current_device()}")
    logger.info(f"CUDA device name: {torch.cuda.get_device_name()}")
    
    # Set the default device to GPU
    device = torch.device("cuda")
    logger.info(f"Using device: {device}")
    
    # Enable CUDA optimizations
    torch.backends.cudnn.benchmark = True
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
else:
    device = torch.device("cpu")
    logger.warning("CUDA not available, using CPU")

# Remove model loading from startup - will be loaded lazily when needed
logger.info("Model will be loaded on first use")

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
    model_name: Optional[str] = None

class QueryResponse(BaseModel):
    response: str
    semantic_context: Optional[List[Dict]] = None
    embedding_progress: Dict
    graph_expansion: Optional[str] = None
    model_used: str

class AARRequest(BaseModel):
    pdf_url: str
    store_in_neo4j: bool = True

class ModelInfo(BaseModel):
    name: str
    description: str
    max_length: int
    loaded: bool
    installed: bool

class ModelListResponse(BaseModel):
    available_models: Dict[str, ModelInfo]
    default_model: str

class EvaluationRequest(BaseModel):
    models: Optional[List[str]] = None
    use_rag: bool = True
    csv_path: Optional[str] = None

class EvaluationResponse(BaseModel):
    results: Dict
    report: str
    timestamp: str

class ModelLoadRequest(BaseModel):
    model_name: str

class ModelUnloadRequest(BaseModel):
    model_name: str

class ModelLoadResponse(BaseModel):
    success: bool
    message: str

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.get("/models")
async def list_models() -> ModelListResponse:
    """List all available models and their status"""
    available_models = model_registry.list_available_models()
    return ModelListResponse(
        available_models=available_models,
        default_model=model_registry.default_model
    )

@app.post("/models/load", response_model=ModelLoadResponse)
async def load_model(request: ModelLoadRequest):
    """Load a specific model"""
    try:
        if not model_registry.is_model_installed(request.model_name):
            return ModelLoadResponse(
                success=False,
                message=f"Model {request.model_name} is not installed. Please run the install_models.py script first."
            )
            
        model_info = model_registry.load_model(request.model_name)
        if model_info:
            return ModelLoadResponse(
                success=True,
                message=f"Successfully loaded model {request.model_name}"
            )
        else:
            return ModelLoadResponse(
                success=False,
                message=f"Failed to load model {request.model_name}"
            )
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/models/unload", response_model=ModelLoadResponse)
async def unload_model(request: ModelUnloadRequest):
    """Unload a specific model"""
    try:
        success = model_registry.unload_model(request.model_name)
        if success:
            return ModelLoadResponse(
                success=True,
                message=f"Successfully unloaded model {request.model_name}"
            )
        else:
            return ModelLoadResponse(
                success=False,
                message=f"Failed to unload model {request.model_name}"
            )
    except Exception as e:
        logger.error(f"Error unloading model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/models/unload-all", response_model=ModelLoadResponse)
async def unload_all_models():
    """Unload all models except the default one"""
    try:
        model_registry.unload_all_models()
        return ModelLoadResponse(
            success=True,
            message="Successfully unloaded all non-default models"
        )
    except Exception as e:
        logger.error(f"Error unloading models: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process a query using the RAG pipeline"""
    try:
        start_time = time.time()
        
        # Get model - will reuse if already loaded
        model_info = model_registry.get_model(request.model_name)
        if model_info is None:
            raise HTTPException(status_code=400, detail="Model not available")
        
        # First try to get graph context if requested
        graph_context = None
        if request.graph_context:
            graph_context = get_graph_context(request.query, driver)
            
        # Get semantic context (will be used as supplementary if we have graph context)
        context = get_relevant_context(request.query, n_results=5)
            
        # Generate response, where context is the semantic context if no graph context is requested, or the graph context if it is requested
        response = generate_response(
            query=request.query,
            context=context,
            model_registry=model_registry,
            model_name=model_info["model_name"],
            graph_context=graph_context
        )
        
        total_time = time.time() - start_time
        logger.info(f"Query processed in {total_time:.2f}s")
        
        return QueryResponse(
            response=response,
            semantic_context=context if not graph_context else None,  # Only include if no graph context
            embedding_progress=shared_state.get_progress(),
            graph_expansion=graph_context,
            model_used=model_registry.current_model
        )
        
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
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

@app.post("/evaluate", response_model=EvaluationResponse)
async def evaluate_models(request: EvaluationRequest):
    """Evaluate models on provided test cases"""
    try:
        evaluator = ModelEvaluator(csv_path=request.csv_path) if request.csv_path else ModelEvaluator()
        
        if request.models:
            results = {}
            for model_name in request.models:
                if model_name in model_registry.available_models:
                    results[model_name] = evaluator.evaluate_model(
                        model_name=model_name,
                        use_rag=request.use_rag
                    )
        else:
            logger.warning("No models provided for evaluation. Exiting...")
            return EvaluationResponse(
                results={},
                report="No models provided for evaluation",
                timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
            )
            
        report = evaluator.generate_report(results)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("evaluation_results")
        output_dir.mkdir(exist_ok=True)
        
        output_file = output_dir / f"evaluation_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        return EvaluationResponse(
            results=results,
            report=report,
            timestamp=timestamp
        )
        
    except Exception as e:
        # Dump what we have so far
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("evaluation_results")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"evaluation_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.error(f"Error during evaluation: {e}, results dumped to {output_file}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8051)