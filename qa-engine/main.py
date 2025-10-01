from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import os
import logging
import asyncio
from typing import Optional, Dict, Any

# Import our Q&A engines
from multiRAG import MultiRAG
from text2cypher.backend.text2cypher import Text2Cypher
from text2cypher.backend.ollama_llm import OllamaLLM

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Global instances (initialized on startup)
multirag_engine = None
text2cypher_engine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown"""
    global multirag_engine, text2cypher_engine
    
    # Startup
    logger.info("Initializing Q&A engines...")
    
    try:
        # Initialize MultiRAG
        logger.info("Initializing MultiRAG engine...")
        multirag_engine = MultiRAG()
        logger.info("MultiRAG engine initialized successfully")
        
        # Initialize Text2Cypher
        logger.info("Initializing Text2Cypher engine...")
        llm = OllamaLLM(base_url=OLLAMA_URL, model=OLLAMA_MODEL)
        text2cypher_engine = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)
        
        # Pre-warm by getting schema
        schema = text2cypher_engine.get_schema()
        logger.info("Text2Cypher engine initialized successfully")
        
        logger.info("All Q&A engines initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Q&A engines: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Q&A engines...")
    
    try:
        if multirag_engine:
            multirag_engine.close()
            logger.info("MultiRAG engine closed")
            
        if text2cypher_engine and hasattr(text2cypher_engine, 'driver'):
            text2cypher_engine.driver.close()
            logger.info("Text2Cypher engine closed")
            
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")

# Create FastAPI app with lifespan
app = FastAPI(
    title="UCKG Q&A Engine",
    description="Unified service for MultiRAG and Text2Cypher queries",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class RAGRequest(BaseModel):
    query: str
    mode: str = "auto"
    top_k: int = 5
    include_visualization: bool = True

class Text2CypherRequest(BaseModel):
    question: str
    execute: bool = True
    explain: bool = True

class ChatRequest(BaseModel):
    question: str
    session_id: str

# Response formatting functions
def format_multirag_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Format MultiRAG result for frontend visualization"""
    visualization_data = {
        "nodes": [],
        "relationships": []
    }

    sources = result.get("sources", [])

    # Process sources into nodes for visualization
    for i, source in enumerate(sources):
        node_id = source.get("metadata", {}).get("id", f"node_{i}")
        score = source.get("score", 0.0)

        node = {
            "id": node_id,
            "label": source.get("metadata", {}).get("nodeLabel", "Unknown"),
            "caption": source.get("metadata", {}).get("nodeLabel", "Unknown"),
            "type": source.get("metadata", {}).get("nodeType", "Unknown"),
            "properties": {
                **source.get("metadata", {}),
                "isRAGResult": True,
                "score": score,
                "content": source.get("content", ""),
                "mode": result.get("mode", "unknown")
            },
            "score": score,
            "color": get_score_color(score),
            "size": get_score_size(score)
        }
        visualization_data["nodes"].append(node)

        # Add relationships if available (from graphrag mode)
        if "firstHopNeighbors" in source:
            for rel_idx, rel in enumerate(source["firstHopNeighbors"]):
                relationship = {
                    "id": f"rel_{i}_{rel_idx}",
                    "from": node_id,
                    "to": rel.get("primaryNode", {}).get("nodeId", f"rel_node_{rel_idx}"),
                    "type": rel.get("relationshipType", "RELATED"),
                    "label": rel.get("relationshipType", "RELATED"),
                    "properties": {
                        "isRAGResult": True
                    }
                }
                visualization_data["relationships"].append(relationship)

    # Format sources for chat display
    formatted_sources = []
    for source in sources:
        formatted_sources.append({
            "node_label": source.get("metadata", {}).get("nodeLabel", "Unknown"),
            "node_type": source.get("metadata", {}).get("nodeType", "Unknown"),
            "content": source.get("content", ""),
            "score": source.get("score", 0.0),
            "uri": source.get("metadata", {}).get("uri", "")
        })

    # Calculate confidence based on scores
    if formatted_sources:
        avg_score = sum(s["score"] for s in formatted_sources) / len(formatted_sources)
        confidence = min(avg_score * 1.1, 1.0)  # Slight boost, cap at 1.0
    else:
        confidence = 0.0

    return {
        "answer": result.get("answer", "No answer generated"),
        "chat_data": {
            "message": result.get("answer", "No answer generated"),
            "sources": formatted_sources,
            "confidence": confidence,
            "mode": result.get("mode", "unknown")
        },
        "visualization_data": visualization_data,
        "metadata": {
            "mode": result.get("mode", "unknown"),
            "execution_time": 0,
            "total_nodes": len(visualization_data["nodes"]),
            "total_relationships": len(visualization_data["relationships"]),
            "score_statistics": {
                "min": min(s["score"] for s in formatted_sources) if formatted_sources else 0,
                "max": max(s["score"] for s in formatted_sources) if formatted_sources else 0,
                "avg": sum(s["score"] for s in formatted_sources) / len(formatted_sources) if formatted_sources else 0
            }
        }
    }

def format_text2cypher_result(cypher_query: str, execution_result: list, explanation: str, confidence: float) -> Dict[str, Any]:
    """Format Text2Cypher result for frontend"""
    nodes = []
    relationships = []

    if execution_result and isinstance(execution_result, list):
        for i, record in enumerate(execution_result):
            for key, value in record.items():
                if isinstance(value, dict) and value.get("uri"):
                    # This looks like a node
                    node_id = value.get("uri", f"node_{i}_{key}")
                    nodes.append({
                        "id": node_id,
                        "label": infer_node_label_from_uri(value.get("uri", "")),
                        "caption": value.get("label", value.get("name", "Unknown")),
                        "type": infer_node_label_from_uri(value.get("uri", "")),
                        "properties": {
                            **value,
                            "isCypherResult": True
                        },
                        "color": "#4287f5",  # Blue for Cypher results
                        "size": 50
                    })

    return {
        "cypher_query": cypher_query,
        "explanation": explanation,
        "execution_result": {
            "nodes": nodes,
            "relationships": relationships,
            "summary": {
                "total_nodes": len(nodes),
                "total_relationships": len(relationships),
                "execution_time": 0.0
            }
        },
        "confidence": confidence,
        "query_validated": True
    }

def get_score_color(score: float) -> str:
    """Map relevance scores to colors for NVL visualization"""
    if score >= 0.9:
        return "#00ff00"  # High relevance - bright green
    elif score >= 0.8:
        return "#7fff00"  # Medium-high - chartreuse
    elif score >= 0.7:
        return "#ffff00"  # Medium - yellow
    elif score >= 0.6:
        return "#ffa500"  # Medium-low - orange
    else:
        return "#ff4500"  # Lower relevance - orange-red

def get_score_size(score: float) -> float:
    """Map relevance scores to node sizes for NVL"""
    base_size = 40
    max_size = 100
    return base_size + (score * (max_size - base_size))

def infer_node_label_from_uri(uri: str) -> str:
    """Infer node label from URI"""
    if not uri:
        return "Unknown"
    if "CVE-" in uri:
        return "UcoCVE"
    if "CWE-" in uri:
        return "UcoCWE"
    if "cpe:" in uri:
        return "UcoexCPE"
    if "CAPEC-" in uri:
        return "UcoexCAPEC"
    return "Unknown"

# Lifespan management is now handled by the lifespan context manager above

# API Endpoints
@app.get("/")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "UCKG Q&A Engine is running"}

@app.get("/api/schema")
def get_schema():
    """Get detailed schema information"""
    try:
        if not text2cypher_engine:
            raise HTTPException(status_code=503, detail="Text2Cypher engine not initialized")
        
        schema_info = text2cypher_engine.get_schema_info()
        return schema_info
    except Exception as e:
        logger.error(f"Error getting schema: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rag")
async def rag_query(request: RAGRequest):
    """Execute MultiRAG query"""
    try:
        if not multirag_engine:
            raise HTTPException(status_code=503, detail="MultiRAG engine not initialized")
        
        logger.info(f"Processing RAG query: {request.query} (mode: {request.mode})")
        
        # Execute MultiRAG query
        result = multirag_engine.run(request.query)
        
        # Format for frontend
        formatted_result = format_multirag_result(result)
        
        logger.info(f"RAG query completed successfully")
        return formatted_result
        
    except Exception as e:
        logger.error(f"Error processing RAG query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/text2cypher")
async def text2cypher_query(request: Text2CypherRequest):
    """Execute Text2Cypher query"""
    try:
        if not text2cypher_engine:
            raise HTTPException(status_code=503, detail="Text2Cypher engine not initialized")
        
        logger.info(f"Processing Text2Cypher query: {request.question}")
        
        # Get schema and generate Cypher
        schema = text2cypher_engine.get_schema()
        cypher_query = text2cypher_engine.text_to_cypher(request.question, schema)
        logger.info(f"Generated Cypher: {cypher_query}")
        
        # Execute query if requested
        execution_result = None
        if request.execute:
            execution_result = text2cypher_engine.run_cypher(cypher_query)
            logger.info(f"Query returned {len(execution_result) if execution_result else 0} results")
        
        # Generate explanation
        explanation = f"Converted '{request.question}' to Cypher query"
        if request.explain:
            explanation += f" and executed successfully, returning {len(execution_result) if execution_result else 0} results."
        
        # Calculate confidence (simple heuristic)
        confidence = 0.8 if execution_result else 0.5
        
        # Format for frontend
        formatted_result = format_text2cypher_result(cypher_query, execution_result, explanation, confidence)
        
        logger.info("Text2Cypher query completed successfully")
        return formatted_result
        
    except Exception as e:
        logger.error(f"Error processing Text2Cypher query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat_history")
async def chat_history(request: ChatRequest):
    """Chat with history support"""
    try:
        logger.info(f"Chat history query: {request.question}")
        
        # For now, redirect to RAG query
        # In the future, this could implement proper chat history
        rag_request = RAGRequest(query=request.question)
        result = await rag_query(rag_request)
        
        return {"answer": result["answer"]}
        
    except Exception as e:
        logger.error(f"Chat history error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
