from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .text2cypher import Text2Cypher
# NOTE: Configuration is now environment-driven. See ``ollama_llm.OllamaLLM``.
from .ollama_llm import OllamaLLM
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Text2Cypher API",
    description="Convert natural language to Cypher queries for Neo4j",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration: prefer environment variables so that the same code works both
# locally and inside Docker Compose.
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")

# ``ollama_llm`` already resolves ``OLLAMA_URL`` and ``OLLAMA_MODEL`` env vars,
# but we keep them here for clarity and to document defaults.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Instantiate LLM wrapper with resolved values.
llm = OllamaLLM(base_url=OLLAMA_URL, model=OLLAMA_MODEL)
t2c = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)

class QueryRequest(BaseModel):
    question: str

@app.get("/")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Text2Cypher API is running"}

@app.get("/api/schema")
def get_schema():
    """Get detailed schema information"""
    try:
        schema_info = t2c.get_schema_info()
        return schema_info
    except Exception as e:
        logger.error(f"Error getting schema: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/text2cypher")
def text2cypher_endpoint(req: QueryRequest):
    try:
        logger.info(f"Processing query: {req.question}")
        schema = t2c.get_schema()
        cypher = t2c.text_to_cypher(req.question, schema)
        logger.info(f"Generated Cypher: {cypher}")
        result = t2c.run_cypher(cypher)
        logger.info(f"Query returned {len(result)} results")
        return {"cypher": cypher, "result": result}
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 