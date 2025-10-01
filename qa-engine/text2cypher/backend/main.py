from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from logger import get_logger

# Import logger from logger module
logger = get_logger()

# --- Early import and instantiation to catch startup errors ---
try:
    from text2cypher import Text2Cypher
    from ollama_llm import OllamaLLM
except ImportError as e:
    logger.critical(f"Failed to import necessary modules: {e}")
    # Exit if core modules are missing
    exit(1)

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Text2Cypher API",
    description="Convert natural language to Cypher queries for Neo4j",
    version="1.0.0"
)

# Add CORS middleware for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"], # Add other origins if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration Loading ---
# Load configuration from environment variables with sensible defaults.
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# --- Service Initialization ---
# Instantiate core components. If schema file is missing, Text2Cypher will log
# a critical error, and subsequent calls will fail.
try:
    llm = OllamaLLM(base_url=OLLAMA_URL, model=OLLAMA_MODEL)
    t2c = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)
    logger.info("Successfully initialized Text2Cypher and LLM components.")
except Exception as e:
    logger.critical(f"FATAL: Failed to initialize Text2Cypher service. Is the schema file present? Error: {e}")
    # You might want to exit here if the service cannot run at all
    # exit(1)

# --- API Models ---
class QueryRequest(BaseModel):
    question: str

class ChatRequest(QueryRequest):
    session_id: str

# --- API Endpoints ---
@app.get("/")
def health_check():
    """Health check endpoint to confirm the API is running."""
    return {"status": "healthy", "message": "Text2Cypher API is running"}

@app.get("/api/schema")
def get_schema_endpoint():
    """Returns the graph schema content as loaded from the text file."""
    try:
        schema_info = t2c.get_schema_info()
        return schema_info
    except Exception as e:
        logger.error(f"Error getting schema: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not retrieve schema information.")

@app.post("/api/text2cypher")
def text2cypher_endpoint(req: QueryRequest):
    """Converts a natural language question to a Cypher query and executes it."""
    try:
        logger.info(f"Processing question: '{req.question}'")
        
        # The schema is now pre-loaded in t2c, no need to pass it here
        cypher = t2c.text_to_cypher(req.question)
        logger.info(f"Generated Cypher: {cypher}")
        
        result = t2c.run_cypher(cypher)
        logger.info(f"Query returned {len(result)} results.")
        
        return {"cypher": cypher, "result": result}
    except ValueError as ve:
        # Catch validation or schema loading errors specifically
        logger.error(f"Processing error for question '{req.question}': {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"An unexpected error occurred for question '{req.question}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {str(e)}")

# Note: The chat_history endpoint and its dependencies are omitted for brevity
# as they were not part of the requested changes. They would remain the same.
#
# @app.post("/api/chat_history")
# def chat_history(req: ChatRequest):
#     ...