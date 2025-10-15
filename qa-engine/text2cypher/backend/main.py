from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from text2cypher import Text2Cypher
# NOTE: Configuration is now environment-driven. See ``ollama_llm.OllamaLLM``.
from ollama_llm import OllamaLLM
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

# Add CORS middleware with more permissive settings for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=False,  # Set to False when using wildcard origins
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# --- Configuration Loading ---
# Load configuration from environment variables with sensible defaults.
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Instantiate LLM wrapper with resolved values.
llm = OllamaLLM(base_url=OLLAMA_URL, model=OLLAMA_MODEL)

# Instantiate Text2Cypher with V2 capabilities
# Force reload of the module to ensure latest code is used
import importlib
import text2cypher
importlib.reload(text2cypher)
t2c = text2cypher.Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)

# --- API Models ---
class QueryRequest(BaseModel):
    question: str

class ChatRequest(QueryRequest):
    session_id: str

# prompt template
HISTORY_EXAMPLE = (
    "Chat history:\nUSER: Hi\nASSISTANT: Hello\n\n"
    "User question: What did I just say?\n"
    "Assistant: You said: \"Hi\".\n\n"
)

HISTORY_PROMPT = (
    "You are an assistant that helps to form nice and human understandable answers.\n"
    "The information part contains the current chat history that you must use to answer the user.\n"
    "The provided information is authoritative, you must never doubt it or try to use your internal knowledge to correct it.\n"
    "Make the answer sound as a response to the question. Do not mention that you based the result on the given information.\n"
    "If the provided information is empty, say that you don't know the answer.\n\n"
    "Information:\n{history}\n\n"
    "Question: {question}\n\n"
    "Helpful Answer:"
)

def answer_from_history(session_id: str, question: str) -> str:
    from memory import get_memory
    from memory import ChatMessage, Role

    mem = get_memory(session_id)
    prompt = HISTORY_PROMPT.format(history=mem.formatted_history(), question=question)

    raw_answer = llm.invoke(prompt).strip()

    # store turns
    mem.add(ChatMessage(role=Role.USER, content=question))
    mem.add(ChatMessage(role=Role.ASSISTANT, content=raw_answer))
    return raw_answer

@app.get("/")
def health_check():
    """Health check endpoint to confirm the API is running."""
    return {"status": "healthy", "message": "Text2Cypher API is running"}

@app.options("/{path:path}")
def options_handler(path: str):
    """Handle CORS preflight for all endpoints"""
    return {"status": "ok", "path": path}

@app.options("/api/text2cypher")
def options_text2cypher():
    """Handle CORS preflight for text2cypher endpoint"""
    return {"status": "ok"}

@app.options("/api/schema")
def options_schema():
    """Handle CORS preflight for schema endpoint"""
    return {"status": "ok"}

@app.options("/api/chat_history")
def options_chat_history():
    """Handle CORS preflight for chat_history endpoint"""
    return {"status": "ok"}

@app.get("/api/schema")
def get_schema_endpoint():
    """Returns the graph schema content as loaded from the text file."""
    try:
        logger.info("Calling t2c.get_schema_info()")
        schema_info = t2c.get_schema_info()
        logger.info(f"Schema info keys: {list(schema_info.keys())}")
        logger.info(f"Has node_types: {'node_types' in schema_info}")
        logger.info(f"Has schema_status: {'schema_status' in schema_info}")
        return schema_info
    except Exception as e:
        logger.error(f"Error getting schema: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not retrieve schema information.")

@app.get("/api/validation")
def get_validation_info():
    """Get Cypher Guard validation information"""
    try:
        validation_info = t2c.cypher_validator.get_validation_info()
        return {
            "cypher_guard_status": "active",
            "validation_info": validation_info,
            "features": [
                "Syntax validation",
                "Schema validation", 
                "Read-only query enforcement",
                "Security checks"
            ]
        }
    except Exception as e:
        logger.error(f"Error getting validation info: {str(e)}")
        return {
            "cypher_guard_status": "error",
            "error": str(e),
            "fallback_validation": "active"
        }

@app.post("/api/text2cypher")
def text2cypher_endpoint(req: QueryRequest):
    """Enhanced text2cypher endpoint with comprehensive error handling and fallback responses."""
    try:
        logger.info(f"Processing query: {req.question}")
        schema = t2c.get_schema()
        
        # Use enhanced method with fallback handling
        response = t2c.text_to_cypher_with_fallback(req.question, schema)
        
        # Add relationship information if query was successful
        if response.get('cypher') and response.get('status') == 'success':
            relationship_info = t2c.extract_query_relationships(response['cypher'])
            response['relationship_info'] = relationship_info
        
        logger.info(f"Query status: {response['status']}")
        if response['cypher']:
            logger.info(f"Generated Cypher: {response['cypher']}")
        logger.info(f"Response message: {response['message']}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        # Return a structured error response instead of raising HTTPException
        return {
            "cypher": None,
            "result": [],
            "status": "error",
            "message": f"I encountered an unexpected error processing your question: '{req.question}'. Please try again or contact support if the issue persists.",
            "count": 0,
            "error": str(e),
            "suggestions": [
                "Try rephrasing your question",
                "Check if the question is about cybersecurity entities (CVEs, CWEs, CAPEC, etc.)",
                "Try asking about specific node types or relationships"
            ]
        }

@app.post("/api/text2cypher/simple")
def text2cypher_simple_endpoint(req: QueryRequest):
    """Simple text2cypher endpoint for backward compatibility (original behavior)."""
    try:
        logger.info(f"Processing simple query: {req.question}")
        schema = t2c.get_schema()
        cypher = t2c.text_to_cypher(req.question, schema)
        logger.info(f"Generated Cypher: {cypher}")
        
        result = t2c.run_cypher(cypher)
        result_list = list(result)
        logger.info(f"Query returned {len(result_list)} results")
        return {"cypher": cypher, "result": result_list}
    except Exception as e:
        logger.error(f"Error processing simple query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ---------- new endpoint --------------------

@app.post("/api/chat_history")
def chat_history(req: ChatRequest):
    try:
        logger.info(f"Chat history Q: {req.question}")
        answer = answer_from_history(req.session_id, req.question)
        return {"answer": answer}
    except Exception as e:
        logger.error(f"Chat-history error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)