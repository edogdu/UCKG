from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from text2cypher import Text2Cypher
# NOTE: Configuration is now environment-driven. See ``ollama_llm.OllamaLLM``.
from ollama_llm import OllamaLLM
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

# -------- Chat-from-history support ---------
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
    from chat_memory import get_memory
    from chat_types import ChatMessage, Role

    mem = get_memory(session_id)
    prompt = HISTORY_PROMPT.format(history=mem.formatted_history(), question=question)

    raw_answer = llm.invoke(prompt).strip()

    # store turns
    mem.add(ChatMessage(role=Role.USER, content=question))
    mem.add(ChatMessage(role=Role.ASSISTANT, content=raw_answer))
    return raw_answer

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
    uvicorn.run(app, host="0.0.0.0", port=8000)