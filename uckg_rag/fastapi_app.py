from fastapi import FastAPI, Query
from rag_pipeline import ask

app = FastAPI()

@app.get("/query")
def query(
    ask_query: str = Query(..., description="Your question"),
    model: str = Query("huggingface", description="Model to use (huggingface, ollama, openai)"),
    graph_context: bool = Query(False, description="Enable graph context expansion")
):
    result = ask(ask_query, provider=model, graph_context=graph_context)
    return {
        "question": ask_query,
        "answer": result["answer"],
        "sources": result["sources"],
        "graph_context": result.get("graph_expansion", None)
    }

@app.get("/")
def root():
    return {"message": "UCKG RAG API is live. Use /query?ask=...&model=...&graph_context=true"}