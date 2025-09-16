# Text2Cypher Standalone Module

This directory provides a minimal, testable implementation of a Text-to-Cypher pipeline using FastAPI, Neo4j, and Ollama (open LLM).

## Features
- Converts natural language questions to Cypher queries using an LLM (Ollama)
- Runs Cypher queries on your Neo4j database
- Returns both the generated Cypher and the query results

## Setup

1. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

2. **Start Neo4j** (with your data loaded and accessible at `bolt://localhost:7687`)

3. **Start Ollama** (with your desired model, e.g. `llama3`):
   ```sh
   ollama serve
   ollama pull llama3
   ```

4. **Run the FastAPI app:**
   ```sh
   uvicorn main:app --reload --port 8001
   ```

## Usage

Send a POST request to `http://localhost:8001/api/text2cypher` with a JSON body:
```json
{
  "question": "List all CVEs from 2023"
}
```

Response:
```json
{
  "cypher": "MATCH (n:CVE {year: 2023}) RETURN n",
  "result": [ ... ]
}
```

## Configuration
- Edit `main.py` to change Neo4j or Ollama connection details or model.

## Notes
- This is a minimal, testable pipeline for development and experimentation.
- For production, add authentication, error handling, and security as needed. 