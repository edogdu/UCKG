# Text2Cypher Standalone Module

This directory provides a minimal, testable implementation of a Text-to-Cypher pipeline using FastAPI, Neo4j, and Ollama (open LLM).

## Features
- Converts natural language questions to Cypher queries using an LLM (Ollama)
- Runs Cypher queries on your Neo4j database
- Returns both the generated Cypher and the query results

## Setup (run from the backend folder)
1. Open a terminal and change to the backend folder:
   ```powershell
   cd C:\Users\User\Downloads\UCKG\text2cypher\backend
   ```

2. Create and activate a virtual environment
   - PowerShell:
     ```powershell
     python -m venv .venv
     . .venv\Scripts\Activate.ps1
     ```
     (If execution policy blocks Activate.ps1, run the CMD variant below or open PowerShell as Administrator.)
   - CMD:
     ```cmd
     python -m venv .venv
     .venv\Scripts\activate.bat
     ```

3. Install Python dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Ensure Neo4j is running and reachable (default: bolt://localhost:7687). If needed, set environment variables:
   - PowerShell example:
     ```powershell
     $env:NEO4J_URI="bolt://localhost:7687"
     $env:NEO4J_USER="neo4j"
     $env:NEO4J_PASSWORD="abcd90909090"
     ```

5. Export the Neo4j schema to neo4j_graph_schema.txt (required for prompts/validation):
   ```powershell
   python neo4j_schema_extractor.py
   ```
   - This creates `neo4j_graph_schema.txt` in this backend folder.
   - If export fails, check Neo4j connectivity and credentials.

6. Prepare Ollama (in a separate terminal) and make sure a model is available:
   ```powershell
   ollama pull llama3
   ollama serve
   ```
   Keep `ollama serve` running in its own window.

7. Start the FastAPI app (from the backend folder, venv activated):
   ```powershell
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
- Environment variables supported:
  - NEO4J_URI (default: bolt://localhost:7687)
  - NEO4J_USER (default: neo4j)
  - NEO4J_PASSWORD (default: abcd90909090)
  - OLLAMA_URL (default: http://localhost:11434)
  - OLLAMA_MODEL (default: llama3)
- The code will look for `neo4j_graph_schema.txt` next to the backend module. Export schema before running the app.

## Notes / Troubleshooting
- If you see "Could not load schema file", confirm `neo4j_graph_schema.txt` exists in this folder.
- Run `neo4j_schema_extractor.py` again after changing the database schema.
- Keep Ollama running before invoking endpoints that call the LLM.
- This is a development/test setup; add authentication, error handling and security before production.