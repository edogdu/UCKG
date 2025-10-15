# Text2Cypher Standalone Module

This directory provides a minimal, testable implementation of a Text-to-Cypher pipeline using FastAPI, Neo4j, and Ollama (open LLM).

## Features
- Converts natural language questions to Cypher queries using an LLM (Ollama)
- **V4 Update**: Bidirectional paths, multi-hop templates, cardinality analysis, filtering hints, intelligent error handling, and Cypher Guard validation
- Dynamic schema extraction with real-time property discovery
- Cybersecurity-focused schema filtering (excludes ontology metadata)
- Runs Cypher queries on your Neo4j database
- **Enhanced Error Handling**: LLM-generated helpful responses for empty results and errors
- **Smart Suggestions**: Context-aware query suggestions based on user intent
- **Cypher Guard Validation**: Robust query validation with fallback system
- Returns both the generated Cypher and the query results with comprehensive status information

## What's New in V4

**Bidirectional Paths & Advanced Features**: The schema now provides complete graph topology understanding:

```
UcoCVE:
  Outgoing:
    - UcoCVE -[UCOEXHASCPE]-> UcoexCPE (1:many)
  Incoming:
    - UcoVulnerability -[UCOHASCVE_ID]-> UcoCVE (1:1)

Common Multi-hop Path Templates:
- UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK <-[UCOEXSOFTWAREUSESTECHNIQUE]- UcoexSOFTWARE

Property-based Filtering Hints:
- UcoCVE: Filter by ucobaseSeverity: 'HIGH', 'MEDIUM', 'LOW'
- UcoexGROUPS: Filter by ucoexDOMAIN: 'enterprise-attack', 'mobile-attack', 'ics-attack'
```

V4 enables complex multi-hop queries, reverse analysis, performance-optimized query generation, and intelligent error handling.

**Error Handling Features:**
- LLM-generated helpful responses for empty results
- Context-aware query suggestions
- Graceful error handling with user-friendly messages
- Structured response format with status indicators

**Cypher Guard Validation:**
- Robust query validation using industry-standard tools
- Automatic fallback when Cypher Guard is not available
- Schema-aware validation against actual Neo4j database
- Security enforcement (read-only queries only)
- Comprehensive error detection and reporting

See [V4_BIDIRECTIONAL_ADVANCED_UPDATE.md](V4_BIDIRECTIONAL_ADVANCED_UPDATE.md), [V4_ERROR_HANDLING_UPDATE.md](V4_ERROR_HANDLING_UPDATE.md), and [V4_CYPHER_GUARD_INTEGRATION.md](V4_CYPHER_GUARD_INTEGRATION.md) for full details.

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

### Enhanced Endpoint (Recommended)
Send a POST request to `http://localhost:8001/api/text2cypher` with a JSON body:
```json
{
  "question": "List all CVEs from 2023"
}
```

Enhanced Response (with error handling):
```json
{
  "cypher": "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve LIMIT 10",
  "result": [/* query results */],
  "status": "success",
  "message": "Query executed successfully. Found 5 results.",
  "count": 5,
  "suggestions": [/* helpful suggestions if needed */]
}
```

### Simple Endpoint (Backward Compatibility)
Send a POST request to `http://localhost:8001/api/text2cypher/simple` for the original behavior:
```json
{
  "question": "List all CVEs from 2023"
}
```

Simple Response:
```json
{
  "cypher": "MATCH (n:CVE {year: 2023}) RETURN n",
  "result": [ ... ]
}
```

### Validation Endpoint

Get validation system information:
```bash
GET http://localhost:8001/api/validation
```

Response:
```json
{
  "cypher_guard_status": "fallback",
  "validation_info": {
    "cypher_guard_available": false,
    "validation_mode": "Fallback",
    "node_types": 26,
    "relationship_types": 157,
    "schema_loaded": true
  },
  "features": [
    "Syntax validation",
    "Schema validation", 
    "Read-only query enforcement",
    "Security checks"
  ]
}
```

### Error Handling Examples

**No Results Found:**
```json
{
  "cypher": "MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'CRITICAL' RETURN cve",
  "result": [],
  "status": "no_results",
  "message": "No results found for your query. Try broadening your search criteria or using different keywords.",
  "count": 0,
  "suggestions": [
    "Try: 'Show CVEs with high severity'",
    "Try: 'Find CVEs affecting Windows platforms'"
  ]
}
```

**Query Error:**
```json
{
  "cypher": null,
  "result": [],
  "status": "error",
  "message": "I encountered an error processing your question. Please try rephrasing your question.",
  "count": 0,
  "error": "Validation failed: Nodes should have labels",
  "suggestions": [
    "Try asking about specific node types (CVEs, CWEs, CAPEC patterns, etc.)",
    "Try using broader search terms"
  ]
}
```

## Configuration
- Edit `main.py` to change Neo4j or Ollama connection details or model.

## Notes
- This is a minimal, testable pipeline for development and experimentation.
- For production, add authentication, error handling, and security as needed. 