# Text2Cypher (T2C) Software Architecture

## Overview

Text2Cypher converts natural language questions into Neo4j Cypher queries for the UCKG (Unified Cybersecurity Knowledge Graph). The system supports **two pipeline methods**:

1. **Full Schema Method** (Default) - Uses complete schema in LLM prompt
2. **T2CSS Method** (Semantic Filtering) - Uses cosine-similarity filtered schema for reduced token usage

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React)                          │
│  File: qa-engine/text2cypher/frontend/src/App.js            │
│  - User query input                                          │
│  - Display results, schema, validation info                  │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP POST /api/text2cypher
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Backend API (FastAPI)                           │
│  File: qa-engine/text2cypher/backend/main.py                │
│  - Endpoint routing                                          │
│  - Method selection (Full vs T2CSS)                          │
│  - Environment variable: USE_T2CSS=true/false                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ├─────────────┬─────────────────────┐
                       ▼             ▼                     ▼
          ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐
          │  Text2Cypher    │  │ T2CSS Module │  │  LLM Module  │
          │   (Full)        │  │  (Filtered)  │  │   (Ollama)   │
          └─────────────────┘  └──────────────┘  └──────────────┘
                       │             │                     │
                       └─────────────┴─────────────────────┘
                                     │
                                     ▼
                       ┌──────────────────────────┐
                       │   Neo4j Database (UCKG)  │
                       └──────────────────────────┘
```

---

## Method 1: Full Schema Pipeline

### Architecture Flow

```
User Question
     │
     ▼
┌──────────────────────────────────────────────────────┐
│ Text2Cypher.text_to_cypher()                         │
│ File: qa-engine/text2cypher/backend/text2cypher.py  │
└─────────┬────────────────────────────────────────────┘
          │
          ├─► Step 1: Load Full Schema
          │   Method: get_cybersecurity_schema()
          │   Input: None
          │   Output: Full schema text (all nodes + relationships)
          │   Source: qa-engine/shared/schema_cache.txt
          │
          ├─► Step 2: Build Prompt
          │   Method: _build_prompt()
          │   Inputs:
          │     - User question
          │     - Full schema block
          │     - Few-shot examples (from config.py)
          │     - Semantic descriptions (from CYBERSECURITY_SEMANTICS)
          │   Output: Complete LLM prompt
          │
          ├─► Step 3: LLM Generation
          │   Method: llm.invoke()
          │   Module: qa-engine/text2cypher/backend/llm/ollama_llm.py
          │   Input: Full prompt
          │   Output: Raw LLM response (with Cypher query)
          │
          ├─► Step 4: Extract & Fix Cypher
          │   Method: extract_cypher()
          │   Input: Raw LLM response
          │   Process:
          │     - Parse markdown code blocks
          │     - Apply fix_common_label_mistakes()
          │     - Add LIMIT if missing
          │   Output: Clean Cypher query
          │
          ├─► Step 5: Validate Query
          │   Method: cypher_validator.validate_query()
          │   Module: qa-engine/text2cypher/backend/cypher_validation.py
          │   Input: Cypher query
          │   Output: Validation status + errors
          │
          └─► Step 6: Execute Query
              Method: run_cypher()
              Input: Validated Cypher query
              Output: Query results (list of records)
```

### Code Modules

| Module | File Path | Description |
|--------|-----------|-------------|
| **Main Pipeline** | `qa-engine/text2cypher/backend/text2cypher.py` | Core T2C logic (Full Schema method) |
| **API Server** | `qa-engine/text2cypher/backend/main.py` | FastAPI endpoints |
| **Configuration** | `qa-engine/text2cypher/backend/config.py` | Prompts, few-shot examples, excluded labels |
| **LLM Interface** | `qa-engine/text2cypher/backend/llm/ollama_llm.py` | Ollama LLM wrapper |
| **Cypher Validation** | `qa-engine/text2cypher/backend/cypher_validation.py` | Query validation (Cypher Guard) |
| **Schema Cache** | `qa-engine/shared/schema_cache.txt` | Pre-extracted UCKG schema |

### Key Methods in text2cypher.py

```python
class Text2Cypher:
    def text_to_cypher(self, question: str, schema: str = None) -> dict:
        """Main entry point for Full Schema method"""
        # Load full schema
        schema_block = schema or self.get_cybersecurity_schema()
        
        # Build prompt with semantic descriptions
        prompt = self._build_prompt(question, schema_block, examples)
        
        # Generate Cypher via LLM
        response = self.llm.invoke(prompt)
        
        # Extract and clean Cypher
        cypher = self.extract_cypher(response)
        
        # Validate
        validation = self.cypher_validator.validate_query(cypher)
        
        # Execute
        results = self.run_cypher(cypher)
        
        return {"cypher": cypher, "results": results, ...}
    
    def get_cybersecurity_schema(self) -> str:
        """Read full schema from cache file"""
        # Reads: qa-engine/shared/schema_cache.txt
        
    def _build_prompt(self, question, schema_block, examples) -> str:
        """Assemble LLM prompt with rules, schema, semantics, examples"""
```

---

## Method 2: T2CSS (Semantic Filtering) Pipeline

### Architecture Flow

```
User Question
     │
     ▼
┌──────────────────────────────────────────────────────┐
│ T2CypherWithT2CSS.text_to_cypher()                   │
│ File: qa-engine/text2cypher/backend/t2css_integration.py │
└─────────┬────────────────────────────────────────────┘
          │
          ├─► Step 1: Generate Semantic Triples
          │   Method: T2CSSPipeline.generate_semantic_texts()
          │   Module: qa-engine/text2cypher/backend/t2css_pipeline.py
          │   Input: Full schema text
          │   Process:
          │     - Parse node labels + properties
          │     - Parse relationship patterns
          │     - Attach semantic descriptions from CYBERSECURITY_SEMANTICS
          │   Output: List of SchemaTriple objects
          │   Example:
          │     SchemaTriple(
          │       subject="UcoCVE",
          │       predicate="is_a",
          │       object="node_type",
          │       text="UcoCVE is a Common Vulnerabilities and Exposures...",
          │       properties=["id", "ucobaseSeverity", ...]
          │     )
          │
          ├─► Step 2: Embed Schema Triples
          │   Method: T2CSSPipeline.embed_schema_triples()
          │   Input: List of SchemaTriple objects
          │   Process:
          │     - Generate embeddings using Ollama nomic-embed-text
          │     - Cache embeddings to schema_embeddings.json
          │   Output: SchemaTriple objects with .embedding field populated
          │
          ├─► Step 3: Embed User Question
          │   Method: T2CSSPipeline._embed_text()
          │   Input: User question string
          │   Output: Question embedding vector (numpy array)
          │
          ├─► Step 4: Filter Schema by Similarity
          │   Method: T2CSSPipeline.filter_schema_by_similarity()
          │   Input:
          │     - Question embedding
          │     - All schema triple embeddings
          │     - top_k (default: 10)
          │   Process:
          │     - Calculate cosine similarity between question and each triple
          │     - Sort by similarity score (descending)
          │     - Select top-k most relevant triples
          │   Output: Filtered list of top-k SchemaTriple objects
          │
          ├─► Step 5: Assemble Filtered Prompt
          │   Method: T2CSSPipeline.assemble_prompt()
          │   Input:
          │     - User question
          │     - Filtered schema triples (top-k)
          │     - Few-shot examples
          │   Output: Compact LLM prompt with only relevant schema
          │
          ├─► Step 6: LLM Generation
          │   Method: llm.invoke()
          │   Input: Filtered prompt
          │   Output: Raw LLM response (with Cypher query)
          │
          ├─► Step 7: Extract & Fix Cypher
          │   (Same as Full Schema method)
          │
          ├─► Step 8: Validate Query
          │   (Same as Full Schema method)
          │
          └─► Step 9: Execute Query
              (Same as Full Schema method)
```

### Code Modules

| Module | File Path | Description |
|--------|-----------|-------------|
| **T2CSS Pipeline** | `qa-engine/text2cypher/backend/t2css_pipeline.py` | Semantic filtering logic |
| **T2CSS Integration** | `qa-engine/text2cypher/backend/t2css_integration.py` | T2CypherWithT2CSS wrapper class |
| **Embedding Cache** | `qa-engine/text2cypher/backend/schema_embeddings.json` | Cached schema embeddings |
| **Semantic Mappings** | `qa-engine/text2cypher/backend/config.py` | CYBERSECURITY_SEMANTICS dictionary |
| **API Server** | `qa-engine/text2cypher/backend/main.py` | Runtime toggle via USE_T2CSS env var |

### Key Methods in t2css_pipeline.py

```python
class T2CSSPipeline:
    def generate_semantic_texts(self, schema_text: str) -> List[SchemaTriple]:
        """Step 1: Parse schema and create semantic triples"""
        # Parse nodes: "UcoCVE {id: string, ...}"
        # Parse rels: "(:UcoCVE) -[:UCOEXHASCPE]-> (:UcoexCPE)"
        # Attach semantic descriptions from CYBERSECURITY_SEMANTICS
        
    def embed_schema_triples(self, triples: List[SchemaTriple]) -> List[SchemaTriple]:
        """Step 2: Generate embeddings for each triple"""
        # Uses Ollama nomic-embed-text model
        # Caches to schema_embeddings.json
        
    def filter_schema_by_similarity(self, question: str, top_k: int = 10) -> List[SchemaTriple]:
        """Step 3-4: Embed question, calculate cosine similarity, filter top-k"""
        question_emb = self._embed_text(question)
        
        # Calculate cosine similarity
        similarities = []
        for triple in self.schema_triples:
            score = cosine_similarity(question_emb, triple.embedding)
            similarities.append((score, triple))
        
        # Sort and select top-k
        similarities.sort(reverse=True, key=lambda x: x[0])
        return [triple for score, triple in similarities[:top_k]]
        
    def assemble_prompt(self, question: str, filtered_triples: List[SchemaTriple]) -> str:
        """Step 5: Build compact prompt with filtered schema"""
        # Reconstructs schema block from filtered triples only
```

### Key Methods in t2css_integration.py

```python
class T2CypherWithT2CSS(Text2Cypher):
    """Extended Text2Cypher with T2CSS filtering"""
    
    def text_to_cypher(self, question: str, schema: str = None) -> dict:
        """Override to use filtered schema"""
        if self.use_t2css:
            # Get filtered schema via T2CSS pipeline
            filtered_triples = self.t2css_pipeline.filter_schema_by_similarity(
                question, top_k=self.top_k_schema
            )
            filtered_schema = self._reconstruct_schema(filtered_triples)
            
            # Build prompt with filtered schema
            prompt = self._build_prompt(question, filtered_schema, examples)
        else:
            # Fall back to full schema method
            return super().text_to_cypher(question, schema)
        
        # Rest of pipeline (LLM, validation, execution) is identical
```

---

## Runtime Method Selection

In `main.py`:

```python
# Environment variables control which method is used
USE_T2CSS = os.getenv("USE_T2CSS", "false").lower() == "true"
T2CSS_TOP_K = int(os.getenv("T2CSS_TOP_K", "10"))

if USE_T2CSS:
    # Use T2CSS filtered method
    from t2css_integration import create_enhanced_text2cypher
    t2c = create_enhanced_text2cypher(
        NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm,
        use_t2css=True, top_k_schema=T2CSS_TOP_K
    )
else:
    # Use full schema method
    import text2cypher
    t2c = text2cypher.Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)
```

**To switch methods:**
```bash
# Full Schema (default)
export USE_T2CSS=false
python3 main.py

# T2CSS Filtered
export USE_T2CSS=true
export T2CSS_TOP_K=15
python3 main.py
```

---

## Comparison: Full Schema vs T2CSS

| Aspect | Full Schema Method | T2CSS Filtered Method |
|--------|-------------------|----------------------|
| **Schema Size in Prompt** | Complete schema (~5000 tokens) | Top-k filtered schema (~500-1000 tokens) |
| **Token Usage** | High | Low (80-90% reduction) |
| **LLM Context Window** | Consumes most of context | Leaves room for longer conversations |
| **Accuracy** | High (all schema available) | Comparable if top_k ≥ 10 |
| **Latency** | Fast (no embedding step) | Slightly slower (embedding + similarity) |
| **Use Case** | Simple queries, small schemas | Complex queries, large schemas, chat history |
| **Setup Complexity** | Simple | Requires Ollama embedding model |
| **Caching** | Schema cache only | Schema + embedding cache |

---

## File Structure Summary

```
qa-engine/
├── shared/
│   ├── schema_extract.py          # Schema extraction from Neo4j
│   ├── schema_cache.txt           # Cached full schema (used by both methods)
│   ├── run_schema_extraction.py   # Runner script
│   └── README.md                  # Schema extraction documentation
│
└── text2cypher/
    ├── backend/
    │   ├── main.py                      # FastAPI server, method selection
    │   ├── config.py                    # Prompts, semantics, config
    │   ├── text2cypher.py               # Full Schema pipeline (Method 1)
    │   ├── t2css_pipeline.py            # T2CSS filtering logic (Method 2)
    │   ├── t2css_integration.py         # T2CypherWithT2CSS wrapper
    │   ├── schema_embeddings.json       # Cached embeddings for T2CSS
    │   ├── cypher_validation.py         # Cypher Guard validator
    │   ├── requirements.txt             # Python dependencies
    │   ├── T2CSS_README.md              # T2CSS documentation
    │   ├── T2C_ARCHITECTURE.md          # This file
    │   │
    │   ├── llm/
    │   │   ├── __init__.py
    │   │   ├── ollama_llm.py            # Ollama LLM interface
    │   │   ├── gemma_llm.py             # Gemma LLM interface (optional)
    │   │   └── gemma_mps.py             # Gemma MPS support (optional)
    │   │
    │   ├── memory/
    │   │   ├── __init__.py
    │   │   ├── chat_memory.py           # Conversation history management
    │   │   └── chat_types.py            # Message data models
    │   │
    │   ├── evaluation/
    │   │   ├── __init__.py
    │   │   ├── evaluate_models.py       # Model evaluation scripts
    │   │   └── generate_eval_dataset.py # Evaluation dataset generator
    │   │
    │   └── testing/
    │       ├── __init__.py
    │       ├── test_cypher_guard.py          # Validation tests
    │       ├── test_working_queries.py       # Query execution tests
    │       ├── preview_filtered_schema.py    # T2CSS preview tool
    │       ├── run_t2css_tests.py            # T2CSS test runner
    │       └── t2css_test_queries.json       # Test dataset
    │
    └── frontend/
        └── src/
            ├── App.js                   # React UI
            ├── api.js                   # Backend API client
            └── sampleQueries.json       # Categorized sample queries
```

---

## Dependencies

### Backend (requirements.txt)
```
fastapi==0.104.1
uvicorn==0.24.0
neo4j==5.14.1
langchain==0.1.0
langchain-community==0.0.10
pydantic==2.5.2
python-dotenv==1.0.0
numpy==1.24.3
scikit-learn==1.3.2
```

### LLM Service
- Ollama (running locally)
- Models:
  - `llama3` (text generation)
  - `nomic-embed-text` (embeddings for T2CSS)

### Neo4j Database
- UCKG graph database
- Connection: `bolt://localhost:7687`

---

## API Endpoints

### POST /api/text2cypher
Convert natural language to Cypher query

**Request:**
```json
{
  "question": "Show all CVEs affecting Microsoft products"
}
```

**Response (Success):**
```json
{
  "cypher": "MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft' RETURN cve LIMIT 100",
  "results": [...],
  "status": "success",
  "validation": {...},
  "relationship_info": {...}
}
```

### GET /api/schema
Get full schema information

**Response:**
```json
{
  "node_types": ["UcoCVE", "UcoCWE", ...],
  "relationship_types": ["UCOEXHASCPE", ...],
  "node_properties": {...},
  "schema_status": "✅ Loaded"
}
```

---

## Testing

### Full Schema Method
```bash
cd qa-engine/text2cypher/backend
export USE_T2CSS=false
python3 -m testing.test_working_queries
```

### T2CSS Filtered Method
```bash
cd qa-engine/text2cypher/backend
export USE_T2CSS=true
export T2CSS_TOP_K=10
python3 -m testing.run_t2css_tests
```

### Preview Filtered Schema
```bash
python3 -m testing.preview_filtered_schema "Show CVEs affecting Adobe"
```

---

## Configuration

All configuration in `config.py`:

```python
# Schema Extraction
EXCLUDED_LABELS = ["OldLabel"]
EXCLUDED_RELATIONSHIPS = ["OLD_RELATIONSHIP"]
EXCLUDED_PROPERTIES = ["embedding", "embedding_processed"]

# Schema Cache
SCHEMA_CACHE_FILENAME = "schema_cache.txt"

# Prompts
PROMPT_RULES = "..."
PROMPT_GUIDE = "..."
FEW_SHOT_EXAMPLES = "..."

# Semantic Descriptions
CYBERSECURITY_SEMANTICS = {
    "UcoCVE": "Common Vulnerabilities and Exposures...",
    "UCOEXHASCPE": "Vulnerability affects specific products...",
    ...
}

# T2CSS Settings (via environment)
USE_T2CSS=true/false
T2CSS_TOP_K=10
```

---

## Summary

Text2Cypher provides two complementary methods for natural language to Cypher conversion:

1. **Full Schema Method** - Simple, fast, high accuracy for straightforward queries
2. **T2CSS Method** - Token-efficient, scalable for complex queries and large schemas

Both methods share:
- Same LLM interface
- Same validation logic (Cypher Guard)
- Same Neo4j execution
- Same API endpoints

The choice is made at runtime via environment variables, allowing flexible deployment based on use case requirements.
