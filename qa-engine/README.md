# UCKG Q&A Engine Setup Guide

This guide covers setting up and running the complete UCKG Q&A system including:
- **UI Frontend** (React) - Interactive chat and graph visualization
- **UI Backend** (Express.js) - API gateway and middleware
- **Q&A Engine** (FastAPI) - Unified service for both GraphRAG and Text2Cypher

##  System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React UI      │    │  Express.js     │    │   FastAPI       │
│   (Port 3000)   │◄──►│   Backend       │◄──►│   Q&A Engine    │
│                 │    │   (Port 3001)   │    │   (Port 8001)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │      Neo4j Database     │
                    │      (Port 7687)       │
                    └─────────────────────────┘
                                 ▲
                    ┌─────────────────────────┐
                    │    Ollama LLM Server    │
                    │     (Port 11434)       │
                    └─────────────────────────┘
```

##  File Structure

```
qa-engine/
├── main.py                          # FastAPI server - unified entry point
├── multiRAG.py                      # Alternative multi-mode RAG system
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
│
├── graphrag/                        # GraphRAG Pipeline
│   ├── __init__.py                 # Clean exports
│   ├── pipeline.py                 # Main orchestrator - 4-stage pipeline
│   ├── query_processor.py          # Stage 0: Hop selection, relationship prediction
│   ├── retrieval.py                # Stage 1-2: Semantic search + graph traversal
│   ├── reranking.py                # Stage 3: Neighbor-aware scoring
│   ├── generation.py               # Stage 4: Context formatting + LLM generation
│   ├── utils.py                    # Configuration, enums, helper functions
│   └── README.md                   # GraphRAG documentation
│
├── text2cypher/                     # Text-to-Cypher System
│   ├── main.py                     # T2C FastAPI server
│   ├── config.py                   # Configuration and semantics
│   ├── requirements.txt            # T2C-specific dependencies
│   ├── README.md                   # T2C documentation
│   │
│   ├── core/                       # Core T2C pipelines
│   │   ├── text2cypher.py         # Full schema pipeline
│   │   ├── t2css_pipeline.py      # Semantic schema filtering (T2CSS)
│   │   ├── t2css_integration.py   # Integration wrapper
│   │   └── dynamic_rules.py       # Dynamic rule generation
│   │
│   ├── llm/                        # LLM integrations
│   │   ├── ollama_llm.py          # Ollama interface
│   │   └── gemma_llm.py           # Gemma model support
│   │
│   ├── validation/                 # Cypher query validation
│   │   ├── noexec_validator.py    # Pre-execution validation
│   │   └── utils/                 # Validation utilities
│   │
│   ├── memory/                     # Conversation memory
│   │   ├── chat_memory.py         # Chat history storage
│   │   └── chat_types.py          # Type definitions
│   │
│   ├── evaluation/                 # Evaluation framework
│   │   ├── evaluate_models.py     # Multi-metric evaluation
│   │   └── results_analysis.ipynb # Results visualization
│   │
│   ├── dataset/                    # Evaluation datasets
│   │   └── technical_dataset_COMPLETION.csv  # 388 questions
│   │
│   └── configt2c/                  # T2C configuration
│       ├── fewshot_candidates.json
│       └── semantic_schema_uckg.json
│
├── dataset/                         # Dataset Generation
│   ├── create_evaluation_dataset.py # Generate eval datasets from pipeline
│   ├── evaluate_coverage.py        # Coverage analysis
│   ├── evaluation_dataset.json     # Generated evaluation data
│   └── README.md                   # Dataset documentation
│
├── evaluation/                      # Evaluation Framework
│   ├── multi-eval.py               # Multi-metric evaluation script
│   ├── metric_chart.ipynb          # Visualization notebook
│   ├── requirements.txt            # Evaluation dependencies
│   ├── new_result.csv              # Evaluation results
│   └── README.md                   # Evaluation documentation
│
└── shared/                          # Shared Utilities
    ├── schema_extract.py           # Neo4j schema extraction
    ├── run_schema_extraction.py    # Schema extraction runner
    ├── schema_cache.txt            # Cached schema (used by T2C)
    ├── README.md                   # Shared module documentation
    └── question_set/               # Question datasets
        ├── questions_0hop.json     # 0-hop questions (9)
        ├── questions_1hop.json     # 1-hop questions (25)
        └── questions_2hop.json     # 2-hop questions (25)
```

### Component Overview

| Component | Purpose | Key Files |
|-----------|---------|-----------|
| **main.py** | FastAPI server exposing GraphRAG and Text2Cypher APIs | `main.py` |
| **graphrag/** | Semantic search + graph traversal + LLM generation | `pipeline.py`, `retrieval.py` |
| **text2cypher/** | Natural language → Cypher query generation | `core/text2cypher.py`, `core/t2css_pipeline.py` |
| **dataset/** | Evaluation dataset generation from GraphRAG pipeline | `create_evaluation_dataset.py` |
| **evaluation/** | Multi-metric evaluation (ROUGE, BLEU, BERTScore) | `multi-eval.py`, `metric_chart.ipynb` |
| **shared/** | Schema extraction and question datasets | `schema_extract.py`, `question_set/` |

##  Prerequisites

### Required Software
- **Node.js** (v16+) and npm
- **Python 3.8+** with pip
- **Neo4j** (v5.x) - Running locally or via Docker
- **Ollama** - For LLM inference

### System Requirements
- **RAM**: 16GB minimum (32GB recommended)
- **Storage**: 5GB free space
- **Network**: Internet connection for model downloads

### Configuration (`.env`)

- **Location**: `qa-engine/.env`
- **Neo4j**:
  - `NEO4J_URI` – set to `bolt://localhost:7687` for local Docker Neo4j, or to your remote Neo4j bolt URI.
  - `NEO4J_USER`, `NEO4J_PASSWORD` – credentials for the Neo4j instance.
   - `INDEX_NAME` – name of the Neo4j vector index used by GraphRAG.
- **Ollama**:
  - `OLLAMA_URL` – `http://localhost:11434` for local Docker Ollama, or your remote Ollama server URL.
  - `OLLAMA_MODEL`, `OLLAMA_EMBEDDING_MODEL` – LLM and embedding model names used by GraphRAG / Text2Cypher.
  - `LLM_TEMPERATURE` – decoding temperature for generation (lower = more deterministic).
- **GraphRAG Pipeline**:
  - `GRAPHRAG_INITIAL_TOP_K_MULTIPLIER`, `GRAPHRAG_FINAL_TOP_K` – controls how many candidate nodes are retrieved and kept after reranking.
  - `GRAPHRAG_MAX_NEIGHBORS_PER_NODE` – maximum neighbors to expand per node during graph traversal.
  - `GRAPHRAG_RERANK_WEIGHT_PRIMARY`, `GRAPHRAG_RERANK_WEIGHT_NEIGHBOR` – weighting between primary node score and neighbor-based score.
  - `GRAPHRAG_TOP_NEIGHBOR_COUNT_FOR_SCORING` – how many top neighbors are considered when computing neighbor scores.
  - `GRAPHRAG_ENABLE_SECOND_HOP`, `GRAPHRAG_MAX_SECOND_HOP_PER_FIRST` – toggle and limit second-hop expansion in the graph.

##  Ultimate Setup Method

Choose your OS and follow these 4 steps to run the complete UCKG Q&A system.

> **Note**  
> Step 1 (`docker-compose up --build`) is primarily for starting the **Neo4j graph database locally** via Docker.  
> If your **Neo4j graph data server is already running on another machine / server**, you can **skip Step 1 (Docker)** in your OS section and only follow Steps 2–4, making sure your configuration points to that external Neo4j instance.

<details>
<summary><b>macOS / Linux</b></summary>

#### Step 1: Build UCKG with Docker
```bash
# From project root directory
docker-compose up --build

# Note: If you don't want embeddings generated, change EMBED_ENV=false in docker-compose.yml
# This starts Neo4j, Ollama, and all infrastructure services
```

#### Step 2: Prepare Dependencies

**IMPORTANT**: Due to .gitignore settings, `package.json` files are not tracked. You need to rename the provided `.txt` files:

```bash
# In UI directory
cd UI
mv package.json.txt package.json

# In UI/backend directory
cd backend
mv package.json.txt package.json
```

**Setup Python environment for Q&A Engine:**

```bash
cd ../../qa-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Setup Node.js dependencies for UI:**

```bash
cd ../UI
npm install
cd backend && npm install
```

#### Step 3: Run Q&A Engine (FastAPI)
```bash
cd ../../qa-engine
source venv/bin/activate
python main.py
```

#### Step 4: Run UI Frontend & Backend
```bash
# In a new terminal, from UI directory
cd UI
npm run dev
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

#### Step 1: Build UCKG with Docker
```powershell
# From project root directory
docker-compose up --build

# Note: If you don't want embeddings generated, change EMBED_ENV=false in docker-compose.yml
# This starts Neo4j, Ollama, and all infrastructure services
```

#### Step 2: Prepare Dependencies

**IMPORTANT**: Due to .gitignore settings, `package.json` files are not tracked. You need to rename the provided `.txt` files:

```powershell
# In UI directory
cd UI
Rename-Item package.json.txt package.json

# In UI/backend directory
cd backend
Rename-Item package.json.txt package.json
```

**Setup Python environment for Q&A Engine:**

```powershell
cd ..\..\qa-engine
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

**Setup Node.js dependencies for UI:**

```powershell
cd ..\UI
npm install
cd backend
npm install
```

#### Step 3: Run Q&A Engine (FastAPI)
```powershell
cd ..\qa-engine
.\venv\Scripts\activate
python .\main.py
```

#### Step 4: Run UI Frontend & Backend
```powershell
cd ..\UI
npm run dev
```

</details>

<details>
<summary><b>Windows (Git Bash)</b></summary>

#### Step 1: Build UCKG with Docker
```bash
# From project root directory
docker-compose up --build

# Note: If you don't want embeddings generated, change EMBED_ENV=false in docker-compose.yml
# This starts Neo4j, Ollama, and all infrastructure services
```

#### Step 2: Prepare Dependencies

**IMPORTANT**: Due to .gitignore settings, `package.json` files are not tracked. You need to rename the provided `.txt` files:

```bash
# In UI directory
cd UI
mv package.json.txt package.json

# In UI/backend directory
cd backend
mv package.json.txt package.json
```

**Setup Python environment for Q&A Engine:**

```bash
cd ../../qa-engine
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
```

**Setup Node.js dependencies for UI:**

```bash
cd ../UI
npm install
cd backend && npm install
```

#### Step 3: Run Q&A Engine (FastAPI)
```bash
cd ../../qa-engine
source venv/Scripts/activate
python main.py
```

#### Step 4: Run UI Frontend & Backend
```bash
# In a new terminal, from UI directory
cd UI
npm run dev
```

</details>


##  Service URLs

Once running, access these URLs:

| Service | URL | Description |
|---------|-----|-------------|
| **UI Frontend** | http://localhost:3000 | Main application interface |
| **UI Backend** | http://localhost:3001 | Express.js API gateway |
| **Q&A Engine** | http://localhost:8001 | FastAPI service |
| **Neo4j Browser** | http://localhost:7474 | Database interface |
| **Ollama API** | http://localhost:11434 | LLM service |

##  Testing the Setup

### 1. Health Checks
```bash
# Test Q&A Engine service
curl http://localhost:8001/

# Test UI Backend
curl http://localhost:3001/api/graph/labels

# Test MultiRAG endpoint
curl -X POST http://localhost:8001/api/rag \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CWE-89?", "mode": "auto"}'

# Test Text2Cypher endpoint
curl -X POST http://localhost:8001/api/text2cypher \
  -H "Content-Type: application/json" \
  -d '{"question": "Find CVEs with HIGH severity"}'
```

### 2. Sample Queries

**RAG Mode:**
- "What is CWE-89?"
- "Show me SQL injection vulnerabilities"
- "Find high severity CVEs"

**Text2Cypher Mode:**
- "Find CVEs with HIGH severity"
- "Show CWE weaknesses related to authentication"
- "List CAPEC patterns for CWE-79"

##  Troubleshooting

### Common Issues

**Port Already in Use:**
```bash
# Find and kill processes using ports
lsof -ti:3000 | xargs kill -9  # Frontend
lsof -ti:3001 | xargs kill -9  # Backend
lsof -ti:8001 | xargs kill -9  # Q&A Engine
```

**Neo4j Connection Failed:**
```bash
# Check Neo4j status
neo4j status

# Restart Neo4j
neo4j restart

# Check Docker Neo4j logs
docker logs neo4j
```

**Ollama Model Not Found:**
```bash
# List available models
ollama list

# Pull missing models
ollama pull llama3
ollama pull nomic-embed-text
```