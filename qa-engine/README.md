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
│                 │    │   (Port 3001)   │    │   (Port 8000)   │
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

##  Ultimate Setup Method

Follow these 4 simple steps to run the complete UCKG Q&A system:

### Step 1: Build UCKG with Docker
```bash
# From project root directory
docker-compose up --build

# Note: If you don't want embeddings generated, change EMBED_ENV=false in docker-compose.yml
# This starts Neo4j, Ollama, and all infrastructure services
```

### Step 2: Prepare Dependencies

**IMPORTANT**: Due to .gitignore settings, package.json files are not tracked. You need to rename the provided .txt files:

```bash
# In UI directory
mv package.json.txt package.json

# In UI/backend directory  
cd backend
mv package.json.txt package.json
```

```bash
# Setup Python environment for Q&A Engine
cd qa-engine
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Setup Node.js dependencies for UI
cd ../UI
npm install
cd backend && npm install
```

### Step 3: Run Q&A Engine (FastAPI)
```bash
# In a new terminal
cd qa-engine
source venv/bin/activate  # If using venv
python main.py
```

### Step 4: Run UI Frontend & Backend
```bash
# In another terminal, from UI directory
cd UI
npm run dev
```


##  Service URLs

Once running, access these URLs:

| Service | URL | Description |
|---------|-----|-------------|
| **UI Frontend** | http://localhost:3000 | Main application interface |
| **UI Backend** | http://localhost:3001 | Express.js API gateway |
| **Q&A Engine** | http://localhost:8000 | FastAPI service |
| **Neo4j Browser** | http://localhost:7474 | Database interface |
| **Ollama API** | http://localhost:11434 | LLM service |

##  Testing the Setup

### 1. Health Checks
```bash
# Test Q&A Engine service
curl http://localhost:8000/

# Test UI Backend
curl http://localhost:3001/api/graph/labels

# Test MultiRAG endpoint
curl -X POST http://localhost:8000/api/rag \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CWE-89?", "mode": "auto"}'

# Test Text2Cypher endpoint
curl -X POST http://localhost:8000/api/text2cypher \
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
lsof -ti:8000 | xargs kill -9  # Q&A Engine
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