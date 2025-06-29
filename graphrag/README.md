# UCKG GraphRAG System

A high-performance Retrieval-Augmented Generation system for cybersecurity knowledge using Neo4j GraphRAG and the UCKG (Unified Cybersecurity Knowledge Graph).

## Performance Enhancements

This system includes several performance optimizations:

- **Simplified Cypher Queries**: Streamlined from 6 to 2 OPTIONAL MATCH clauses for faster execution
- **Streamlined Result Processing**: Optimized formatter for improved processing speed
- **Multi-Level Caching**: TTL-based caching system for queries, embeddings, and context
- **Async Handling**: Proper async processing for better concurrency

**Result**: Significantly improved performance over basic implementations

## Quick Start

### Prerequisites
- **Neo4j Database**: Running on `localhost:7687` with UCKG data
- **OpenAI API Key**: For LLM responses
- **Python 3.8+** and **Node.js 16+**

### 1. Backend Setup

```bash
cd graphrag/backend

# Install dependencies (includes caching)
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY='your-api-key-here'
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USERNAME='neo4j'
export NEO4J_PASSWORD='your-password'

# Generate embeddings (first time only)
python scripts/embedding_setup.py

# Test enhancements (optional - validates performance)
python test_optimizations.py

# Start API server
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 2. Frontend Setup

```bash
cd graphrag/frontend

# Install dependencies
npm install

# Start development server
npm start
```

The application will be available at:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000

## System Overview

**Architecture**: `User Query → Vector Search → Graph Traversal → LLM Generation → Response`

**Components**:
- **Vector Store**: Neo4j with CAPEC embeddings
- **Graph Traversal**: Multi-hop relationship exploration using real UCKG relationships
- **LLM**: OpenAI GPT models for answer generation
- **Frontend**: React chat interface

**Performance**: Enhanced performance with optimizations and caching

## Configuration

Key settings in `backend/core/config.py`:

```python
# Database
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"
NEO4J_PASSWORD = "Password"

# OpenAI
OPENAI_MODEL = "text-embedding-3-small"
LLM_MODEL = "gpt-4"

# Vector Index
UCOEX_CAPEC_INDEX_NAME = "ucoex_capec_embeddings"
VECTOR_DIMENSION = 1536
```

## API Endpoints

### Core Endpoints
- **POST /api/rag/query**: Main query endpoint with caching
- **GET /health**: System health and performance statistics
- **GET /api/rag/statistics**: Detailed system statistics

### Cache Management
- **POST /api/rag/clear-cache**: Clear all caches for fresh queries
- **POST /api/rag/warm-cache**: Pre-warm cache with common queries
- **GET /stats**: Comprehensive system metrics

## Deployment

### Docker

```bash
# Build and run backend
cd graphrag/backend
docker build -t uckg-graphrag-backend .
docker run -p 8000:8000 -e OPENAI_API_KEY=your-key uckg-graphrag-backend

# Frontend
cd graphrag/frontend
npm run build
# Serve build/ directory with your web server
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Import errors | Ensure you're in the correct directory |
| No embeddings | Run `python scripts/embedding_setup.py` |
| Connection failed | Check Neo4j is running on `localhost:7687` |
| Slow queries | Verify vector index exists and has data |
| API key errors | Set `OPENAI_API_KEY` environment variable |

## Performance Enhancement Details

### Key Optimizations

1. **Simplified Cypher Queries**
   - Streamlined from 6 to 2 OPTIONAL MATCH clauses
   - Reduced complex multi-hop traversals  
   - Pre-truncated descriptions for faster processing

2. **Streamlined Result Formatter**
   - Optimized processing pipeline
   - Eliminated redundant operations
   - Focused on essential information

3. **Multi-Level Caching System**
   - TTL-based query caching (5 minutes)
   - Embedding cache (30 minutes)
   - Context cache (10 minutes)
   - Cache warming for common queries

4. **Improved Async Handling**
   - Optimized async/await patterns
   - Sync cache checks before async operations
   - Better concurrent query processing

### Performance Testing

Run the comprehensive test suite to validate enhancements:

```bash
cd graphrag/backend
python test_optimizations.py
```

This will test:
- Fresh query performance
- Cached query performance  
- Cache warming functionality
- Concurrent query handling
- Response quality maintenance

## Development

### Running Tests
```bash
cd graphrag/backend
python tests/test_corrected_properties.py
```

### Regenerating Embeddings
```bash
cd graphrag/backend
python scripts/embedding_setup.py
```

### Code Quality Assessment

The codebase follows these principles:
- **Clean imports**: Proper Python package structure
- **Error handling**: Comprehensive try-catch blocks
- **Async processing**: For improved performance
- **Type hints**: Throughout the codebase
- **Logging**: Structured logging for debugging

---

**Performance**: ~0.1-0.5 seconds per query (cached) | **Coverage**: 500+ CAPEC nodes | **Architecture**: Enhanced Neo4j GraphRAG | **Status**: Performance optimized 