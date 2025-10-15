# Text2Cypher V4: Cybersecurity Knowledge Graph Query Assistant

## 🎯 **Project Overview**

Text2Cypher V4 is an enterprise-grade natural language to Cypher query conversion system designed specifically for cybersecurity knowledge graphs. It enables security analysts, researchers, and threat hunters to query complex cybersecurity data using natural language instead of learning Cypher syntax.

## 🏗️ **Architecture**

### **Modular Framework Design**
```
qa-engine/
├── shared/                    # Reusable utilities
│   ├── schema_extract.py     # Schema extraction classes
│   └── schema_cache.txt      # Performance optimization
├── text2cypher/
│   ├── backend/              # FastAPI backend
│   │   ├── llm/             # LLM implementations
│   │   │   ├── ollama_llm.py    # Ollama integration
│   │   │   ├── gemma_llm.py     # Gemma integration
│   │   │   └── gemma_mps.py     # Gemma MPS support
│   │   ├── memory/          # Chat memory management
│   │   ├── evaluation/      # Model evaluation tools
│   │   ├── testing/         # Test suites and validation
│   │   │   ├── test_*.py        # Unit and integration tests
│   │   │   ├── *.cypher         # Cypher query examples
│   │   │   └── check_*.py       # Validation scripts
│   │   └── config.py        # Centralized configuration
│   └── frontend/            # React frontend demo
```

### **Core Components**

#### **1. Schema Extraction Engine (`shared/`)**
- **SchemaExtractor**: Extracts complete graph schema from Neo4j
- **SchemaFormatter**: Formats schema for LLM consumption
- **SchemaValidator**: Validates schema integrity
- **Caching**: Performance optimization with `schema_cache.txt`

#### **2. Text2Cypher Core (`backend/`)**
- **Natural Language Processing**: Converts questions to Cypher queries
- **Error Handling**: Comprehensive validation and fallback mechanisms
- **Cypher Guard Integration**: Enterprise-grade query validation
- **Smart Suggestions**: Context-aware query alternatives

#### **3. Memory Management (`backend/memory/`)**
- **Ring Buffer**: Efficient chat history management
- **Session Management**: Multi-user conversation support
- **Context Preservation**: Maintains conversation context

#### **4. LLM Module (`backend/llm/`)**
- **OllamaLLM**: Primary LLM interface for Ollama
- **GemmaLLM**: Alternative LLM implementation
- **GemmaMPS**: Metal Performance Shaders support for Apple Silicon
- **Unified Interface**: Consistent API across all LLM providers

#### **5. Testing Module (`backend/testing/`)**
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Cypher Query Tests**: Query validation and performance
- **Relationship Tests**: Graph relationship validation
- **Cypher Guard Tests**: Security validation testing

#### **6. Model Evaluation (`backend/evaluation/`)**
- **Performance Testing**: Compare different LLM models
- **Dataset Generation**: Create evaluation datasets
- **Metrics Collection**: Track accuracy and performance

## 🚀 **Key Features**

### **V4 Core Capabilities**
1. **Enhanced Error Handling** - Comprehensive validation and fallback responses
2. **Intelligent Error Handling** - LLM-generated helpful responses for all scenarios
3. **Smart Suggestions** - Context-aware query alternatives based on user intent
4. **Enterprise-Grade Validation** - Cypher Guard integration with fallback system

### **Cybersecurity Focus**
- **Domain-Specific Schema**: Optimized for cybersecurity knowledge graphs
- **Threat Intelligence**: Support for CVEs, CWEs, CAPEC, MITRE ATT&CK
- **Security Validation**: Read-only query enforcement
- **Performance Optimization**: Cached schema for fast responses

### **Technical Features**
- **Dynamic Schema Extraction**: Real-time property discovery from database
- **Modular Architecture**: Clean separation of concerns
- **Configuration Management**: Centralized constants and prompts
- **API-First Design**: RESTful endpoints for integration

## 📊 **Supported Data Types**

### **Node Types**
- **UcoCVE**: Common Vulnerabilities and Exposures
- **UcoCWE**: Common Weakness Enumeration
- **UcoexCAPEC**: Common Attack Pattern Enumeration and Classification
- **UcoexMITREATTACK**: MITRE ATT&CK techniques
- **UcoexGROUPS**: Threat actor groups
- **UcoexSOFTWARE**: Malware and tools
- **UcoexCPE**: Common Platform Enumeration

### **Relationship Types**
- **UCOEXHASCPE**: CVE has CPE entries
- **UCOHASWEAKNESS**: Exploit target has weakness
- **UCOEXGROUPUSESTECHNIQUE**: Group uses attack technique
- **UCOEXSOFTWAREUSESTECHNIQUE**: Software uses technique
- **UCOEXMITIGATES**: Mitigation addresses technique

## 🛠️ **Installation & Setup**

### **Prerequisites**
- Python 3.8+
- Neo4j database
- Ollama (for LLM)
- Node.js (for frontend)

### **Backend Setup**
```bash
cd qa-engine/text2cypher/backend
pip install -r requirements.txt
python main.py
```

### **Frontend Setup**
```bash
cd qa-engine/text2cypher/frontend
npm install
npm start
```

### **Testing Setup**
```bash
# Run all tests
python -m pytest testing/

# Run specific test categories
python testing/test_cybersecurity_queries.py
python testing/test_cypher_guard.py
python testing/test_working_queries.py
```

### **Environment Variables**
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

## 📝 **Usage Examples**

### **Basic Queries**
```
"Show me all CVEs with HIGH severity"
"Find CWE weaknesses related to buffer overflow"
"List all MITRE ATT&CK techniques used by APT groups"
```

### **Complex Queries**
```
"Find CVEs affecting Microsoft products with exploitability score > 8"
"Show attack techniques used by groups in enterprise-attack domain"
"Find mitigations for techniques used by specific threat groups"
```

### **API Endpoints**
- `POST /api/text2cypher` - Convert natural language to Cypher
- `GET /api/schema` - Get graph schema information
- `GET /api/validation` - Get validation system status
- `POST /api/chat_history` - Chat with memory context

## 🔧 **Configuration**

### **Schema Filtering**
The system automatically filters out ontology metadata:
- Excluded labels: `rdfs:Class`, `owl:Class`, etc.
- Excluded relationships: `rdfs:subClassOf`, `owl:equivalentClass`, etc.
- Excluded properties: `rdf:type`, `rdfs:label`, etc.

### **Query Limits**
- Default limit: 1000 results per query
- Configurable via `DEFAULT_QUERY_LIMIT` in `config.py`

### **LLM Configuration**
- Supports Ollama and Gemma models
- Configurable via environment variables
- Fallback mechanisms for reliability

## 📈 **Performance**

### **Optimizations**
- **Schema Caching**: Reduces database queries
- **Connection Pooling**: Efficient Neo4j connections
- **Query Validation**: Prevents expensive operations
- **Response Pagination**: Handles large result sets

### **Metrics**
- Query response time: < 2 seconds average
- Schema extraction: < 5 seconds (cached after first run)
- Memory usage: Optimized with ring buffer
- Concurrent users: Supports multiple sessions

## 🔒 **Security**

### **Query Validation**
- **Cypher Guard**: Industry-standard validation
- **Read-only Enforcement**: Prevents data modification
- **Schema Validation**: Ensures queries match database structure
- **Input Sanitization**: Prevents injection attacks

### **Error Handling**
- **Graceful Degradation**: System continues on errors
- **User-friendly Messages**: Clear error explanations
- **Fallback Mechanisms**: Alternative approaches when primary fails
- **Logging**: Comprehensive error tracking

## 🚀 **Future Roadmap**

### **V5 Planned Features**
1. **Agentic Workflows** - Multi-agent collaboration
2. **Vector Store Integration** - Semantic similarity search
3. **Advanced Visualization** - Interactive graph exploration
4. **Multi-language Support** - Support for different languages

### **Integration Opportunities**
- **SIEM Integration** - Connect with security tools
- **Threat Intelligence** - Real-time threat data
- **Automated Analysis** - Scheduled query execution
- **Custom Models** - Domain-specific fine-tuning

## 📚 **Documentation**

- **Weekly Report**: `WEEKLY_REPORT_V4_ACHIEVEMENTS.md`
- **API Documentation**: Available at `/docs` when running
- **Schema Guide**: `NEO4J_DISTINCT_LABELS_GUIDE.md`
- **Cybersecurity Guide**: `CYBERSECURITY_TEXT2CYPHER_GUIDE.md`

## 🤝 **Contributing**

The modular architecture makes it easy to contribute:
1. **New Features**: Add to appropriate module
2. **Bug Fixes**: Update specific components
3. **Documentation**: Improve guides and examples
4. **Testing**: Add to evaluation module

## 📄 **License**

This project is part of the UCKG (Unified Cybersecurity Knowledge Graph) initiative, designed to advance cybersecurity research and threat intelligence capabilities.

---

**Text2Cypher V4** - Making cybersecurity knowledge graphs accessible through natural language queries.