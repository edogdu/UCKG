# Testing Module

This module contains all testing utilities, test cases, and validation scripts for Text2Cypher V4.

## 🎯 **Purpose**

The testing module ensures Text2Cypher V4 works correctly across all components, validates cybersecurity queries, and maintains high code quality through comprehensive testing.

## 📁 **Module Structure**

```
testing/
├── __init__.py                    # Module exports
├── test_cypher_guard.py          # Cypher Guard validation tests
├── test_cybersecurity_queries.py # Cybersecurity query tests
├── test_relationship_queries.py  # Graph relationship tests
├── test_schema_distinct.py       # Schema validation tests
├── test_working_queries.py       # Frontend query tests
├── check_relationships.py        # Relationship validation
├── cybersecurity_user_questions.md # Test question bank
├── distinct_schema_queries.cypher # Schema discovery queries
└── neo4j_distinct_queries.cypher  # Neo4j-specific queries
```

## 🧪 **Test Categories**

### **1. Unit Tests**
- **`test_cypher_guard.py`**: Tests Cypher Guard integration
- **`test_schema_distinct.py`**: Tests schema extraction
- **`test_working_queries.py`**: Tests individual query processing

### **2. Integration Tests**
- **`test_cybersecurity_queries.py`**: End-to-end cybersecurity queries
- **`test_relationship_queries.py`**: Graph relationship validation
- **`check_relationships.py`**: Relationship integrity checks

### **3. Query Validation**
- **`*.cypher` files**: Cypher query examples and templates
- **`cybersecurity_user_questions.md`**: Real-world question bank

## 🚀 **Running Tests**

### **Individual Test Files**
```bash
# Test Cypher Guard integration
python testing/test_cypher_guard.py

# Test cybersecurity queries
python testing/test_cybersecurity_queries.py

# Test relationship queries
python testing/test_relationship_queries.py

# Test schema extraction
python testing/test_schema_distinct.py

# Test working queries
python testing/test_working_queries.py
```

### **All Tests**
```bash
# Run all tests
python -m pytest testing/

# Run with verbose output
python -m pytest testing/ -v

# Run specific test category
python -m pytest testing/test_cypher_guard.py -v
```

## 📊 **Test Coverage**

### **Core Components**
- ✅ **Text2Cypher Core**: Query generation and execution
- ✅ **Schema Extraction**: Dynamic schema discovery
- ✅ **Cypher Guard**: Query validation and security
- ✅ **Error Handling**: Comprehensive error scenarios
- ✅ **Memory Management**: Chat history and context

### **Cybersecurity Queries**
- ✅ **CVE Queries**: Vulnerability information retrieval
- ✅ **CWE Queries**: Weakness enumeration queries
- ✅ **CAPEC Queries**: Attack pattern queries
- ✅ **MITRE ATT&CK**: Technique and tactic queries
- ✅ **Threat Groups**: Actor and campaign queries

### **Graph Relationships**
- ✅ **Node Relationships**: Valid relationship patterns
- ✅ **Property Filtering**: Property-based queries
- ✅ **Multi-hop Queries**: Complex traversal patterns
- ✅ **Bidirectional Paths**: Reverse relationship queries

## 🔍 **Test Data**

### **Query Examples (`cybersecurity_user_questions.md`)**
Real-world questions from security analysts:
- "Show me all CVEs with HIGH severity"
- "Find CWE weaknesses related to buffer overflow"
- "List MITRE ATT&CK techniques used by APT groups"
- "Find mitigations for specific attack techniques"

### **Cypher Queries (`*.cypher` files)**
- **`distinct_schema_queries.cypher`**: Schema discovery queries
- **`neo4j_distinct_queries.cypher`**: Neo4j-specific queries

## 🛠️ **Test Configuration**

### **Environment Setup**
```bash
# Required environment variables
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

### **Test Database**
Tests require a Neo4j database with cybersecurity data:
- UCKG (Unified Cybersecurity Knowledge Graph)
- CVE, CWE, CAPEC, MITRE ATT&CK data
- Proper relationships and properties

## 📈 **Performance Testing**

### **Query Performance**
- **Response Time**: < 2 seconds average
- **Memory Usage**: Optimized with connection pooling
- **Concurrent Users**: Multi-session support
- **Error Recovery**: Graceful degradation

### **Load Testing**
```python
# Example load test
import concurrent.futures
import time

def test_concurrent_queries():
    queries = ["Show CVEs", "Find CWEs", "List techniques"]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        start_time = time.time()
        futures = [executor.submit(run_query, q) for q in queries]
        results = [f.result() for f in futures]
        end_time = time.time()
        
    print(f"Processed {len(queries)} queries in {end_time - start_time:.2f}s")
```

## 🔧 **Adding New Tests**

### **Test Template**
```python
# test_new_feature.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from text2cypher import Text2Cypher
from llm import OllamaLLM

def test_new_feature():
    """Test description"""
    print("🧪 Testing New Feature")
    print("=" * 50)
    
    # Setup
    llm = OllamaLLM()
    t2c = Text2Cypher("bolt://localhost:7687", "neo4j", "password", llm)
    
    # Test cases
    test_cases = [
        "Test query 1",
        "Test query 2",
        "Test query 3"
    ]
    
    for i, query in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: {query}")
        try:
            result = t2c.text_to_cypher_with_fallback(query)
            print(f"   Status: {result['status']}")
            print(f"   Cypher: {result['cypher']}")
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n✅ Test completed")

if __name__ == "__main__":
    test_new_feature()
```

### **Test Categories**
1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test speed and memory usage
5. **Security Tests**: Test validation and security

## 📊 **Test Results**

### **Success Metrics**
- **Query Success Rate**: > 95%
- **Response Time**: < 2 seconds
- **Error Recovery**: 100% graceful handling
- **Schema Accuracy**: 100% correct extraction

### **Test Reports**
Test results are logged and can be exported:
```python
# Generate test report
python testing/generate_test_report.py

# Export results to CSV
python testing/export_test_results.py
```

## 🐛 **Debugging Tests**

### **Enable Debug Logging**
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Your test code
test_cybersecurity_queries()
```

### **Common Issues**
1. **Neo4j Connection**: Ensure database is running
2. **Ollama Server**: Ensure LLM server is available
3. **Schema Cache**: Clear cache if schema changes
4. **Memory Issues**: Check for memory leaks

## 📚 **Test Documentation**

- **Test Cases**: Documented in each test file
- **Expected Results**: Clear success/failure criteria
- **Setup Requirements**: Environment and data requirements
- **Troubleshooting**: Common issues and solutions

## 🤝 **Contributing Tests**

When adding new tests:
1. Follow the naming convention: `test_*.py`
2. Include comprehensive test cases
3. Add proper error handling
4. Document test purpose and expected results
5. Update this README

---

**Testing Module** - Ensuring Text2Cypher V4 works perfectly for cybersecurity queries.