# UCKG Schema Extraction Module

This module provides comprehensive schema extraction capabilities for the UCKG (Unified Cybersecurity Knowledge Graph) from Neo4j databases. It separates schema extraction functionality from the main Text2Cypher implementation, making it reusable across different components.

## 🏗️ Architecture Overview

### Core Components

1. **`SchemaExtractor`** - Main class for extracting and saving schema
2. **`SchemaFormatter`** - Handles different output formats (text, JSON)
3. **`SchemaValidator`** - Validates extracted schema completeness

### Key Features

- ✅ **Comprehensive Schema Extraction**: Node types, properties, relationships, and connections
- ✅ **Multiple Output Formats**: Text, JSON, or both
- ✅ **Property Type Inference**: Automatic detection of property data types
- ✅ **Schema Validation**: Completeness and consistency checks
- ✅ **Configurable Filtering**: Exclude non-cybersecurity domain elements
- ✅ **Caching Support**: Save and reuse extracted schemas
- ✅ **Command-line Interface**: Easy integration with scripts and automation

## 📁 File Structure

```
qa-engine/text2cypher/backend/
├── schema_extract.py              # Main schema extraction module
├── extract_schema_example.py      # Usage examples
├── SCHEMA_EXTRACTION_README.md    # This documentation
├── config.py                      # Configuration constants
└── schema.txt                     # Generated schema file (output)
```

## 🚀 Quick Start

### Basic Usage

```python
from schema_extract import SchemaExtractor

# Initialize extractor
extractor = SchemaExtractor(
    neo4j_uri="bolt://localhost:7687",
    neo4j_user="neo4j", 
    neo4j_password="your_password"
)

# Extract schema as text file
results = extractor.extract_complete_schema(
    output_file="schema.txt",
    format="text"
)

if results["status"] == "success":
    print(f"Schema saved to: {results['files_created']['text_file']}")
```

### Command Line Usage

```bash
# Extract as text file
python3 schema_extract.py --output uckg_schema.txt --format text

# Extract as JSON file  
python3 schema_extract.py --output uckg_schema.json --format json

# Extract both formats
python3 schema_extract.py --output uckg_schema --format both
```

## 📊 Output Formats

### Text Format (`schema.txt`)

```
# UCKG Schema
# Generated: 2024-01-15 14:30:25

## NODE TYPES

UcoCVE { cve_id: string, severity: string, description: string }
UcoCWE { cwe_id: string, name: string, status: string }
UcoexCAPEC { capec_id: string, name: string, severity: string }
UcoexCPE { cpe_name: string, title: string, vendor: string }

## RELATIONSHIPS

(:UcoCVE) -[:UCOEXHASCPE]-> (:UcoexCPE)
(:UcoCVE) -[:UCOHASWEAKNESS]-> (:UcoCWE)
(:UcoexCAPEC) -[:UCOEXHASRELATEDWEAKNESS]-> (:UcoCWE)
```

### JSON Format (`schema.json`)

```json
{
  "metadata": {
    "extraction_timestamp": "2024-01-15T14:30:25.123456",
    "database_uri": "bolt://localhost:7687",
    "total_node_types": 4,
    "total_relationship_types": 3,
    "total_connections": 6
  },
  "node_types": {
    "UcoCVE": ["cve_id", "severity", "description"],
    "UcoCWE": ["cwe_id", "name", "status"]
  },
  "relationship_types": {
    "UCOEXHASCPE": [],
    "UCOHASWEAKNESS": []
  },
  "connections": {
    "outgoing": {
      "UcoCVE": [["UCOEXHASCPE", "UcoexCPE"]]
    },
    "incoming": {}
  },
  "property_types": {
    "UcoCVE": {
      "cve_id": "string",
      "severity": "string|integer"
    }
  }
}
```

## 🔧 Configuration

The module uses configuration from `config.py`:

```python
# Schema extraction configuration
SCHEMA_EXTRACTION_CONFIG = {
    "default_output_file": "schema.txt",
    "default_format": "text",
    "property_sample_size": 50,
    "max_properties_per_label": 10,
    "include_metadata": True,
    "validate_schema": True,
}

# Excluded elements (non-cybersecurity domain)
EXCLUDED_LABELS = {"Resource", "Entity", "UcoObject", ...}
EXCLUDED_RELATIONSHIPS = {"UCOHASPROPERTY", "UCOHASFACET", ...}
EXCLUDED_PROPERTIES = {"embedding", "embedding_processed"}
```

## 📈 Schema Validation

The module includes comprehensive validation:

- ✅ **Completeness Check**: Ensures all node types and relationships are extracted
- ✅ **Isolation Detection**: Identifies nodes with no connections
- ✅ **Statistics Generation**: Provides extraction metrics
- ✅ **Error Reporting**: Detailed error and warning messages

### Validation Results

```python
{
    "is_valid": True,
    "warnings": ["Isolated nodes found: ['UcoCVE']"],
    "errors": [],
    "statistics": {
        "total_node_types": 4,
        "total_relationship_types": 3,
        "total_connections": 6,
        "isolated_nodes": 1
    }
}
```

## 🔄 Integration with Text2Cypher

The extracted schema can be used by other components:

### 1. **Text2Cypher Integration**

```python
# In text2cypher.py
def get_cybersecurity_schema(self) -> str:
    # Check if cached schema exists
    cache_path = os.path.join(os.path.dirname(__file__), "schema.txt")
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            return f.read()
    
    # Fallback to dynamic extraction
    return self._extract_schema_dynamically()
```

### 2. **Frontend Integration**

```javascript
// Load schema for frontend display
fetch('/api/schema')
  .then(response => response.json())
  .then(data => {
    displaySchemaInfo(data.schema_info);
  });
```

### 3. **API Integration**

```python
# In main.py
@app.get("/api/schema")
def get_schema():
    # Use extracted schema file
    schema_file = "schema.txt"
    if os.path.exists(schema_file):
        with open(schema_file, 'r') as f:
            return {"schema": f.read()}
    return {"error": "Schema not found"}
```

## 🛠️ Advanced Usage

### Custom Configuration

```python
# Override default configuration
extractor = SchemaExtractor(uri, user, password)
extractor.excluded_labels.add("CustomLabel")
extractor.excluded_properties.add("custom_prop")
```

### Batch Processing

```python
# Extract schema for multiple databases
databases = [
    ("bolt://db1:7687", "user1", "pass1"),
    ("bolt://db2:7687", "user2", "pass2")
]

for uri, user, password in databases:
    extractor = SchemaExtractor(uri, user, password)
    results = extractor.extract_complete_schema(f"schema_{uri.split('//')[1]}.txt")
```

### Schema Comparison

```python
# Compare schemas from different databases
import json

with open("schema1.json") as f1, open("schema2.json") as f2:
    schema1 = json.load(f1)
    schema2 = json.load(f2)
    
    # Compare node types
    nodes1 = set(schema1["node_types"].keys())
    nodes2 = set(schema2["node_types"].keys())
    print(f"Common nodes: {nodes1 & nodes2}")
    print(f"Unique to schema1: {nodes1 - nodes2}")
```

## 🐛 Troubleshooting

### Common Issues

1. **Connection Errors**
   ```bash
   # Check Neo4j is running
   docker ps | grep neo4j
   
   # Test connection
   cypher-shell -u neo4j -p password
   ```

2. **Empty Schema**
   ```python
   # Check excluded labels
   print(EXCLUDED_LABELS)
   
   # Verify database has data
   MATCH (n) RETURN count(n) LIMIT 1
   ```

3. **Permission Errors**
   ```bash
   # Check file permissions
   ls -la schema.txt
   
   # Fix permissions
   chmod 644 schema.txt
   ```

### Debug Mode

```python
# Enable debug output
import logging
logging.basicConfig(level=logging.DEBUG)

extractor = SchemaExtractor(uri, user, password)
results = extractor.extract_complete_schema(debug=True)
```

## 📚 API Reference

### SchemaExtractor Class

#### `__init__(neo4j_uri, neo4j_user, neo4j_password)`
Initialize schema extractor with Neo4j connection.

#### `extract_complete_schema(output_file, format)`
Extract complete schema and save to file.

**Parameters:**
- `output_file` (str): Output filename
- `format` (str): Output format ("text", "json", "both")

**Returns:**
- `dict`: Extraction results with status, files created, and validation

### SchemaFormatter Class

#### `format_as_text(node_properties, outgoing_connections, incoming_connections, property_types)`
Format schema data as structured text.

### SchemaValidator Class

#### `validate_schema(schema_data)`
Validate extracted schema for completeness and consistency.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

This module is part of the UCKG project and follows the same license terms.

## 🔗 Related Documentation

- [Text2Cypher V4 Quick Summary](V4_QUICK_SUMMARY.md)
- [Configuration Guide](config.py)
- [Main README](README.md)