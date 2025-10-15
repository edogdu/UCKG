# Shared Module - QA Engine

## 📁 **New Shared Architecture**

The schema extraction module has been moved to a shared location so all components in the QA engine can use it:

```
qa-engine/
├── 📁 shared/                    # Shared utilities for all QA engine components
│   ├── __init__.py
│   ├── schema_extract.py        # Schema extraction utilities
│   ├── schema_cache.txt         # Cached schema file
│   ├── extract_schema_example.py
│   ├── run_schema_extraction.py
│   ├── test_schema_extraction_standalone.py
│   ├── SCHEMA_EXTRACTION_README.md
│   └── SCHEMA_EXTRACTION_STATUS.md
│
├── text2cypher/
│   ├── backend/                  # Backend API (uses shared schema)
│   │   ├── memory/              # Chat memory
│   │   ├── evaluation/          # Model evaluation
│   │   ├── text2cypher.py      # Core logic
│   │   ├── main.py             # FastAPI server
│   │   └── config.py            # Configuration
│   └── frontend/                # React frontend
│
└── multiRAG.py                  # Other QA components (can use shared schema)
```

## 🎯 **Benefits of Shared Schema Extraction**

### **1. Universal Access**
- **All QA engine components** can use schema extraction
- **Consistent schema** across all modules
- **Single source of truth** for schema data
- **Easy to maintain** and update

### **2. Better Organization**
- **Shared utilities** in one place
- **Clear separation** between shared and component-specific code
- **Easier to find** common functionality
- **Better code reuse**

### **3. Scalability**
- **New components** can easily use schema extraction
- **Future modules** can leverage shared utilities
- **Consistent API** across all components
- **Easy to extend** with new shared functionality

## 🚀 **Usage Examples**

### **From Backend**
```python
# text2cypher/backend/text2cypher.py
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'shared'))

# Schema extraction is automatically available
# The Text2Cypher class uses shared schema extraction
```

### **From Other QA Components**
```python
# Any component in qa-engine/
import sys
sys.path.append('shared')

from schema_extract import SchemaExtractor, SchemaFormatter, SchemaValidator

# Use schema extraction in any component
extractor = SchemaExtractor(uri, user, password)
results = extractor.extract_complete_schema()
```

### **Standalone Usage**
```bash
# Run schema extraction from anywhere in qa-engine
cd shared
python3 run_schema_extraction.py
python3 test_schema_extraction_standalone.py
```

## 📋 **Files Moved to Shared**

### **Core Module**
- `schema_extract.py` - Main schema extraction functionality
- `schema_cache.txt` - Cached schema file

### **Utilities**
- `extract_schema_example.py` - Usage examples
- `run_schema_extraction.py` - Simple extraction script
- `test_schema_extraction_standalone.py` - Standalone tests

### **Documentation**
- `SCHEMA_EXTRACTION_README.md` - Comprehensive documentation
- `SCHEMA_EXTRACTION_STATUS.md` - Status and usage guide

## 🔧 **Import Paths Updated**

### **Backend Integration**
- `text2cypher.py` now imports from shared module
- Schema cache path updated to shared directory
- All functionality preserved

### **Shared Module**
- Imports config from backend
- All classes and functions available
- Standalone testing works

## 🧪 **Testing Results**

### **Shared Module** ✅
```bash
cd qa-engine/shared
python3 test_schema_extraction_standalone.py
# ✅ ALL TESTS PASSED
```

### **Backend Integration** ✅
```python
from text2cypher import Text2Cypher
# ✅ Imports successfully with shared schema extraction
```

### **Schema Caching** ✅
- Schema cache file in shared directory
- Backend reads from shared location
- All components can access cached schema

## 🎉 **Ready for Use**

The shared schema extraction module is now available to all QA engine components:

1. **Backend** - Uses shared schema extraction seamlessly
2. **Frontend** - Can access schema via backend API
3. **Future components** - Can easily import and use schema extraction
4. **Standalone usage** - Can be used independently

The schema extraction is now truly shared across the entire QA engine! 🚀