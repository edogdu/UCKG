# Backend Directory Structure

## 📁 **New Modular Organization**

The backend has been reorganized into a cleaner, more modular structure:

```
qa-engine/text2cypher/backend/
├── 📁 memory/                    # Chat memory and conversation management
│   ├── __init__.py
│   ├── chat_memory.py           # ChatMemory class and session management
│   └── chat_types.py            # ChatMessage and Role data models
│
├── 📁 evaluation/               # Model evaluation and testing
│   ├── __init__.py
│   ├── evaluate_models.py       # Model evaluation scripts
│   └── generate_eval_dataset.py # Dataset generation utilities
│
├── 📁 core/                     # Core Text2Cypher functionality (main files)
│   ├── text2cypher.py          # Main Text2Cypher class
│   ├── main.py                 # FastAPI server
│   ├── config.py               # Configuration constants
│   ├── cypher_validation.py    # Cypher Guard validation
│   └── schema_extract.py       # Schema extraction utilities
│
└── 📁 tests/                    # Test files and utilities
    ├── test_*.py               # Various test files
    └── *.cypher                # Cypher test queries
```

## 🔄 **Migration Summary**

### **Moved Files:**
- `chat_memory.py` → `memory/chat_memory.py`
- `chat_types.py` → `memory/chat_types.py`
- `evaluate_models.py` → `evaluation/evaluate_models.py`
- `generate_eval_dataset.py` → `evaluation/generate_eval_dataset.py`

### **Updated Imports:**
- `main.py` now imports from `memory` module
- `evaluation/` files updated to import from parent directory

## 🎯 **Benefits of New Structure**

### **1. Separation of Concerns**
- **Memory**: Chat history and conversation management
- **Evaluation**: Testing, benchmarking, and dataset generation
- **Core**: Main Text2Cypher functionality
- **Tests**: All testing utilities in one place

### **2. Better Organization**
- Related functionality grouped together
- Easier to find specific components
- Cleaner root directory
- Clear module boundaries

### **3. Improved Maintainability**
- Each module has a specific purpose
- Easier to add new features
- Better code organization
- Clearer dependencies

## 🚀 **Usage Examples**

### **Memory Management**
```python
from memory import get_memory, ChatMessage, Role

# Get chat memory for a session
memory = get_memory("session_123")

# Add a new message
message = ChatMessage(role=Role.USER, content="Hello!")
memory.add(message)
```

### **Evaluation**
```python
from evaluation import evaluate_models, generate_eval_dataset

# Generate evaluation dataset
generate_eval_dataset.main()

# Run model evaluation
evaluate_models.main()
```

### **Core Functionality**
```python
from text2cypher import Text2Cypher
from config import EXCLUDED_LABELS
from schema_extract import SchemaExtractor

# Use core Text2Cypher functionality
t2c = Text2Cypher(uri, user, password, llm)
```

## 📋 **Next Steps**

1. **Move remaining files** to appropriate directories
2. **Update all imports** across the codebase
3. **Create comprehensive tests** for each module
4. **Add module-specific documentation**
5. **Consider further modularization** if needed

## 🔧 **Import Updates Required**

If you have any files that import from the old locations, update them:

```python
# Old imports
from chat_memory import get_memory
from chat_types import ChatMessage, Role
from evaluate_models import evaluate_model

# New imports
from memory import get_memory, ChatMessage, Role
from evaluation import evaluate_model
```

The new structure provides better organization while maintaining all existing functionality! 🎉