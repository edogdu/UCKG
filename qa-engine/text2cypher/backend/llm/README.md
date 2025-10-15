# LLM Module

This module contains all Large Language Model (LLM) implementations and interfaces for Text2Cypher V4.

## 🎯 **Purpose**

The LLM module provides a unified interface for different language model providers, enabling Text2Cypher to work with various LLM backends while maintaining consistent behavior.

## 📁 **Module Structure**

```
llm/
├── __init__.py          # Module exports
├── ollama_llm.py        # Ollama integration
├── gemma_llm.py         # Gemma model support
├── gemma_mps.py         # Apple Silicon optimization
└── README.md            # This file
```

## 🔧 **Available Implementations**

### **1. OllamaLLM (`ollama_llm.py`)**
- **Primary LLM**: Main implementation for production use
- **Ollama Integration**: Works with local Ollama server
- **Model Support**: llama3, codellama, mistral, etc.
- **Configuration**: Environment variable driven
- **Features**: Streaming support, error handling, retry logic

**Usage:**
```python
from llm import OllamaLLM

llm = OllamaLLM(
    base_url="http://localhost:11434",
    model="llama3"
)
response = llm.invoke("Your question here")
```

### **2. GemmaLLM (`gemma_llm.py`)**
- **Alternative LLM**: Google's Gemma model support
- **Research Use**: Useful for model comparison
- **Lightweight**: Minimal implementation for testing
- **Compatibility**: Drop-in replacement for OllamaLLM

**Usage:**
```python
from llm import GemmaLLM

llm = GemmaLLM()
response = llm.invoke("Your question here")
```

### **3. GemmaMPS (`gemma_mps.py`)**
- **Apple Silicon**: Optimized for M1/M2/M3 Macs
- **Metal Performance**: Uses Metal Performance Shaders
- **Local Processing**: No external server required
- **High Performance**: Native Apple Silicon optimization

**Usage:**
```python
from llm import GemmaMPS

llm = GemmaMPS()
response = llm.invoke("Your question here")
```

## ⚙️ **Configuration**

### **Environment Variables**
```bash
# Ollama Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Gemma Configuration (if using Gemma)
GEMMA_MODEL_PATH=/path/to/gemma/model
```

### **Model Selection**
The system automatically selects the best available LLM:
1. **OllamaLLM** - If Ollama server is running
2. **GemmaMPS** - If on Apple Silicon and Gemma is available
3. **GemmaLLM** - Fallback for testing

## 🔄 **Unified Interface**

All LLM implementations follow the same interface:

```python
class LLMInterface:
    def invoke(self, prompt: str) -> str:
        """Process a text prompt and return response"""
        pass
    
    def stream(self, prompt: str) -> Iterator[str]:
        """Stream response tokens (if supported)"""
        pass
```

## 🧪 **Testing**

Test different LLM implementations:

```python
# Test Ollama
from llm import OllamaLLM
llm = OllamaLLM()
result = llm.invoke("Test prompt")

# Test Gemma
from llm import GemmaLLM
llm = GemmaLLM()
result = llm.invoke("Test prompt")
```

## 🚀 **Performance**

### **OllamaLLM**
- **Speed**: Fast with local server
- **Memory**: Moderate (depends on model size)
- **Quality**: High (depends on model)
- **Setup**: Requires Ollama installation

### **GemmaMPS**
- **Speed**: Very fast (native Apple Silicon)
- **Memory**: High (model loaded in memory)
- **Quality**: High (Google's Gemma models)
- **Setup**: Requires Gemma model download

### **GemmaLLM**
- **Speed**: Slow (CPU-only)
- **Memory**: Low
- **Quality**: High
- **Setup**: Minimal (fallback implementation)

## 🔧 **Adding New LLM Providers**

To add a new LLM provider:

1. **Create Implementation**:
```python
# new_llm.py
class NewLLM:
    def __init__(self, **kwargs):
        # Initialize your LLM
        pass
    
    def invoke(self, prompt: str) -> str:
        # Process prompt and return response
        pass
```

2. **Update `__init__.py`**:
```python
from .new_llm import NewLLM
__all__ = ['OllamaLLM', 'GemmaLLM', 'GemmaMPS', 'NewLLM']
```

3. **Add Configuration**:
Update `config.py` with new environment variables and settings.

## 📊 **Model Comparison**

| Model | Speed | Quality | Memory | Setup |
|-------|-------|---------|--------|-------|
| Ollama (llama3) | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| GemmaMPS | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| GemmaLLM | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 🔍 **Debugging**

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Your LLM usage
llm = OllamaLLM()
response = llm.invoke("Debug this prompt")
```

## 📚 **Dependencies**

- **OllamaLLM**: `requests`, `ollama` (optional)
- **GemmaLLM**: `transformers`, `torch`
- **GemmaMPS**: `transformers`, `torch`, `mps` (Apple Silicon)

## 🤝 **Contributing**

When adding new LLM providers:
1. Follow the unified interface
2. Add comprehensive error handling
3. Include performance metrics
4. Update this documentation
5. Add test cases

---

**LLM Module** - Making Text2Cypher work with any language model.