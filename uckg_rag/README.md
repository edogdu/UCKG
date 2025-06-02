# UCKG RAG Service

## Multi-Model Support

The RAG service supports multiple language models for generating responses. By default, it uses Microsoft's Phi-2 model, which is lightweight and efficient. Additional models can be used by installing them locally.

### Available Models

1. **Microsoft Phi-2** (Default)
   - Model ID: `microsoft/phi-2`
   - Size: ~2.7B parameters
   - Included in Docker container

2. **Mistral-7B**
   - Model ID: `mistralai/Mistral-7B-v0.1`
   - Size: ~7B parameters
   - Requires local installation

3. **Llama-2-7B**
   - Model ID: `meta-llama/Llama-2-7b-chat-hf`
   - Size: ~7B parameters
   - Requires local installation

### Using Different Models

#### Docker Usage (Default Model Only)
```bash
$ docker compose -f docker-compose.yml -f docker-compose-rag.yml up --build
```

#### Local Installation (Additional Models)
1. Install the required models locally:
```bash
# Create a models directory
mkdir -p ~/.cache/huggingface/models

# Download models (example for Mistral-7B)
python -c "from transformers import AutoModelForCausalLM, AutoTokenizer; AutoModelForCausalLM.from_pretrained('mistralai/Mistral-7B-v0.1', cache_dir='~/.cache/huggingface/models')"
```

2. Run the service with local models:
```bash
# Set environment variables
export GEN_LLM_MODEL=mistralai/Mistral-7B-v0.1  # or any other model
export HUGGINGFACE_HUB_CACHE=~/.cache/huggingface/models

# Run the service
python -m uckg_rag.rag_pipeline
```

### API Endpoints

#### List Available Models
```bash
GET /models
```
Response:
```json
{
    "available_models": {
        "microsoft/phi-2": {
            "name": "Phi-2",
            "description": "Microsoft's Phi-2 model, 2.7B parameters",
            "max_length": 2048,
            "loaded": true
        },
        ...
    },
    "default_model": "microsoft/phi-2"
}
```

#### Query with Specific Model
```bash
POST /query
{
    "query": "Your question here",
    "model_name": "mistralai/Mistral-7B-v0.1",
    "graph_context": true
}
```

#### Evaluate Models
```bash
POST /evaluate
{
    "test_cases": [
        {
            "question": "What is CVE-2023-1234?",
            "expected_answer": "CVE-2023-1234 is a critical vulnerability...",
            "context": "Additional context..."
        }
    ],
    "models": ["microsoft/phi-2", "mistralai/Mistral-7B-v0.1"]
}
```

### Evaluation Results

Evaluation results are stored in the `evaluation_results` directory:
- Individual model results: `{model_name}_{timestamp}.json`
- Comparison results: `comparison_{timestamp}.json`
- Human-readable report: `evaluation_report.txt`

## Notes

- The Docker container only includes the default Phi-2 model to keep the image size manageable
- Larger models should be installed locally for better performance
- Model evaluation requires sufficient system resources (RAM, GPU)
- Evaluation results are saved in the `evaluation_results` directory 