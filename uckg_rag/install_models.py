import os
import logging
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from huggingface_hub import login, snapshot_download

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_hf_token():
    """Get Hugging Face token from user input"""
    token = input("Please enter your Hugging Face token (get it from https://huggingface.co/settings/tokens): ")
    return token.strip()

def is_model_installed(model_name: str, cache_dir: str) -> bool:
    """Check if model is already installed"""
    try:
        # Try to load the model config to check if it exists
        model_path = os.path.join(cache_dir, model_name.replace('/', '_'))
        if os.path.exists(model_path):
            # Check for essential model files
            required_files = ['config.json', 'pytorch_model.bin', 'tokenizer.json']
            if all(os.path.exists(os.path.join(model_path, f)) for f in required_files):
                logger.info(f"Model {model_name} is already installed")
                return True
        return False
    except Exception as e:
        logger.warning(f"Error checking model installation: {e}")
        return False

def install_model(model_name: str, cache_dir: str):
    """Install a model locally"""
    try:
        if is_model_installed(model_name, cache_dir):
            return True
            
        logger.info(f"Installing model: {model_name}")
        
        # Create cache directory if it doesn't exist
        os.makedirs(cache_dir, exist_ok=True)
        
        # Download model and tokenizer
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16,
            device_map="auto",
            cache_dir=cache_dir
        )
        
        tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            cache_dir=cache_dir
        )
        
        logger.info(f"Successfully installed {model_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error installing {model_name}: {e}")
        return False

def main():
    # Get Hugging Face token
    token = get_hf_token()
    login(token)
    
    # Models to install
    models = [
        "microsoft/phi-2",
        "mistralai/Mistral-7B-v0.1",
        "deepseek-ai/deepseek-coder-6.7b-base",
        "meta-llama/Llama-2-7b-chat-hf"
    ]
    
    # Default cache directory
    cache_dir = os.path.expanduser("~/.cache/huggingface/models")
    
    # Install each model
    for model in models:
        install_model(model, cache_dir)
        
    logger.info("Model installation complete. Set these environment variables to use the models:")
    logger.info(f"export HUGGINGFACE_HUB_CACHE={cache_dir}")

if __name__ == "__main__":
    main() 