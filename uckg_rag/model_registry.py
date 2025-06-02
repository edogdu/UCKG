import os
import logging
from pathlib import Path
from typing import Dict, Optional
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import time
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

class ModelRegistry:
    def __init__(self):
        self.models: Dict[str, Dict] = {}
        self.installation_cache: Dict[str, bool] = {}
        self.default_model = "microsoft/phi-2"
        self.available_models = {
            "microsoft/phi-2": {
                "name": "Phi-2",
                "description": "Microsoft's Phi-2 model, 2.7B parameters",
                "max_length": 2048
            },
            "mistralai/Mistral-7B-v0.1": {
                "name": "Mistral-7B",
                "description": "Mistral AI's 7B parameter model",
                "max_length": 2048
            },
            "deepseek-ai/deepseek-coder-6.7b-base": {
                "name": "Deepseek Coder",
                "description": "Deepseek's 6.7B parameter model for code",
                "max_length": 2048
            },
            "meta-llama/Llama-2-7b-chat-hf": {
                "name": "Llama-2-7B",
                "description": "Meta's Llama 2 7B parameter model",
                "max_length": 2048
            }
        }
        self.base_cache_dir = os.getenv("HUGGINGFACE_HUB_CACHE", "/root/.cache/huggingface")
        os.makedirs(self.base_cache_dir, exist_ok=True)
        self._current_model = None

    @property
    def current_model(self):
        """Get currently active model"""
        return self._current_model

    def is_model_installed(self, model_name: str) -> bool:
        if model_name in self.installation_cache:
            return self.installation_cache[model_name]

        model_dir = os.path.join(self.base_cache_dir, "models", f"models--{model_name.replace('/', '--')}")
        is_installed = os.path.exists(model_dir)
        logger.info(f"{model_name} installed: {is_installed}")
        self.installation_cache[model_name] = is_installed
        return is_installed

    def is_model_loaded(self, model_name: str) -> bool:
        model_info = self.models.get(model_name)
        return bool(model_info and "model" in model_info and hasattr(model_info["model"], "device"))

    def unload_model(self, model_name: str) -> bool:
        try:
            if model_name in self.models:
                del self.models[model_name]
                import gc
                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                logger.info(f"Unloaded {model_name}")
            return True
        except Exception as e:
            logger.error(f"Unload error: {e}")
            return False

    def unload_all_models(self):
        for name in list(self.models.keys()):
            self.unload_model(name)

    def load_model(self, model_name: str, force_reload: bool = False) -> Optional[Dict]:
        """Load model with smart caching - only reload if necessary"""
        #logger.info(f"Current model: {self._current_model}")
        #logger.info(f"Models Loaded: {self.models}")
        if not force_reload and model_name in self.models:
            logger.info(f"Returning cached model: {model_name}")
            return self.models.get(model_name)

        if model_name not in self.available_models:
            logger.error(f"{model_name} not available in registry")
            return None

        if not self.is_model_installed(model_name):
            logger.warning(f"{model_name} not installed. Run install_models.py first.")
            return None

        # Only unload if we're switching models
        if self._current_model and self._current_model != model_name:
            self.unload_model(self._current_model)

        if model_name not in self.models:
            logger.info(f"Loading model: {model_name}")
            start_time = time.time()

            try:
                resolved_path = os.path.join(self.base_cache_dir, "models", f"models--{model_name.replace('/', '--')}", "snapshots")
                snapshot_dirs = [
                    directory for directory in os.listdir(resolved_path)
                    if os.path.isdir(os.path.join(resolved_path, directory))
                ]
                resolved_path = os.path.join(resolved_path, snapshot_dirs[0])
                tokenizer = AutoTokenizer.from_pretrained(resolved_path)
                logger.info(f"###############################################################")
                logger.info(f"Attempting to load model {model_name} from {resolved_path}")
                logger.info(f"###############################################################")
                model = AutoModelForCausalLM.from_pretrained(
                    resolved_path,
                    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                    device_map="cuda" if torch.cuda.is_available() else "auto",
                    trust_remote_code=True,
                    low_cpu_mem_usage=True,

                )

                model.eval()
                if tokenizer.pad_token is None:
                    tokenizer.pad_token = tokenizer.eos_token
                    model.config.pad_token_id = model.config.eos_token_id

                load_time = time.time() - start_time
                logger.info(f"{model_name} loaded in {load_time:.2f}s on {model.device}")

                self.models[model_name] = {
                    "model": model,
                    "model_name": model_name,
                    "tokenizer": tokenizer,
                    "config": self.available_models[model_name],
                    "load_time": load_time,
                    "last_accessed": time.time()
                }

            except Exception as e:
                logger.error(f"Model loading error for {model_name}: {e}")
                return None

        self._current_model = model_name
        return self.models[model_name]

    def get_model(self, model_name: Optional[str] = None) -> Optional[Dict]:
        """Get model, loading only if necessary"""
        model_name = model_name or self.default_model
        return self.load_model(model_name, force_reload=False)

    def list_available_models(self) -> Dict:
        return {
            name: {
                **config,
                "loaded": self.is_model_loaded(name),
                "installed": self.is_model_installed(name)
            } for name, config in self.available_models.items()
        }