import httpx
import os
from typing import Optional

class OllamaLLM:
    """Light wrapper around Ollama's HTTP API.

    The class now supports configuration through environment variables so that it
    can run both locally (defaulting to localhost) and inside Docker Compose
    where the Ollama service is reachable via the hostname ``ollama``.

    Environment variables used:
    - ``OLLAMA_URL``   – Full base URL of the Ollama server (e.g. http://ollama:11434)
    - ``OLLAMA_MODEL`` – Model name to use when generating responses (e.g. llama3)
    """

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        # Allow overriding through function arguments, otherwise fall back to env
        # vars and finally to safe defaults.
        self.base_url = base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")

    def invoke(self, prompt: str):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.1,  # Low temperature for more consistent outputs
            "top_p": 0.9,       # Nucleus sampling for better quality
            "top_k": 40,        # Limit vocabulary choices
            "repeat_penalty": 1.1,  # Prevent repetition
            "num_predict": 200,  # Limit response length
            "stop": ["\n\n", "```", "Question:", "Schema:"]  # Stop at natural boundaries
        }
        try:
            response = httpx.post(
                f"{self.base_url}/api/generate", json=payload, timeout=60
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # If the model is not found, Ollama returns 404. Try pulling the model once.
            if exc.response.status_code == 404:
                self._pull_model()
                # Retry exactly once after pulling
                response = httpx.post(
                    f"{self.base_url}/api/generate", json=payload, timeout=120
                )
                response.raise_for_status()
            else:
                raise

        result = response.json()
        return result["response"]

    def _pull_model(self):
        """Pull the required model from the Ollama server if it doesn't exist.

        This calls the /api/pull endpoint and streams the response until the pull
        is complete. It is a no-op if the model already exists, so safe to call.
        """
        try:
            r = httpx.post(
                f"{self.base_url}/api/pull",
                json={"name": self.model},
                timeout=None,  # Pull can take a while
                headers={"Accept": "application/json"},
            )
            r.raise_for_status()
            # The API streams status lines separated by newlines; we just wait
            # until completion. No need to parse.
        except Exception as e:
            # Log and continue; the next generate call will surface any errors.
            print(f"[ollama] Warning: failed to pull model {self.model}: {e}") 