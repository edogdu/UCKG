"""
LLM Module for Text2Cypher

This module contains all LLM-related implementations and interfaces.
Supports multiple LLM providers including Ollama and Gemma.
"""

from .ollama_llm import OllamaLLM

# Optional Gemma imports (do not fail if not available)
try:
    from .gemma_llm import GemmaLLM  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    GemmaLLM = None  # type: ignore

try:
    from .gemma_mps import GemmaMPS  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    GemmaMPS = None  # type: ignore

__all__ = ['OllamaLLM']
if GemmaLLM is not None:
    __all__.append('GemmaLLM')
if GemmaMPS is not None:
    __all__.append('GemmaMPS')