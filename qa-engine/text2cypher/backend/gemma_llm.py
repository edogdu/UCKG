from __future__ import annotations

from gemma_mps import load_model, generate

class GemmaLLM:
    """Light wrapper so Text2Cypher can call .invoke(prompt)."""

    def __init__(self):
        self.tokenizer, self.model = load_model()

    def invoke(self, prompt: str) -> str:
        """Generate Cypher given a *fully formatted* prompt string.
        We treat the whole prompt as the *question* and pass an empty schema—
        because Text2Cypher already embeds schema into the prompt.
        """
        return generate(self.tokenizer, self.model, question=prompt, schema="")