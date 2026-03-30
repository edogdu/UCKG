
import os
from sft_engine.bases import BaseEvaluator, QAPair
from sft_engine.models.tokenizer import Tokenizer


class LengthEvaluator(BaseEvaluator):
    def __init__(self, tokenizer_name: str = None):
        tokenizer_model = tokenizer_name or os.environ.get("TOKENIZER_MODEL", "cl100k_base")
        self.tokenizer: Tokenizer = Tokenizer(tokenizer_model)

    def evaluate(self, pair: QAPair) -> float:
        """
        Evaluate the length of the qa pair.
        """
        content = pair.question + pair.answer
        tokens = self.tokenizer.encode(content)
        return len(tokens)
