import re
from typing import Any

from sft_engine.bases import BaseGenerator
from sft_engine.templates import ATOMIC_GENERATION_PROMPT
from sft_engine.utils import compute_content_hash, detect_main_language, logger


class AtomicGenerator(BaseGenerator):
    @staticmethod
    def build_prompt(
        batch: tuple[list[tuple[str, dict]], list[tuple[Any, Any, dict]]]
    ) -> str:
        nodes, edges = batch
        context = ""
        for node in nodes:
            context += f"- {node[0]}: {node[1]['description']}\n"
        for edge in edges:
            context += f"- {edge[0]} - {edge[1]}: {edge[2]['description']}\n"
        language = detect_main_language(context)

        prompt = ATOMIC_GENERATION_PROMPT[language].format(context=context)
        return prompt

    @staticmethod
    def parse_response(response: str) -> dict:
        """
        Parse response to extract multiple QA pairs.
        Expected format:
        <question>Q1</question>
        <answer>A1</answer>
        <question>Q2</question>
        <answer>A2</answer>
        ...
        """
        qa_pairs = {}
        
        # Find all questions and answers
        questions = re.findall(r"<question>(.*?)</question>", response, re.DOTALL)
        answers = re.findall(r"<answer>(.*?)</answer>", response, re.DOTALL)

        if not questions or not answers:
            logger.warning("Failed to parse response: %s", response)
            return {}

        # Pair them up (assuming sequential order)
        for i, (q, a) in enumerate(zip(questions, answers)):
            question = q.strip().strip('"').strip("'")
            answer = a.strip().strip('"').strip("'")
            
            logger.debug("Question %d: %s", i+1, question)
            logger.debug("Answer %d: %s", i+1, answer)
            
            # Use unique hash for each pair
            qa_pairs[compute_content_hash(question)] = {
                "question": question,
                "answer": answer,
            }
            
        return qa_pairs
