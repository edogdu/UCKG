import re
from typing import Any

from sft_engine.bases import BaseGenerator
from sft_engine.templates import MULTI_HOP_GENERATION_PROMPT
from sft_engine.utils import compute_content_hash, detect_main_language, logger


class MultiHopGenerator(BaseGenerator):
    @staticmethod
    def build_prompt(
        batch: tuple[list[tuple[str, dict]], list[tuple[Any, Any, dict]]]
    ) -> str:
        nodes, edges = batch
        entities_str = "\n".join(
            [
                f"{index + 1}. {node[0]}: {node[1]['description']}"
                for index, node in enumerate(nodes)
            ]
        )

        relationships_str = "\n".join(
            [
                f"{index + 1}. {edge[0]} -- {edge[1]}: {edge[2]['description']}"
                for index, edge in enumerate(edges)
            ]
        )
        language = detect_main_language(entities_str + relationships_str)
        prompt = MULTI_HOP_GENERATION_PROMPT[language].format(
            entities=entities_str, relationships=relationships_str
        )
        return prompt

    @staticmethod
    def parse_response(response: str) -> dict:
        question_match = re.search(r"<question>(.*?)</question>", response, re.DOTALL)
        answer_match = re.search(r"<answer>(.*?)</answer>", response, re.DOTALL)

        if question_match and answer_match:
            question = question_match.group(1).strip()
            answer = answer_match.group(1).strip()
        else:
            logger.warning("Failed to parse response: %s", response)
            return {}

        question = question.strip('"').strip("'")
        answer = answer.strip('"').strip("'")
        logger.debug("Question: %s", question)
        logger.debug("Answer: %s", answer)
        return {
            compute_content_hash(question): {
                "question": question,
                "answer": answer,
            }
        }
