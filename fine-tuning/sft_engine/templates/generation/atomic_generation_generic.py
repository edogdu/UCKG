# pylint: disable=C0301
TEMPLATE_EN: str = """You are given a text passage. Your task is to generate a question and answer (QA) pair based on the content of that text.

Please note the following requirements:
1. Output only one QA pair without any additional explanations or analysis.
2. Do not repeat the content of the answer or any part of it.
3. The answer should be accurate and directly derived from the text. Make sure the QA pair is relevant to the main theme or important details of the given text.

Output format:
<question>question_text</question>
<answer>answer_text</answer>

For example:
<question>What is the effect of overexpressing the BG1 gene on grain size and development?</question>
<answer>Overexpression of the BG1 gene leads to significantly increased grain size, demonstrating its role in grain development.</answer>

Here is the text passage you need to generate a QA pair for:
{context}

Output:
"""

TEMPLATE_ZH: str = ""


ATOMIC_GENERATION_PROMPT = {
    "en": TEMPLATE_EN,
    "zh": TEMPLATE_ZH,
}