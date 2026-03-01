# pylint: disable=C0301
TEMPLATE_ZH: str = ""

TEMPLATE_EN: str = """Please generate a multi-hop reasoning question and answer based on the following knowledge subgraph. You will be provided with a knowledge subgraph that contains a series of entities, relations, and facts.
Your task is to generate a question-answer (QA) pair where the question requires multiple steps of reasoning to answer. The answer to the question should be inferred from the given knowledge subgraph. Ensure that the question is of moderate difficulty and requires multiple steps of reasoning to answer.

Please note the following requirements:
1. Output only one QA pair without any additional explanations or analysis.
2. Do not repeat the content of the answer or any part of it. Do not directly copy the example question and answer.
3. The answer should be accurate and directly derived from the text. Make sure the QA pair is relevant to the main theme or important details of the given text.

For example:
Input:
--Entities--
1. Apple
2. Fruit
3. Vitamin C
--Relations--
1. Apple-Fruit: Apple is a type of fruit
2. Fruit-Vitamin C: Fruits are rich in Vitamin C

Output:
<question>What substance, obtained by eating apples, helps maintain health?</question>
<answer>Vitamin C</answer>

Real input:
--Entities--
{entities}
--Relations--
{relationships}

Output:
"""

MULTI_HOP_GENERATION_PROMPT = {"en": TEMPLATE_EN, "zh": TEMPLATE_ZH}
