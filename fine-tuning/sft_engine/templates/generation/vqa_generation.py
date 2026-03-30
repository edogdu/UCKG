# pylint: disable=C0301
TEMPLATE_EN: str = """You are a senior VQA data engineer. Your task is to generate logically coherent, verifiable and non-hallucinated question-answer pairs for the given multi-modal samples.
Use English as the output language.

---Objectives---
Create multiple sets of VQA question-answer pairs that satisfy the following:
1. Only ask about objectively existing facts in the given data, avoiding subjective or ambiguous questions.
2. Ensure that each question has a clear and verifiable answer, avoiding questions with no answer or uncertainty.
3. Questions should cover various aspects of both image and text content, ensuring diversity and comprehensiveness.
4. Avoid repetitive questions, ensuring that each question is unique and meaningful.
5. Use clear and concise language, avoiding complex or ambiguous wording.

---Instructions---
1. Carefully analyze the provided entities and relationships to identify:
    - Key concepts and their hierarchical relationships
    - Temporal sequences and time order
    - Cause-and-effect relationships
    - Dependencies between different elements
2. Organize the information into a logical sequence by:
    - Starting with foundational concepts
    - Gradually building up to more complex relationships
    - Grouping related ideas together
    - Creating clear transitions between sections
3. Maintain the following when generating question-answer pairs:
    - Logical flow
    - Clear connections between concepts
    - Appropriate context and background
    - Coherent narrative structure
4. Review and refine the question-answer pairs to ensure:
    - Overall logical consistency
    - Clear cause-and-effect relationships

################
-Entities-
################
{entities}
################
-Relationships-
################
{relationships}
################

Please directly output the generated questions and answers, do not directly copy the example questions and answers, and do not provide irrelevant information.

Here is the response format you should follow:
<question>question1</question>
<answer>answer1</answer>
<question>question2</question>
<answer>answer2</answer>

Output:
"""

TEMPLATE_ZH: str = ""

VQA_GENERATION_PROMPT = {"en": TEMPLATE_EN, "zh": TEMPLATE_ZH}
