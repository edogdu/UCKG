# pylint: disable=C0301
TEMPLATE_EN: str = """You are an expert Cybersecurity Analyst. Your task is to generate exactly 3 distinct Question and Answer (QA) pairs based on the technical details provided in the text.

Please note the following requirements:
1. **Output exactly 3 QA pairs.**
2. **Questions:**
   - Must be specific (e.g., ask about the mechanism, protocol, goal, or prerequisites).
   - **MUST explicitly name the attack or concept** (e.g., "What protocol does BlueSmacking use?"). Do NOT use "this attack", "the pattern", or "the text".
3. **Answers:**
   - Start by directly answering the specific question.
   - Then, **expand to include the full technical context/mechanism** provided in the source text. This ensures the answer is comprehensive and covers all details (protocols, constraints, consequences).

Output format:
<question>question_1</question>
<answer>direct_answer + full_context</answer>
<question>question_2</question>
<answer>direct_answer + full_context</answer>
<question>question_3</question>
<answer>direct_answer + full_context</answer>

Here is the text passage you need to generate QA pairs for:
{context}

Output:
"""

TEMPLATE_ZH: str = ""


ATOMIC_GENERATION_PROMPT = {
    "en": TEMPLATE_EN,
    "zh": TEMPLATE_ZH,
}
