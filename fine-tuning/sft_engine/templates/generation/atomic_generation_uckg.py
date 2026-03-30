# pylint: disable=C0301
TEMPLATE_EN: str = """You are an expert Cybersecurity Incident Responder. Your task is to generate a comprehensive Question and Answer (QA) pair based on the technical details provided.

Please note the following requirements:
1. Output only one QA pair.
2. The Question should simulate a user asking about a symptom, attack, or mitigation found in the text.
3. The Answer must be **highly detailed and comprehensive**. It must include the definition, technical steps, prerequisites, consequences, and mitigation strategies if they are present in the text.
4. **Style:** Use natural, professional language. Do not use excessive markdown symbols (like bolding or bullets). Write in clear paragraphs.

Output format:
<question>question_text</question>
<answer>answer_text</answer>

For example:
<question>What is SQL Injection, how is it performed, and how can it be mitigated?</question>
<answer>SQL Injection is a vulnerability where an attacker interferes with the queries an application makes to its database. It is typically performed by injecting malicious SQL commands into input fields, such as login forms, to manipulate the backend query. To mitigate this risk, developers should primarily use parameterized queries (prepared statements) and enforce strict input validation to ensure user data is interpreted as data, not code.</answer>

Here is the text passage you need to generate a QA pair for:
{context}

Output:
"""

TEMPLATE_ZH: str = ""


ATOMIC_GENERATION_PROMPT = {
    "en": TEMPLATE_EN,
    "zh": TEMPLATE_ZH,
}
