TEMPLATE_GENERATION_ZH: str = ""

TEMPLATE_GENERATION_EN: str = """Generate independent multiple-choice questions \
based on the provided context. Each question should contain four options \
with only one correct answer and three distractors.

Requirements:
1. **Language Consistency**: Generate in the same language as the context (Chinese/English)
2. **Quantity**: Generate {num_of_questions} questions per context
3. **Independence**: Each question must be self-contained
4. **Accuracy**: Correct answer must be derivable from text, distractors should be plausible

Output Format:
<qa_pairs>
<qa_pair>
<question>Question text</question>
<options>A. Option A text
B. Option B text
C. Option C text
D. Option D text</options>
<answer>Correct option letter</answer>
</qa_pair>
</qa_pairs>

Example (2 questions):
<qa_pairs>
<qa_pair>
<question>What year was the iPad Air 2 released?</question>
<options>A. 2012
B. 2014
C. 2015
D. 2017</options>
<answer>B</answer>
</qa_pair>
<qa_pair>
<question>Which processor does iPad Air 2 use?</question>
<options>A. A8
B. A9X
C. A8X
D. A10</options>
<answer>C</answer>
</qa_pair>
</qa_pairs>

Context:
{context}

Please generate {num_of_questions} questions for the following context:
"""


MCQ_GENERATION_PROMPT = {"zh": TEMPLATE_GENERATION_ZH, "en": TEMPLATE_GENERATION_EN}
