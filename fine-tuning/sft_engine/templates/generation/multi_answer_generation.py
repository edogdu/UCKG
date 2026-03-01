TEMPLATE_ZH = ""


TEMPLATE_EN = """Generate independent multiple-select knowledge questions \
based on the provided context. Each question should contain four options \
with one or more correct answers and distractors.

Requirements:
1. **Language Consistency**: Generate in the same language as the context (Chinese/English)
2. **Quantity**: Generate {num_of_questions} questions per context
3. **Independence**: Each question must be self-contained
4. **Accuracy**: Correct answer(s) must be derivable from text, distractors should be plausible
5. **Answer Format**: For multiple correct answers, separate option letters with commas, e.g., "A, B, C"

Output Format:
<qa_pairs>
<qa_pair>
<question>Question text</question>
<options>A. Option A text
B. Option B text
C. Option C text
D. Option D text</options>
<answer>Correct option letter(s) (separate multiple answers with commas)</answer>
</qa_pair>
</qa_pairs>

Example (2 questions):
<qa_pairs>
<qa_pair>
<question>What are the features of iPad Air 2?</question>
<options>A. Touch ID fingerprint recognition
B. A8X processor
C. Ten-megapixel front camera
D. Eight-megapixel rear camera</options>
<answer>A, B, D</answer>
</qa_pair>
<qa_pair>
<question>When was iPad Air 2 discontinued?</question>
<options>A. March 21, 2016
B. March 21, 2017
C. October 22, 2017
D. October 16, 2016</options>
<answer>B</answer>
</qa_pair>
</qa_pairs>

Context:
{context}

Please generate {num_of_questions} multiple-select questions for the following context:
"""


MAQ_GENERATION_PROMPT = {"zh": TEMPLATE_ZH, "en": TEMPLATE_EN}
