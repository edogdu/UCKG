TEMPLATE_ZH = ""


TEMPLATE_EN = """Generate independent fill-in-the-blank questions based on the provided context. \
Answers must be directly derivable from the text.

Requirements:
1. **Language Consistency**: Generate in the same language as the context (Chinese/English)
2. **Quantity**: Generate {num_of_questions} questions per context
3. **Independence**: Each question must be self-contained
4. **Accuracy**: Correct answer must be directly found in the source text
5. **Placeholder Format**: Use ________ (four underscores) as the blank placeholder

Output Format:
<qa_pairs>
<qa_pair>
<question>Question text (use ________ as placeholder)</question>
<answer>Correct answer text (separate multiple blanks with commas)</answer>
</qa_pair>
</qa_pairs>

Example (2 questions):
<qa_pairs>
<qa_pair>
<question>The iPad Air 2 was manufactured by ________?</question>
<answer>Apple Inc.</answer>
</qa_pair>
<qa_pair>
<question>The iPad Air 2 was released on ________ and launched on ________.</question>
<answer>October 16, 2014, October 22, 2014</answer>
</qa_pair>
</qa_pairs>

Context:
{context}

Please generate {num_of_questions} fill-in-the-blank questions for the following context:
"""


FILL_IN_BLANK_GENERATION_PROMPT = {
    "zh": TEMPLATE_ZH,
    "en": TEMPLATE_EN,
}
