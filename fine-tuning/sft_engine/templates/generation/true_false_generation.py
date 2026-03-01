TEMPLATE_TF_ZH: str = ""


TEMPLATE_TF_EN: str = """Generate independent true/false questions based on the provided context. \
Each question should be a factual statement that can be clearly determined as true or false.

Requirements:
1. **Language Consistency**: Generate in the same language as the context (Chinese/English)
2. **Quantity**: Generate {num_of_questions} true/false questions per context
3. **Independence**: Each question must be self-contained
4. **Accuracy**: Correct answer must be directly derivable from the text with clear evidence

Output Format:
<qa_pairs>
<qa_pair>
<question>Statement text</question>
<answer>True or False</answer>
</qa_pair>
</qa_pairs>

Example (2 questions):
<qa_pairs>
<qa_pair>
<question>The iPad Air 2 was released in 2014.</question>
<answer>True</answer>
</qa_pair>
<qa_pair>
<question>The iPad Air 2 uses an A10 processor.</question>
<options>True
False</options>
<answer>False</answer>
</qa_pair>
</qa_pairs>

Context:
{context}

Please generate {num_of_questions} true/false questions for the following context:
"""


TF_GENERATION_PROMPT = {"zh": TEMPLATE_TF_ZH, "en": TEMPLATE_TF_EN}
