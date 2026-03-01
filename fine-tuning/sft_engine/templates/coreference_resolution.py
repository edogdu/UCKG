TEMPLATE_ZH: str = ""

TEMPLATE_EN: str = """Please identify and resolve the pronouns in the reference text, \
specify the specific entities referred to by each pronoun, and directly output the resolved text.

-Example-
Input:
John and Mary went to the park. They had a great time. Later, they went to eat ice cream.
Output:
John and Mary went to the park. John and Mary had a great time. Later, John and Mary went to eat ice cream.

-Real Data-
Reference text:
{reference}
Input:
{input_sentence}
Please directly output the rewritten sentence without any additional information.
Output:
"""

COREFERENCE_RESOLUTION_PROMPT = {"en": TEMPLATE_EN, "zh": TEMPLATE_ZH}
