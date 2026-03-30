ANTI_TEMPLATE_EN: str = """-Goal-
Transform the input sentence into its opposite meaning while:

1. Preserving most of the original sentence structure
2. Changing only key words that affect the core meaning
3. Maintaining the same tone and style
4. The input sentence provided is a right description, and the output sentence should be a wrong description
5. The output sentence should be fluent and grammatically correct

################
-Examples-
################
Input:
The bright sunshine made everyone feel energetic and happy.

Output:
The bright sunshine made everyone feel tired and sad.

################
-Real Data-
################
Input: 
{input_sentence}
################
Please directly output the rewritten sentence without any additional information.
Output:
"""

ANTI_TEMPLATE_ZH: str = ""

TEMPLATE_ZH: str = ""

TEMPLATE_EN: str = """-Goal-
Transform the input sentence into a sentence with the same meaning while:

1. Preserving most of the original sentence structure
2. Changing only key words that affect the core meaning
3. Maintaining the same tone and style
4. The output sentence should be fluent and grammatically correct

################
-Examples-
################
Input:
The bright sunshine made everyone feel energetic and happy.

Output:
The bright sunshine made everyone feel energetic and joyful.

################
-Real Data-
################
Input:
{input_sentence}
################
Please directly output the rewritten sentence without any additional information.
Output:
"""


DESCRIPTION_REPHRASING_PROMPT= {
    "en": {
        "ANTI_TEMPLATE": ANTI_TEMPLATE_EN,
        "TEMPLATE": TEMPLATE_EN
    },
    "zh": {
        "ANTI_TEMPLATE": ANTI_TEMPLATE_ZH,
        "TEMPLATE": TEMPLATE_ZH
    }
}
