# pylint: disable=C0301
ANSWER_REPHRASING_CONTEXT_EN: str = """---Role---
You are an NLP expert responsible for generating a logically structured and coherent rephrased version of the TEXT based on ENTITIES and RELATIONSHIPS provided below. You may refer to the original text to assist in generating the rephrased version, but ensure that the final output text meets the requirements.
Use English as output language.

---Goal---
To generate a version of the text that is rephrased and conveys the same meaning as the original entity and relationship descriptions, while:
1. Following a clear logical flow and structure
2. Establishing proper cause-and-effect relationships
3. Ensuring temporal and sequential consistency
4. Creating smooth transitions between ideas using conjunctions and appropriate linking words like "firstly," "however," "therefore," etc.

---Instructions---
1. Analyze the provided ENTITIES and RELATIONSHIPS carefully to identify:
   - Key concepts and their hierarchies
   - Temporal sequences and chronological order
   - Cause-and-effect relationships
   - Dependencies between different elements

2. Organize the information in a logical sequence by:
   - Starting with foundational concepts
   - Building up to more complex relationships
   - Grouping related ideas together
   - Creating clear transitions between sections

3. Rephrase the text while maintaining:
   - Logical flow and progression
   - Clear connections between ideas
   - Proper context and background
   - Coherent narrative structure

4. Review and refine the text to ensure:
   - Logical consistency throughout
   - Clear cause-and-effect relationships

################
-ORIGINAL TEXT-
################
{original_text}

################
-ENTITIES-
################
{entities}

################
-RELATIONSHIPS-
################
{relationships}

"""

ANSWER_REPHRASING_CONTEXT_ZH: str = ""

ANSWER_REPHRASING_EN: str = """---Role---
You are an NLP expert responsible for generating a logically structured and coherent rephrased version of the TEXT based on ENTITIES and RELATIONSHIPS provided below.
Use English as output language.

---Goal---
To generate a version of the text that is rephrased and conveys the same meaning as the original entity and relationship descriptions, while:
1. Following a clear logical flow and structure
2. Establishing proper cause-and-effect relationships
3. Ensuring temporal and sequential consistency
4. Creating smooth transitions between ideas using conjunctions and appropriate linking words like "firstly," "however," "therefore," etc.

---Instructions---
1. Analyze the provided ENTITIES and RELATIONSHIPS carefully to identify:
   - Key concepts and their hierarchies
   - Temporal sequences and chronological order
   - Cause-and-effect relationships
   - Dependencies between different elements

2. Organize the information in a logical sequence by:
   - Starting with foundational concepts
   - Building up to more complex relationships
   - Grouping related ideas together
   - Creating clear transitions between sections

3. Rephrase the text while maintaining:
   - Logical flow and progression
   - Clear connections between ideas
   - Proper context and background
   - Coherent narrative structure

4. Review and refine the text to ensure:
   - Logical consistency throughout
   - Clear cause-and-effect relationships

**Attention: Please directly provide the rephrased text without any additional content or analysis.**

################
-ENTITIES-
################
{entities}

################
-RELATIONSHIPS-
################
{relationships}

"""

ANSWER_REPHRASING_ZH: str = ""

REQUIREMENT_ZH = """
################


<rephrased_text>rephrased_text_here</rephrased_text>


"""

REQUIREMENT_EN = """
################
Please directly output the coherent rephrased text below, without any additional content.

Output format:
<rephrased_text>rephrased_text_here</rephrased_text>

Rephrased Text:
"""

QUESTION_GENERATION_EN: str = """The answer to a question is provided. Please generate a question that corresponds to the answer.

The answer for which a question needs to be generated is as follows:
<answer>{answer}</answer>

Please note the following requirements:
1. Only output one question text without any additional explanations or analysis.
2. Do not repeat the content of the answer or any fragments of it.
3. The question must be independently understandable and fully match the answer.

Output format:
<question>question_text</question>

Question:
"""

QUESTION_GENERATION_ZH: str = ""

AGGREGATED_GENERATION_PROMPT = {
    "en": {
        "ANSWER_REPHRASING": ANSWER_REPHRASING_EN + REQUIREMENT_EN,
        "ANSWER_REPHRASING_CONTEXT": ANSWER_REPHRASING_CONTEXT_EN + REQUIREMENT_EN,
        "QUESTION_GENERATION": QUESTION_GENERATION_EN,
    },
    "zh": {
        "ANSWER_REPHRASING": ANSWER_REPHRASING_ZH + REQUIREMENT_ZH,
        "ANSWER_REPHRASING_CONTEXT": ANSWER_REPHRASING_CONTEXT_ZH + REQUIREMENT_ZH,
        "QUESTION_GENERATION": QUESTION_GENERATION_ZH,
    },
}
