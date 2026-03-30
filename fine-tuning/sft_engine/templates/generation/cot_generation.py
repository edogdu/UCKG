COT_GENERATION_ZH = ""

COT_GENERATION_EN = """Given the raw knowledge graph information and the provided reasoning-path, \
produce one Chain-of-Thought (CoT) sample that strictly follows the template \
and can be directly used for downstream training or inference.
CoT (Chain-of-Thought) means that when answering a complex question, the intermediate reasoning steps are \
explicitly written out one by one, making the reasoning process transparent and traceable instead of giving \
only the final answer.

-Input Format-
[Entities:]:
(ENTITY_NAME: ENTITY_DESCRIPTION)
...

[Relationships:]:
(ENTITY_SOURCE)-[RELATIONSHIP_DESCRIPTION]->(ENTITY_TARGET)
...

[Question and Reasoning Path:]:
(QUESTION)
(REASONING_PATH)

-Output Requirements-
1. Each step completes a single, indivisible sub-task and is naturally connected, avoiding abrupt transition words.
2. Use English.
3. Do not use ordered lists or numbering.
4. Do not generate extraneous information, just provide the answer.

-Real Data-
Input:
[Entities:]:
{entities}

[Relationships:]:
{relationships}

[Question:]:
{question}

[Reasoning_Template:]:
{reasoning_template}

Output:
"""

COT_TEMPLATE_DESIGN_ZH: str = ""


COT_TEMPLATE_DESIGN_EN: str = """You are a “meta-reasoning architect”. \
Your task is NOT to answer the question, but to design a reusable, generalizable CoT reasoning-path \
template based solely on the names and descriptions of entities and \
relationships in the provided knowledge graph.

- Steps -
1. Entity Recognition
- Accurately recognize entity information in the [Entities:] section, including entity names and descriptions.
- The general formats for entity information are:
(ENTITY_NAME: ENTITY_DESCRIPTION)

2. Relationship Recognition
- Accurately recognize relationship information in the [Relationships:] section, including source_entity_name, target_entity_name, and relationship descriptions.
- The general formats for relationship information are:
(SOURCE_ENTITY_NAME)-[RELATIONSHIP_DESCRIPTION]->(TARGET_ENTITY_NAME)

3. Graph Structure Understanding
- Correctly associate the source entity name in the relationship information with the entity information.
- Reconstruct the graph structure based on the provided relationship information.

4. Question Design
- Design a question around the "core theme" expressed by the knowledge graph.
- The question must be verifiable directly within the graph through entities, relationships, or attributes; avoid subjective judgments.
- The question should allow the model to think sufficiently, fully utilizing the entities and relationships in the graph, avoiding overly simple or irrelevant questions.

5. Reasoning-Path Design
- Output a **blueprint that any later model can directly execute**.
- Keep steps minimal: each step solves one indivisible sub-problem.


- Constraints -
1. Do NOT describe your thinking; output only the reasoning-path design.
2. If the provided descriptions are contradictory, resolve conflicts and provide a single coherent logic.
3. Avoid using stop words and overly common words.
4. Do not include specific numerical values or conclusions, \
and DO NOT describing meaningless operations like "Identify the entity" or "Identify the relationship".
5. Use English as the output language.
6. The output format is:
<question>question text</question>
<reasoning_path>reasoning path design text</reasoning_path>

Please summarize the information expressed by the knowledge graph based on the following [Entities:] and [Relationships:] provided.

- Real Data -
Input:
[Entities:]:
{entities}

[Relationships:]:
{relationships}

Output:
"""

COT_GENERATION_PROMPT = {
    "en": {
        "COT_GENERATION": COT_GENERATION_EN,
        "COT_TEMPLATE_DESIGN": COT_TEMPLATE_DESIGN_EN,
    },
    "zh": {
        "COT_GENERATION": COT_GENERATION_ZH,
        "COT_TEMPLATE_DESIGN": COT_TEMPLATE_DESIGN_ZH,
    },
}
