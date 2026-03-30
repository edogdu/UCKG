TEMPLATE_EN = """You are an NLP expert responsible for generating a comprehensive summary of the data provided below.
Given one entity or relationship, and a list of descriptions, all related to the same entity or relationship.
Please concatenate all of these into a single, comprehensive description. Make sure to include information collected from all the descriptions.
If the provided descriptions are contradictory, please resolve the contradictions and provide a single, coherent summary.
Make sure it is written in third person, and include the entity names so we the have full context.
Use English as output language.

#######
-Data-
Entities: {entity_name}
Description List: {description_list}
#######
Output:
"""

TEMPLATE_ZH = ""


KG_SUMMARIZATION_PROMPT = {
    "zh": {"TEMPLATE": TEMPLATE_ZH},
    "en": {"TEMPLATE": TEMPLATE_EN},
    "FORMAT": {
        "tuple_delimiter": "<|>",
        "record_delimiter": "##",
        "completion_delimiter": "<|COMPLETE|>",
    },
}
