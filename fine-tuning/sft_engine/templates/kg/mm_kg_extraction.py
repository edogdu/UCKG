# pylint: disable=C0301
TEMPLATE_EN: str = """You are an expert in multi-modal data analysis and knowledge graph construction. Your task is to extract named entities and relationships from a given multi-modal data chunk and its accompanying text.

-Objective-
Given a multi-modal data chunk (e.g., image, table, formula, etc. + accompanying text), construct a knowledge graph centered around the "central multi-modal entity":
- The central entity must be the image/table/formula itself (e.g., image-c71ef797e99af81047fbc7509609c765).
- Related entities and relationships must be extracted from the accompanying text.
- Only retain edges directly connected to the central entity, forming a star-shaped graph.
Use English as the output language.

-Steps-
1. Identify the unique central multi-modal entity and recognize all text entities directly related to the central entity from the accompanying text.
    For the central entity, extract the following information:
    - entity_name: Use the unique identifier of the data chunk (e.g., image-c71ef797e99af81047fbc7509609c765).
    - entity_type: Label according to the type of data chunk (image, table, formula, etc.).
    - entity_summary: A brief description of the content of the data chunk and its role in the accompanying text.
    For each entity recognized from the accompanying text, extract the following information:
    - entity_name: The name of the entity, capitalized
    - entity_type: One of the following types: [{entity_types}]
    - entity_summary: A comprehensive summary of the entity's attributes and activities
    Format each entity as ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_summary>)

2. From the entities identified in Step 1, recognize all (source_entity, target_entity) pairs that are *obviously related* to each other.
    For each pair of related entities, extract the following information:
    - source_entity: The name of the source entity identified in Step 1
    - target_entity: The name of the target entity identified in Step 1
    - relationship_summary: Explain why you think the source entity and target entity are related to each other
    Format each relationship as ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_summary>)

3. Return the output list of all entities and relationships identified in Steps 1 and 2 in English. Use **{record_delimiter}** as the list separator.

4. Upon completion, output {completion_delimiter}

################
-Example-
################
Multi-modal data chunk type: image
Multi-modal data chunk unique identifier: image-c71ef797e99af81047fbc7509609c765
Accompanying text: The Eiffel Tower is an iconic structure in Paris, France, designed by Gustave Eiffel and completed in 1889. It stands 324 meters tall and is one of the tallest structures in the world. The Eiffel Tower is located on the banks of the Seine River and attracts millions of visitors each year. It is not only an engineering marvel but also an important symbol of French culture.
################
Output:
("entity"{tuple_delimiter}"image-c71ef797e99af81047fbc7509609c765"{tuple_delimiter}"image"{tuple_delimiter}"This is an image showcasing the iconic structure in Paris, France, the Eiffel Tower, highlighting its full height of 324 meters along with the riverside scenery, symbolizing both engineering and cultural significance"){record_delimiter}
("entity"{tuple_delimiter}"Eiffel Tower"{tuple_delimiter}"landmark"{tuple_delimiter}"The Eiffel Tower is an iconic structure in Paris, France, designed by Gustave Eiffel and completed in 1889, standing 324 meters tall, located on the banks of the Seine River, attracting millions of visitors each year"){record_delimiter}
("entity"{tuple_delimiter}"Paris, France"{tuple_delimiter}"location"{tuple_delimiter}"Paris, France is the capital of France, known for its rich historical and cultural heritage and as the location of the Eiffel Tower"){record_delimiter}
("entity"{tuple_delimiter}"Gustave Eiffel"{tuple_delimiter}"person"{tuple_delimiter}"Gustave Eiffel is a renowned French engineer who designed and built the Eiffel Tower"){record_delimiter}
("entity"{tuple_delimiter}"Seine River"{tuple_delimiter}"location"{tuple_delimiter}"The Seine River is a major river flowing through Paris, France, with the Eiffel Tower located on its banks"){completion_delimiter}
("relationship"{tuple_delimiter}"image-c71ef797e99af81047fbc7509609c765"{tuple_delimiter}"Eiffel Tower"{tuple_delimiter}"The image showcases the iconic structure, the Eiffel Tower"){record_delimiter}
("relationship"{tuple_delimiter}"image-c71ef797e99af81047fbc7509609c765"{tuple_delimiter}"Paris, France"{tuple_delimiter}"The image's background is Paris, France, highlighting the geographical location of the Eiffel Tower"){record_delimiter}
("relationship"{tuple_delimiter}"image-c71ef797e99af81047fbc7509609c765"{tuple_delimiter}"Gustave Eiffel"{tuple_delimiter}"The Eiffel Tower in the image was designed by Gustave Eiffel"){record_delimiter}
("relationship"{tuple_delimiter}"image-c71ef797e99af81047fbc7509609c765"{tuple_delimiter}"Seine River"{tuple_delimiter}"The image showcases the scenery of the Eiffel Tower located on the banks of the Seine River"){completion_delimiter}
################

-Real Data-
Multi-modal data chunk type: {chunk_type}
Multi-modal data chunk unique identifier: {chunk_id}
Accompanying text: {chunk_text}
################
Output:
"""

TEMPLATE_ZH: str = ""


MMKG_EXTRACTION_PROMPT: dict = {
    "en": TEMPLATE_EN,
    "zh": TEMPLATE_ZH,
    "FORMAT": {
        "tuple_delimiter": "<|>",
        "record_delimiter": "##",
        "completion_delimiter": "<|COMPLETE|>",
        "entity_types": "concept, date, location, keyword, organization, person, event, work, nature, artificial, \
science, technology, mission, gene",
    },
}
