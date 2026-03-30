ENTITY_TYPE_CONFLICT_PROMPT_ZH = ""

ENTITY_TYPE_CONFLICT_PROMPT_EN = (
    """You are a Knowledge Graph Consistency Assessment Expert. """
    """Your task is to determine whether there are semantic conflicts """
    """when the same entity is extracted as different types in different text blocks.

Entity Name: {entity_name}

Type extraction results from different text blocks:
{type_extractions}

Preset entity type list (for reference):
concept, date, location, keyword, organization, person, event, work, nature, """
    """artificial, science, technology, mission, gene

Please determine whether these types have semantic conflicts """
    """(i.e., whether they describe the same category of things, """
    """or if there are contradictions).
Note: If types are just different expressions of the same concept """
    """(such as concept and keyword), it may not be considered a serious conflict.

Please return in JSON format:
{{
    "has_conflict": <true/false>,
    "conflict_severity": <float between 0-1, where 0 means no conflict, 1 means severe conflict>,
    "conflict_reasoning": "<reasoning for conflict judgment>",
    "conflicting_types": ["<pairs of conflicting types>"],
    "recommended_type": "<if there is a conflict, the recommended correct type (must be one of the preset types)>"
}}
"""
)

ENTITY_DESCRIPTION_CONFLICT_PROMPT_ZH = ""

ENTITY_DESCRIPTION_CONFLICT_PROMPT_EN = (
    """You are a Knowledge Graph Consistency Assessment Expert. """
    """Your task is to determine whether there are semantic conflicts """
    """in the descriptions of the same entity across different text blocks.

Entity Name: {entity_name}

Descriptions from different text blocks:
{descriptions}

Please determine whether these descriptions have semantic conflicts """
    """(i.e., whether they describe the same entity, """
    """or if there is contradictory information).

Please return in JSON format:
{{
    "has_conflict": <true/false>,
    "conflict_severity": <float between 0-1>,
    "conflict_reasoning": "<reasoning for conflict judgment>",
    "conflicting_descriptions": ["<pairs of conflicting descriptions>"],
    "conflict_details": "<specific conflict content>"
}}
"""
)

RELATION_CONFLICT_PROMPT_ZH = ""

RELATION_CONFLICT_PROMPT_EN = (
    """You are a Knowledge Graph Consistency Assessment Expert. """
    """Your task is to determine whether there are semantic conflicts """
    """in the relation descriptions of the same entity pair across different text blocks.

Entity Pair: {source_entity} -> {target_entity}

Relation descriptions from different text blocks:
{relation_descriptions}

Please determine whether these relation descriptions have semantic conflicts.

Please return in JSON format:
{{
    "has_conflict": <true/false>,
    "conflict_severity": <float between 0-1>,
    "conflict_reasoning": "<reasoning for conflict judgment>",
    "conflicting_relations": ["<pairs of conflicting relation descriptions>"]
}}
"""
)

ENTITY_EXTRACTION_PROMPT_ZH = ""

ENTITY_EXTRACTION_PROMPT_EN = """Extract the type and description of the specified entity from the following text block.

**Important**: You should only extract the specified entity, do not extract other entities.

Entity Name: {entity_name}

Text Block:
{chunk_content}

Please find and extract the following information for **this entity only** (entity name: {entity_name}) from the text block:

1. entity_type: Entity type, must be one of the following preset types (lowercase):
   - concept: concept
   - date: date
   - location: location
   - keyword: keyword
   - organization: organization
   - person: person
   - event: event
   - work: work
   - nature: nature
   - artificial: artificial
   - science: science
   - technology: technology
   - mission: mission
   - gene: gene

   If the type cannot be determined, please use "concept" as the default value.

2. description: Entity description (briefly describe the role and characteristics of this entity in the text)

Please return in JSON format:
{{
    "entity_type": "<entity type (must be one of the preset types above)>",
    "description": "<entity description>"
}}
"""

CONSISTENCY_EVALUATION_PROMPT = {
    "zh": {
        "ENTITY_TYPE_CONFLICT": ENTITY_TYPE_CONFLICT_PROMPT_ZH,
        "ENTITY_DESCRIPTION_CONFLICT": ENTITY_DESCRIPTION_CONFLICT_PROMPT_ZH,
        "RELATION_CONFLICT": RELATION_CONFLICT_PROMPT_ZH,
        "ENTITY_EXTRACTION": ENTITY_EXTRACTION_PROMPT_ZH,
    },
    "en": {
        "ENTITY_TYPE_CONFLICT": ENTITY_TYPE_CONFLICT_PROMPT_EN,
        "ENTITY_DESCRIPTION_CONFLICT": ENTITY_DESCRIPTION_CONFLICT_PROMPT_EN,
        "RELATION_CONFLICT": RELATION_CONFLICT_PROMPT_EN,
        "ENTITY_EXTRACTION": ENTITY_EXTRACTION_PROMPT_EN,
    },
}
