# pylint: disable=C0301
TEMPLATE_EN: str = """You are an NLP expert, skilled at analyzing text to extract named entities and their relationships.

-Goal-
Given a text document that is potentially relevant to this activity and a list of entity types, identify all entities of those types from the text and all relationships among the identified entities.
Use English as output language.

-Steps-
1. Identify all entities. For each identified entity, extract the following information:
- entity_name: Name of the entity, use same language as input text. If English, capitalized the name.
- entity_type: One of the following types: [{entity_types}]
- entity_summary: Comprehensive summary of the entity's attributes and activities
Format each entity as ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_summary>)

2. From the entities identified in step 1, identify all pairs of (source_entity, target_entity) that are *clearly related* to each other.
For each pair of related entities, extract the following information:
- source_entity: name of the source entity, as identified in step 1
- target_entity: name of the target entity, as identified in step 1
- relationship_summary: explanation as to why you think the source entity and the target entity are related to each other
Format each relationship as ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_summary>)

3. Identify high-level key words that summarize the main concepts, themes, or topics of the entire text. These should capture the overarching ideas present in the document.
Format the content-level key words as ("content_keywords"{tuple_delimiter}<high_level_keywords>)

4. Return output in English as a single list of all the entities and relationships identified in steps 1 and 2. Use **{record_delimiter}** as the list delimiter.

5. When finished, output {completion_delimiter}

################
-Examples-
################
-Example 1-
Text:
################
In the second century of the Christian Era, the empire of Rome comprehended the fairest part of the earth, and the most civilized portion of mankind. The frontiers of that extensive monarchy were guarded by ancient renown and disciplined valor. The gentle but powerful influence of laws and manners had gradually cemented the union of the provinces. Their peaceful inhabitants enjoyed and abused the advantages of wealth and luxury. The image of a free constitution was preserved with decent reverence: the Roman senate appeared to possess the sovereign authority, and devolved on the emperors all the executive powers of government. During a happy period of more than fourscore years, the public administration was conducted by the virtue and abilities of Nerva, Trajan, Hadrian, and the two Antonines.
################
Output:
("entity"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"organization"{tuple_delimiter}"The dominant empire of the second century CE, encompassing the most developed regions of the known world."){record_delimiter}
("entity"{tuple_delimiter}"Second Century CE"{tuple_delimiter}"date"{tuple_delimiter}"Time period of the Christian Era when the Roman Empire was at its height."){record_delimiter}
("entity"{tuple_delimiter}"Rome"{tuple_delimiter}"location"{tuple_delimiter}"The capital and heart of the Roman Empire."){record_delimiter}
("entity"{tuple_delimiter}"Roman Senate"{tuple_delimiter}"organization"{tuple_delimiter}"Legislative body that appeared to hold sovereign authority in Rome."){record_delimiter}
("entity"{tuple_delimiter}"Nerva"{tuple_delimiter}"person"{tuple_delimiter}"Roman emperor who contributed to the public administration during a prosperous period."){record_delimiter}
("entity"{tuple_delimiter}"Trajan"{tuple_delimiter}"person"{tuple_delimiter}"Roman emperor known for his virtue and administrative abilities."){record_delimiter}
("entity"{tuple_delimiter}"Hadrian"{tuple_delimiter}"person"{tuple_delimiter}"Roman emperor who governed during the empire's peaceful period."){record_delimiter}
("entity"{tuple_delimiter}"Antonines"{tuple_delimiter}"person"{tuple_delimiter}"Two Roman emperors who ruled during a period of prosperity and good governance."){record_delimiter}
("entity"{tuple_delimiter}"Roman Law"{tuple_delimiter}"concept"{tuple_delimiter}"System of laws and manners that unified the provinces of the Roman Empire."){record_delimiter}
("relationship"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"Roman Law"{tuple_delimiter}"The empire was unified and maintained through the influence of its laws and customs."){record_delimiter}
("relationship"{tuple_delimiter}"Roman Senate"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"The Senate appeared to possess sovereign authority while delegating executive powers to emperors."){record_delimiter}
("relationship"{tuple_delimiter}"Nerva"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"Nerva was one of the emperors who contributed to the empire's successful administration."){record_delimiter}
("relationship"{tuple_delimiter}"Trajan"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"Trajan was one of the emperors who governed during the empire's prosperous period."){record_delimiter}
("relationship"{tuple_delimiter}"Hadrian"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"Hadrian was one of the emperors who managed the empire's administration effectively."){record_delimiter}
("relationship"{tuple_delimiter}"Antonines"{tuple_delimiter}"Roman Empire"{tuple_delimiter}"The Antonines were emperors who helped maintain the empire's prosperity through their governance."){record_delimiter}
("content_keywords"{tuple_delimiter}"Roman governance, imperial prosperity, law and order, civilized society"){completion_delimiter}

-Example 2-
Text:
#############
Overall, the analysis of the OsDT11 sequence demonstrated that this protein belongs to the CRP family. Since OsDT11 is predicted to be a secreted protein, the subcellular localization of OsDT11 was determined by fusing the OsDT11 ORF to RFP in a p35S::RFP vector by in vivo protein targeting in NB epidermal cells by performing an Agrobacterium tumefaciens-mediated transient assay. After incubation for 48 h, the RFP signals were mainly detected in the cell-wall of OsDT11-RFP transformed cells, while the control cells (transformed with the RFP construct) displayed ubiquitous RFP signals, demonstrating that OsDT11 is a secreted signal peptide. Moreover, when the infiltrated leaf sections were plasmolyzed, the OsDT11-RFP fusion proteins were located on the cell wall.
#############
Output:
("entity"{tuple_delimiter}"OsDT11"{tuple_delimiter}"gene"{tuple_delimiter}"A protein sequence belonging to the CRP family, demonstrated to be a secreted signal peptide that localizes to cell walls."){record_delimiter}
("entity"{tuple_delimiter}"CRP family"{tuple_delimiter}"science"{tuple_delimiter}"A protein family to which OsDT11 belongs, characterized by specific structural and functional properties."){record_delimiter}
("entity"{tuple_delimiter}"RFP"{tuple_delimiter}"technology"{tuple_delimiter}"Red Fluorescent Protein, used as a fusion marker to track protein localization in cells."){record_delimiter}
("entity"{tuple_delimiter}"p35S::RFP vector"{tuple_delimiter}"technology"{tuple_delimiter}"A genetic construct used for protein expression and visualization studies, containing the 35S promoter and RFP marker."){record_delimiter}
("entity"{tuple_delimiter}"NB epidermal cells"{tuple_delimiter}"nature"{tuple_delimiter}"Plant epidermal cells used as the experimental system for protein localization studies."){record_delimiter}
("entity"{tuple_delimiter}"Agrobacterium tumefaciens"{tuple_delimiter}"nature"{tuple_delimiter}"A bacteria species used for transferring genetic material into plant cells in laboratory experiments."){record_delimiter}
("relationship"{tuple_delimiter}"OsDT11"{tuple_delimiter}"CRP family"{tuple_delimiter}"OsDT11 is identified as a member of the CRP family through sequence analysis."){record_delimiter}
("relationship"{tuple_delimiter}"OsDT11"{tuple_delimiter}"RFP"{tuple_delimiter}"OsDT11 was fused to RFP to study its cellular localization."){record_delimiter}
("relationship"{tuple_delimiter}"Agrobacterium tumefaciens"{tuple_delimiter}"NB epidermal cells"{tuple_delimiter}"Agrobacterium tumefaciens was used to transfer genetic material into NB epidermal cells through a transient assay."){record_delimiter}
("relationship"{tuple_delimiter}"OsDT11"{tuple_delimiter}"NB epidermal cells"{tuple_delimiter}"OsDT11's subcellular localization was studied in NB epidermal cells, showing cell wall targeting."){record_delimiter}
("content_keywords"{tuple_delimiter}"protein localization, gene expression, cellular biology, molecular techniques"){completion_delimiter}

################
-Real Data-
################
Entity_types: {entity_types}
Text: {input_text}
################
Output:
"""


TEMPLATE_ZH: str = ""

CONTINUE_EN: str = """MANY entities and relationships were missed in the last extraction.  \
Add them below using the same format:
"""

CONTINUE_ZH: str = ""

IF_LOOP_EN: str = """It appears some entities and relationships may have still been missed.  \
Answer YES | NO if there are still entities and relationships that need to be added.
"""

IF_LOOP_ZH: str = ""

KG_EXTRACTION_PROMPT: dict = {
    "en": {
        "TEMPLATE": TEMPLATE_EN,
        "CONTINUE": CONTINUE_EN,
        "IF_LOOP": IF_LOOP_EN,
    },
    "zh": {
        "TEMPLATE": TEMPLATE_ZH,
        "CONTINUE": CONTINUE_ZH,
        "IF_LOOP": IF_LOOP_ZH,
    },
    "FORMAT": {
        "tuple_delimiter": "<|>",
        "record_delimiter": "##",
        "completion_delimiter": "<|COMPLETE|>",
        "entity_types": "concept, date, location, keyword, organization, person, event, work, nature, artificial, \
science, technology, mission, gene",
    },
}
