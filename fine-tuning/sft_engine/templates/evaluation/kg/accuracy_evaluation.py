ENTITY_EVALUATION_PROMPT_ZH = ""

ENTITY_EVALUATION_PROMPT_EN = """You are a Knowledge Graph Quality Assessment Expert. \
Your task is to evaluate the quality of entity extraction from a given text block and extracted entity list.

Evaluation Dimensions:
1. ACCURACY (Weight: 40%): Whether the extracted entities actually exist in the text, and if there are any false extractions (False Positives)
   - Check: Do entities actually appear in the text? Are non-entity phrases incorrectly identified as entities?
   - Example: Text mentions "Protein A", but "Protein B" (not in text) is extracted → Low accuracy
   - Example: Phrases like "research shows" are extracted as entities → Low accuracy

2. COMPLETENESS (Weight: 40%): Whether important entities from the text are missing (Recall, False Negatives)
   - Check: Are all important entities from the text extracted? Are there any omissions?
   - Example: Text mentions 5 important proteins, but only 3 are extracted → Low completeness
   - Example: All key entities are extracted → High completeness

3. PRECISION (Weight: 20%): Whether extracted entities are precisely named, have correct boundaries, and correct types
   - Check: Are entity names complete and accurate? Are boundaries correct? Are entity types correctly classified?
   - Example: Should extract "Human Insulin Receptor Protein", but only "Insulin" is extracted → Low precision (incorrect boundary)
   - Example: Should be classified as "Protein", but classified as "Gene" → Low precision (incorrect type)
   - Example: Should extract "COVID-19", but "Coronavirus" is extracted → Low precision (naming not precise enough)

Scoring Criteria (0-1 scale for each dimension):
- EXCELLENT (0.8-1.0): High-quality extraction, error rate < 20%
- GOOD (0.6-0.79): Good quality with minor issues, error rate 20-40%
- ACCEPTABLE (0.4-0.59): Acceptable with noticeable issues, error rate 40-60%
- POOR (0.0-0.39): Poor quality, needs improvement, error rate > 60%

Overall Score = 0.4 × Accuracy + 0.4 × Completeness + 0.2 × Precision

Please evaluate the following:

Original Text Block:
{chunk_content}

Extracted Entity List:
{extracted_entities}

Please return the evaluation result in JSON format:
{{
    "accuracy": <float between 0-1>,
    "completeness": <float between 0-1>,
    "precision": <float between 0-1>,
    "overall_score": <overall score>,
    "accuracy_reasoning": "<reasoning for accuracy assessment>",
    "completeness_reasoning": "<reasoning for completeness assessment, including important missing entities>",
    "precision_reasoning": "<reasoning for precision assessment>",
    "issues": ["<list of identified issues>"]
}}
"""

RELATION_EVALUATION_PROMPT_ZH = ""

RELATION_EVALUATION_PROMPT_EN = """You are a Knowledge Graph Quality Assessment Expert. \
Your task is to evaluate the quality of relation extraction from a given text block and extracted relation list.

Evaluation Dimensions:
1. ACCURACY (Weight: 40%): Whether the extracted relations actually exist in the text, and if there are any false extractions (False Positives)
   - Check: Do relations actually appear in the text? Are non-existent relations incorrectly identified?
   - Example: Text shows no relation between A and B, but "A-acts_on->B" is extracted → Low accuracy
   - Example: A parallel relationship in text is misidentified as a causal relationship → Low accuracy

2. COMPLETENESS (Weight: 40%): Whether important relations from the text are missing (Recall, False Negatives)
   - Check: Are all important relations expressed in the text extracted? Are there any omissions?
   - Example: Text explicitly expresses 5 relations, but only 3 are extracted → Low completeness
   - Example: All key relations are extracted → High completeness

3. PRECISION (Weight: 20%): Whether relation descriptions are precise, relation types are correct, and not overly broad
   - Check: Are relation types accurate? Are relation descriptions specific? Are overly broad relation types used?
   - Example: Should extract "inhibits" relation, but "affects" is extracted → Low precision (type not precise enough)
   - Example: Should extract "directly binds", but "related" is extracted → Low precision (description too broad)
   - Example: Is relation direction correct (e.g., "A activates B" vs "B is activated by A") → Precision check

Scoring Criteria (0-1 scale for each dimension):
- EXCELLENT (0.8-1.0): High-quality extraction, error rate < 20%
- GOOD (0.6-0.79): Good quality with minor issues, error rate 20-40%
- ACCEPTABLE (0.4-0.59): Acceptable with noticeable issues, error rate 40-60%
- POOR (0.0-0.39): Poor quality, needs improvement, error rate > 60%

Overall Score = 0.4 × Accuracy + 0.4 × Completeness + 0.2 × Precision

Please evaluate the following:

Original Text Block:
{chunk_content}

Extracted Relation List:
{extracted_relations}

Please return the evaluation result in JSON format:
{{
    "accuracy": <float between 0-1>,
    "completeness": <float between 0-1>,
    "precision": <float between 0-1>,
    "overall_score": <overall score>,
    "accuracy_reasoning": "<reasoning for accuracy assessment>",
    "completeness_reasoning": "<reasoning for completeness assessment, including important missing relations>",
    "precision_reasoning": "<reasoning for precision assessment>",
    "issues": ["<list of identified issues>"]
}}
"""

ACCURACY_EVALUATION_PROMPT = {
    "zh": {
        "ENTITY": ENTITY_EVALUATION_PROMPT_ZH,
        "RELATION": RELATION_EVALUATION_PROMPT_ZH,
    },
    "en": {
        "ENTITY": ENTITY_EVALUATION_PROMPT_EN,
        "RELATION": RELATION_EVALUATION_PROMPT_EN,
    },
}
