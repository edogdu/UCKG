TEMPLATE_EN = """You are an expert at extracting information from text based on a given schema.
Extract relevant information about {field} from a given contract document according to the provided schema.

Instructions:
1. Carefully read the entire document provided at the end of this prompt.
2. Extract the relevant information.
3. Present your findings in JSON format as specified below.

Important Notes:
- Extract only relevant information.
- Consider the context of the entire document when determining relevance.
- Do not be verbose, only respond with the correct format and information.
- Some docs may have multiple relevant excerpts -- include all that apply.
- Some questions may have no relevant excerpts -- just return "".
- Do not include additional JSON keys beyond the ones listed here.
- Do not include the same key multiple times in the JSON.
- Use English for your response.

Expected JSON keys and explanation of what they are:
{schema_explanation}

Expected format:
{{
    "key1": "value1",
    "key2": "value2",
    ...
}}

{examples}

Document to extract from:
{text}
"""

TEMPLATE_ZH = ""

SCHEMA_GUIDED_EXTRACTION_PROMPT = {
    "en": TEMPLATE_EN,
    "zh": TEMPLATE_ZH,
}
