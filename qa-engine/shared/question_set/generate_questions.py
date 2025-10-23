import json
from dotenv import load_dotenv

from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
# from langchain_openai import ChatOpenAI

# Load environment variables
load_dotenv()

# Load schema
with open('../schema_cache.txt', 'r', encoding='utf-8') as file:
    schema_cache = file.read()

# Load JSON data
with open('nodes.json', 'r', encoding='utf-8') as file:
    json_data = json.load(file)

# Load sample questions
with open('questions.txt', 'r', encoding='utf-8') as file:
    sample_questions = file.read()

schema = schema_cache
context = json_data
questions = sample_questions

# # API key for OpenAI
# api_key = "<your_openai_api_key>"

# # Initialize LLM with OpenAI API key
# llm = ChatOpenAI(
#     openai_api_key=api_key,
#     model='gpt-5',
#     temperature=0.7
# )

# Initialize LLM with local Ollama Llama model
llm = ChatOllama(
    model='gpt-oss:120b',  # You can change this to other models
    temperature=0.7
)

# Prompt for 1-hop questions
prompt = PromptTemplate(
    input_variables=['context', 'schema', 'questions'],
    template="""
You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
from a knowledge graph (CVE, CWE, CAPEC, ATT&CK, Mitigations, CPE, Groups, Campaigns, Software, Vulnerabilities).

## Goal
Given:
- a graph SCHEMA,
- EXAMPLE QUESTIONS (style reference), and
- a CONTEXT subgraph (2 connected nodes with properties + relationships),

generate 5 concise, natural analyst-style questions that a human would realistically ask.

## PolyG-style Categorization
Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
- ⟨s,*,*⟩ — general exploration of the first node
- ⟨s,p,*⟩ — focus on a known predicate
- ⟨s,*,o⟩ — relation discovery between known nodes
- ⟨s,p,o⟩ — verification of a known predicate between two nodes

Subject (s): always the FIRST node in the provided context.
Predicate (p): a relationship type from the schema, if used.
Object (o): the second node.

## Style & Constraints
- Focus on the FIRST node’s analytical meaning (its description and concept).
- Integrate the RELATIONSHIP and/or SECOND NODE’s context naturally.
- Each question must be ≤ 25 words, fluent, and realistic.
- DO NOT mention property names (like “ucocweSummary” or “ucoexDescription”) in the question itself.
- Avoid raw IDs, URIs, or field names.
- Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
- Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
- Avoid yes/no questions and multi-part phrasing.
- Use cybersecurity reasoning naturally: exploitability, overflow, mitigation, validation, propagation, etc.
- Ensure diversity in question structure — mix of ⟨s,p,*⟩, ⟨s,*,o⟩, ⟨s,p,o⟩.
- Use only the following node properties for reasoning context:
    - CWE: ucocweSummary, ucocweExtendedSummary, ucocweName
    - CAPEC: label, ucoexDescription


## Output Format (STRICT JSON)
Return ONLY a JSON array of 5 objects.

Each object must include:
{
    "question": "string",
    "type": "<s,p,*>|<s,*,o>|<s,p,o>",
    "first_node": "label/type of first node",
    "used_properties_of_first_node": ["list"],
    "relationship": "relationship name or null",
    "second_node": "label/type of second node or null",
    "used_properties_of_second_node": ["list"]
}

---

## SCHEMA
{schema}

## EXAMPLE QUESTIONS
{questions}

## CONTEXT
{context}
""")

# Generate questions
chain = LLMChain(llm = llm, prompt = prompt)
responses = chain.invoke(context = context, schema = schema, questions = questions)

print(responses)