import json
from dotenv import load_dotenv

from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

# Load environment variables
load_dotenv()

with open('../schema_cache.txt', 'r', encoding='utf-8') as file:
    schema_cache = file.read()

# Load JSON data
with open('nodes.json', 'r', encoding='utf-8') as file:
    json_data = json.load(file)

with open('questions.txt', 'r', encoding='utf-8') as file:
    sample_questions = file.read()

schema = schema_cache
context = json_data
questions = sample_questions

# Initialize LLM with local Ollama Llama model
llm = ChatOllama(
    model='llama3.2',  # You can change this to llama2, llama3, or other models you have installed
    temperature=0.7
)

prompt = PromptTemplate(
    input_variables=['context', 'schema', 'questions'],
    template=r"""
You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions from a knowledge graph (CVE, CWE, CAPEC, ATT&CK, Mitigations, CPE, Groups, Campaigns, Software, Vulnerabilities).

## Goal
Given the graph **SCHEMA**, **EXAMPLE QUESTIONS** (style guide), and a **CONTEXT** subgraph (2 connected nodes with properties + relationships), generate **5 concise, natural analyst-style questions** that a human would actually ask.

## PolyG-style categorization (choose any one of the following except for ⟨s,*,*⟩)
Treat each question as a triple ⟨s, p, o⟩ and classify by what's unknown:
- ⟨s,*,*⟩  (entity-centric exploration; general about subject s)
- ⟨s,p,*⟩  (focused aspect; predicate p known, object o unknown)
- ⟨s,*,o⟩  (relation discovery; s and o known, predicate unknown)
- ⟨s,p,o⟩  (verification; specific relation p between s and o)

**Subject (s):** always the FIRST node in the provided context.
**Predicate (p):** a relationship type from the schema if used.
**Object (o):** the second node.

## Style & Constraints
- Use the **FIRST node’s properties** as the main analytical focus.
- Integrate the **relationship type** and/or the **second node’s context** for meaningful reasoning.
- Keep each question **≤ 25 words**, fluent, and realistic.
- Do **not** copy raw URIs, IDs, or overly technical field names.
- Avoid repeating or using the node label (e.g., "CWE weakness" or "CAPEC attack pattern") when the concept is already clear from context. Use natural phrasing like "weakness," "technique," or "attack" instead.
- Avoid **yes/no-style questions** (e.g., "Does X lead to Y?"); prefer open analytical forms like "How could X lead to Y?" or "Which factor enables X?"
- Avoid **overly detailed or specific property mentions** (e.g., quoting headers, field resets) unless essential to clarity.
- Aim for **simplicity and clarity** — each question should be understandable by a human analyst in one read.
- Ensure diversity in question structure (<s,p,*>, <s,*,o>, <s,p,o>).
- Prefer analytical, investigative forms like:
  - "How could [CWE.ucocweName] lead to [CVE.label]?"
  - "Which mitigations reduce the risk from [ATTACK.ucoexNAME]?"
  - "Through what path is [CAPEC.ucoexCAPEC_name] linked to [ATTACK.ucoexNAME]?"
  - "Which weakness enables [ATTACK.ucoexNAME]?"
- Avoid multi-part or list-style questions.
- Ensure diversity across the 5 generated questions.
- Ground your wording in **real cybersecurity reasoning**, using available properties such as severity, impact, exploitability, description, and likelihood.

## Output format (STRICT JSON)
Return ONLY a JSON array of 5 objects, no prose.
Each object must have:
- "question": string
- "type": one of "<s,p,*>", "<s,*,o>", "<s,p,o>"
- "first_node": label/type of the first node (e.g., "UcoCVE", "UcoCWE", "UcoexMITREATTACK")
- "used_properties": list of properties used from the first node (e.g., ["ucoexDESCRIPTION", "ucoexNAME"])
- "relationship": relationship name if applicable, else null (e.g., "UCOEXHASTAXONOMYMAPPING")
- "second_node": label/type of the second node if used, else null
- "used_properties": list of properties used from the second node (e.g., ["ucoexNAME"])

Example:
[
    {
        "question": "Which mitigations most directly reduce credential dumping via the noted technique?",
        "type": "<s,p,*>",
        "first_node": "UcoexMITREATTACK",
        "used_properties_of_first_node": ["ucoexDESCRIPTION"],
        "relationship": "UCOEXMITIGATES",
        "second_node": "UcoexMITIGATIONS",
        "used_properties_of_second_node": ["ucoexNAME"]
    },
    ...
]

## SCHEMA (reference for labels, properties, relationships)
{schema}

## EXAMPLE QUESTIONS (style & tone to emulate; do not copy text)
{questions}

## CONTEXT (nodes with properties and relationships; the FIRST node is the subject s)
{context}

### Now produce the JSON array of 5 objects per the Output format.
""")


# Generate questions
chain = LLMChain(llm = llm, prompt = prompt)
responses = chain.invoke(context = context, schema = schema)

print(responses)