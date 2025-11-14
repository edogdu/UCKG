import json
import re
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
# from langchain_openai import ChatOpenAI

# Load environment variables
load_dotenv()



# Load context summary
with open('subgraph_description.txt', 'r', encoding='utf-8') as file:
    subgraph_description = file.read()

# Load sample questions
with open('questions.txt', 'r', encoding='utf-8') as file:
    sample_questions = file.read()

context = subgraph_description
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
    model='gemma3:12b',  # You can change this to other models
    temperature=0.7
)

# Prompt for 0-hop questions
# prompt = PromptTemplate(
#     input_variables=['context', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT that contains:
#   * Schema definitions: The node type schemas (e.g., UcoCWE, UcoexCAPEC, UcoexObservedExample) with their property definitions
#   * Semantic descriptions: Template sentences used to generate descriptions for each node type (showing how properties are described)
#   * Actual description: The specific subgraph description (1 node with properties) generated using the schema and semantic templates

# ## Goal
# generate 5 concise, natural analyst-style questions that a human would realistically ask.

# ---

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ but classify and ask only for the first node s:
# - ⟨s,*,*⟩ — general exploration of the first and only node

# Subject (s): always the FIRST node in the provided context.

# - Each question must be ≤ 15 words, fluent, and realistic.
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Include the natural language name of the node in the question.
# - Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Avoid yes/no and multi-part phrasing..


# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 5 objects.

# Each object must include:
# {{
#     "question": "string",
#     "type": "<s,*,*>", (do not change this)
#     "first_node": "URI of the first node starting with http",
#     "context": "the description in the context without the schema definitions and semantic descriptions"
# }}

# ---

# ## EXAMPLE QUESTIONS (style reference)
# {questions}
# ---

# ## CONTEXT
# {context}
# """)

# Prompt for 1-hop questions
# prompt = PromptTemplate(
#     input_variables=['context', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT that contains:
#   * Schema definitions: The node type schemas (e.g., UcoCWE, UcoexCAPEC, UcoexObservedExample) with their property definitions
#   * Semantic descriptions: Template sentences used to generate descriptions for each node type (showing how properties are described)
#   * Relationship definitions: The relationship types and their semantic meanings (e.g., UCOEXHASRELATEDWEAKNESS, UCOHASOBSERVEDEXAMPLE)
#   * Actual description: The specific subgraph description (2 connected nodes with properties + 1 relationship) generated using the schema and semantic templates

# ## Goal
# generate 5 concise, natural analyst-style questions that a human would realistically ask.

# ---

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
# - ⟨s,p,*⟩ — focus on a known predicate
# - ⟨s,*,o⟩ — relation discovery between known nodes
# - ⟨s,p,o⟩ — verification of a known predicate between two nodes

# Subject (s): always the FIRST node in the provided context.
# Predicate (p): a relationship type from the terminology, if used.
# Object (o): the second node.

# ## Style & Constraints
# - Focus on the FIRST node's content mentioned in the context (e.g., CWE, CAPEC, CVE, etc.).
# - Integrate the RELATIONSHIP and/or SECOND node's context naturally.
# - Each question must be ≤ 15 words, fluent, and realistic.
# - Avoid raw IDs or URIs.
# - Include the natural language name of the node in the question.
# - Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Avoid yes/no and multi-part phrasing.
# - Every question must **require** understanding of the first node and the relationship between the first and second node.


# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 5 objects.

# Each object must include:
# {{
#     "question": "string",
#     "type": "<s,p,*>|<s,*,o>|<s,p,o>",
#     "first_node": "URI of the first node starting with http",
#     "relationship": "relationship name or null",
#     "second_node": "URI of the second node starting with http or null",
#     "context": "the description in the context without the schema definitions, semantic descriptions, and relationship definitions"
# }}


# ## EXAMPLE QUESTIONS (style reference)
# {questions}

# ---

# ## CONTEXT
# {context}
# """)

# Prompt for 2-hop questions ⟨s,*,o⟩
prompt = PromptTemplate(
    input_variables=['context', 'questions'],
    template="""
You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
from a knowledge graph.

Given:
- EXAMPLE QUESTIONS (style reference), and
- a CONTEXT that contains:
  * Schema definitions: The node type schemas (e.g., UcoCWE, UcoexCAPEC, UcoexObservedExample) with their property definitions
  * Semantic descriptions: Template sentences used to generate descriptions for each node type (showing how properties are described)
  * Relationship definitions: The relationship types and their semantic meanings (e.g., UCOEXHASRELATEDWEAKNESS, UCOHASOBSERVEDEXAMPLE)
  * Actual description: The specific subgraph description (3 connected nodes with properties + 2 relationships) generated using the schema and semantic templates

## Goal
generate 5 concise, natural analyst-style questions that a human would realistically ask.

---

## PolyG-style Categorization
Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
- ⟨s,*,o⟩ — relation discovery between known nodes

**Subject (s)**: always the FIRST node in the context.  
**Predicate (*)**: unknown relationship types from the terminology, if used (Rel1, Rel2).  
**Object (o)**: the FINAL node (node3).

---

## Style & Constraints
- Focus primarily on the **first node's content** mentioned in the context (e.g., CWE, CAPEC, CVE, etc.).
- Use the **third node's content** to enrich reasoning context.
- Incorporate **both relationships** naturally — the question should imply traversal or causal linkage across the chain.
- Each question must be ≤ 15 words, fluent, and realistic.
- Avoid raw IDs or URIs.
- Include the natural language name of the node in the question.
- Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
- Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
- Avoid yes/no and multi-part phrasing.
- Every question must **require** understanding of the first and third elements and both relationships — no single-hop reasoning.

---

## Output Format (STRICT JSON)
Return ONLY a JSON array of 5 objects.

Each object must include:
{{
    "question": "string",
    "type": "<s,*,o>", (do not change this)
    "first_node": "URI of the first node starting with http",
    "relationship_1": "name of first relationship",
    "second_node": "URI of the second node starting with http",
    "relationship_2": "name of second relationship",
    "third_node": "URI of the third node starting with http",
    "context": "the description in the context without the schema definitions, semantic descriptions, relationship definitions"
}}

---


## EXAMPLE QUESTIONS (style reference)
{questions}

---

## CONTEXT
{context}
""")

# Prompt for 2-hop questions ⟨s,p,*⟩
# prompt = PromptTemplate(
#     input_variables=['context', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT that contains:
#   * Schema definitions: The node type schemas (e.g., UcoCWE, UcoexCAPEC, UcoexObservedExample) with their property definitions
#   * Semantic descriptions: Template sentences used to generate descriptions for each node type (showing how properties are described)
#   * Relationship definitions: The relationship types and their semantic meanings (e.g., UCOEXHASRELATEDWEAKNESS, UCOHASOBSERVEDEXAMPLE)
#   * Actual description: The specific subgraph description (3 connected nodes with properties + 2 relationships) generated using the schema and semantic templates

# ## Goal
# generate 5 concise, natural analyst-style questions that a human would realistically ask.

# ---

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
# - ⟨s,p,*⟩ — focus on a known predicate

# **Subject (s)**: always the FIRST node in the context.  
# **Predicate (p)**: known relationship types from the terminology, if used (Rel1, Rel2).  
# **Object (*)**: unknown target — inferred through reasoning.

# ---

# ## Style & Constraints
# - Focus primarily on the **first node's content** mentioned in the context (e.g., CWE, CAPEC, CVE, etc.).
# - Incorporate **both relationships** naturally — the question should imply traversal or causal linkage across the chain.
# - Each question must be ≤ 15 words, fluent, and realistic.
# - Avoid raw IDs or URIs.
# - Include the natural language name of the node in the question.
# - Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Avoid yes/no and multi-part phrasing.

# ---

# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 5 objects.

# Each object must include:
# {{
#     "question": "string",
#     "type": "<s,p,*>", (do not change this)
#     "first_node": "URI of the first node starting with http",
#     "relationship_1": "name of first relationship",
#     "second_node": "URI of the second node starting with http",
#     "relationship_2": "name of second relationship",
#     "third_node": "URI of the third node starting with http" or null,
#     "context": "the description in the context without the schema definitions, semantic descriptions, relationship definitions"
# }}

# ---


# ## EXAMPLE QUESTIONS (style reference)
# {questions}

# ---

# ## CONTEXT
# {context}
# """)

# Prompt for 2-hop questions ⟨s,p,o⟩
# prompt = PromptTemplate(
#     input_variables=['context', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT that contains:
#   * Schema definitions: The node type schemas (e.g., UcoCWE, UcoexCAPEC, UcoexObservedExample) with their property definitions
#   * Semantic descriptions: Template sentences used to generate descriptions for each node type (showing how properties are described)
#   * Relationship definitions: The relationship types and their semantic meanings (e.g., UCOEXHASRELATEDWEAKNESS, UCOHASOBSERVEDEXAMPLE)
#   * Actual description: The specific subgraph description (3 connected nodes with properties + 2 relationships) generated using the schema and semantic templates

# ## Goal
# generate 5 concise, natural analyst-style questions that a human would realistically ask.

# ---

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
# - ⟨s,p,o⟩ — verification of a known predicate between two nodes

# **Subject (s)**: always the FIRST node in the context.  
# **Predicate (p)**: one or both relationship types from the terminology, if used (Rel1, Rel2).  
# **Object (o)**: the FINAL node (node3).

# ---

# ## Style & Constraints
# - Focus primarily on the **first node's content** mentioned in the context (e.g., CWE, CAPEC, CVE, etc.).
# - Use the **third node's content** to enrich reasoning context.
# - Incorporate **both relationships** naturally — the question should imply traversal or causal linkage across the chain.
# - Each question must be ≤ 15 words, fluent, and realistic.
# - Avoid raw IDs or URIs.
# - Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Avoid yes/no and multi-part phrasing.

# ---

# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 5 objects.

# Each object must include:
# {{
#     "question": "string",
#     "type": "<s,p,o>", (do not change this)
#     "first_node": "URI of the first node starting with http",
#     "relationship_1": "name of first relationship",
#     "second_node": "URI of the second node starting with http",
#     "relationship_2": "name of second relationship",
#     "third_node": "URI of the third node starting with http",
#     "context": "the description in the context without the schema definitions, semantic descriptions, relationship definitions"
# }


# ## EXAMPLE QUESTIONS (style reference)
# {questions}

# ---

# ## CONTEXT
# {context}
# """)

# Generate questions
chain = prompt | llm
response = chain.invoke({"context": context, "questions": questions})

# Extract content from the response (it's a message object)
response_text = response.content if hasattr(response, 'content') else str(response)

# Parse the JSON response
try:
    questions_data = json.loads(response_text)
except json.JSONDecodeError:
    # If the response isn't valid JSON, try to extract JSON from the text
    json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
    if json_match:
        questions_data = json.loads(json_match.group())
    else:
        # If no JSON found, wrap the response in a structure
        questions_data = {"raw_response": response_text}
        print("Warning: Could not parse JSON from response. Saving raw response.")

# Save to JSON file
with open('generated_questions.json', 'w', encoding='utf-8') as f:
    json.dump(questions_data, f, indent=2, ensure_ascii=False)

print(f"Questions generated")