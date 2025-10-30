import json
from dotenv import load_dotenv

from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
# from langchain_openai import ChatOpenAI

# Load environment variables
load_dotenv()

# Load semantic descriptions
with open('semantic_descriptions.txt', 'r', encoding='utf-8') as file:
    semantic_descriptions = file.read()

# Load context summary
with open('summary.txt', 'r', encoding='utf-8') as file:
    summary = file.read()

# Load sample questions
with open('questions.txt', 'r', encoding='utf-8') as file:
    sample_questions = file.read()

terminology = semantic_descriptions
context = summary
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

# Prompt for 0-hop questions
# prompt = PromptTemplate(
#     input_variables=['context', 'terminology', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - a graph TERMINOLOGY,
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT subgraph (1 single node with all the important properties of the nodes such as Summary and Description but no incoming or outgoing relationship),

# ## Goal
# generate 3 concise, natural analyst-style questions that a human would realistically ask about the particular provided node.

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ but classify and ask only for the first node s:
# - ⟨s,*,*⟩ — general exploration of the first and only node

# Subject (s): always the FIRST node in the provided context.
# Predicate (p): a relationship type from the terminology, if used.
# Object (o): the second node.

# - Each question must be ≤ 25 words, fluent, and realistic.
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - You will receive a summary about one and only node that cotains one of the aspects of cybersecurity
# - There will be thousands of cybersecurity related nodes.
# - Ask in a way that a person will have to look through the thousand of nodes and find the most appropriate answer by matching the description of the question and detail in the summary.
# - DO NOT mention property names (like “ucocweSummary” or “ucoexDescription”) in the question itself.
# - Avoid raw IDs, URIs, or field names.
# - Avoid visiting provided links and URLs in order to generate questions. In other words, don't get into the URLs.
# - Avoid yes/no questions and multi-part phrasing.
# - Use cybersecurity reasoning naturally: exploitability, overflow, mitigation, validation, propagation, etc.

# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 3 objects.

# Each object must include:
# {
#     "question": "string",
#     "type": "<s,*,*>",
#     "first_node": "name/label of first node",
#     "used_properties_of_first_node": ["list"],
#     "context": "the context"
# }

# ---

# ## TERMINOLOGY
# {terminology}

# ---

# ## EXAMPLE QUESTIONS (style reference)
# {questions}

# ---

# ## CONTEXT
# {context}
# """)


# Prompt for 1-hop questions
# prompt = PromptTemplate(
#     input_variables=['context', 'terminology', 'questions'],
#     template="""
# You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
# from a knowledge graph.

# Given:
# - a graph TERMINOLOGY,
# - EXAMPLE QUESTIONS (style reference), and
# - a CONTEXT subgraph (2 connected nodes with properties + relationships),

# ## Goal
# generate 5 concise, natural analyst-style questions that a human would realistically ask.

# ## PolyG-style Categorization
# Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
# - ⟨s,p,*⟩ — focus on a known predicate
# - ⟨s,*,o⟩ — relation discovery between known nodes
# - ⟨s,p,o⟩ — verification of a known predicate between two nodes

# Subject (s): always the FIRST node in the provided context.
# Predicate (p): a relationship type from the terminology, if used.
# Object (o): the second node.

# ## Style & Constraints
# - Focus on the FIRST node’s analytical meaning (its description and concept).
# - Integrate the RELATIONSHIP and/or SECOND NODE’s context naturally.
# - Each question must be ≤ 25 words, fluent, and realistic.
# - DO NOT mention property names (like “ucocweSummary” or “ucoexDescription”) in the question itself.
# - Avoid raw IDs, URIs, or field names.
# - Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
# - Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
# - Avoid yes/no questions and multi-part phrasing.
# - Use cybersecurity reasoning naturally: exploitability, overflow, mitigation, validation, propagation, etc.
# - Ensure diversity in question structure — mix of ⟨s,p,*⟩, ⟨s,*,o⟩, ⟨s,p,o⟩ but no <s,*,*> structure.
# - Use node name and other properties for reasoning context.


# ## Output Format (STRICT JSON)
# Return ONLY a JSON array of 5 objects.

# Each object must include:
# {
#     "question": "string",
#     "type": "<s,p,*>|<s,*,o>|<s,p,o>",
#     "first_node": "name/label of first node",
#     "used_properties_of_first_node": ["list"],
#     "relationship": "relationship name or null",
#     "second_node": "name/label of second node or null",
#     "used_properties_of_second_node": ["list"],
#     "context": "the context"
# }

# ---

# ## TERMINOLOGY
# {terminology}

# ---

# ## EXAMPLE QUESTIONS (style reference)
# {questions}

# ---

# ## CONTEXT
# {context}
# """)

# Prompt for 2-hop questions
prompt = PromptTemplate(
    input_variables=['context', 'terminology', 'questions'],
    template="""
You are an experienced cybersecurity analyst generating high-quality, reasoning-based questions 
from a knowledge graph.

Given:
- a graph TERMINOLOGY,
- EXAMPLE QUESTIONS (style reference), and
- a CONTEXT subgraph summary (3 connected nodes with properties + 2 relationships),

## Goal
generate 5 concise, natural analyst-style questions that a human would realistically ask.

---

## PolyG-style Categorization
Treat each question as a triple ⟨s, p, o⟩ and classify by what is unknown:
- ⟨s,p,*⟩ — focus on a known predicate
- ⟨s,*,o⟩ — relation discovery between known nodes
- ⟨s,p,o⟩ — verification of a known predicate between two nodes

**Subject (s)**: always the FIRST node in the context.  
**Predicate (p)**: one or both relationship types from the terminology, if used (Rel1, Rel2).  
**Object (o)**: the FINAL node (node3).

---

## Style & Constraints
- Focus primarily on the **first node’s analytical meaning** (its name, description and concept).
- Use the **second node** and **third node** to enrich reasoning context.
- Incorporate **both relationships** naturally — the question should imply traversal or causal linkage across the chain.
- Each question must be ≤ 25 words, fluent, and realistic.
- DO NOT mention property names (like “ucocweSummary” or “ucoexDescription”).
- Avoid raw IDs, URIs, or field names.
- Do not repeat node labels (e.g., don’t say “CWE weakness” or “CAPEC attack pattern”).
- Prefer open analytical forms (“How could…?”, “What causes…?”, “Which factor connects…?”).
- Avoid yes/no and multi-part phrasing.
- Use **only <s,*,o>** question structure. 
- Every question must **require** understanding of the first and third nodes and both relationships — no single-hop reasoning.

---

## Output Format (STRICT JSON)
Return ONLY a JSON array of 5 objects.

Each object must include:
{
    "question": "string",
    "type": "<s,p,*>|<s,*,o>|<s,p,o>",
    "first_node": "name/label of first node",
    "used_properties_of_first_node": ["list"],
    "relationship_1": "name of first relationship",
    "second_node": "name/label of second node",
    "used_properties_of_second_node": ["list"],
    "relationship_2": "name of second relationship",
    "third_node": "name/label of third node",
    "used_properties_of_third_node": ["list"],
    "context": "the context"
}

---

## TERMINOLOGY
{terminology}

---

## EXAMPLE QUESTIONS (style reference)
{questions}

---

## CONTEXT
{context}
""")

# Generate questions
chain = LLMChain(llm = llm, prompt = prompt)
responses = chain.invoke(context = context, terminology = terminology, questions = questions)

print(responses)