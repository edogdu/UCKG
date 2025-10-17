import os
import sys
import pathlib

# Ensure backend on path
BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from llm import OllamaLLM
from t2css_integration import create_enhanced_text2cypher
from text2cypher import extract_cypher
from config import FEW_SHOT_EXAMPLES


def generate(question: str, top_k: int = 10):
    # Force filtered mode
    os.environ["USE_T2CSS"] = "true"
    os.environ["T2CSS_TOP_K"] = str(top_k)

    # Neo4j config (not used for prompt generation; needed for class init)
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    llm = OllamaLLM()
    t2c = create_enhanced_text2cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm, use_t2css=True, top_k_schema=top_k)

    # Load schema (filtered inside _build_prompt)
    schema_text = t2c.get_schema()

    # Build prompt and invoke LLM directly (bypass validation to just view generated Cypher)
    prompt = t2c._build_prompt(question=question, schema_block=schema_text, examples=FEW_SHOT_EXAMPLES)
    llm_output = llm.invoke(prompt)
    cypher = extract_cypher(llm_output)

    print("=" * 80)
    print(f"QUESTION: {question}")
    print("=" * 80)
    print("GENERATED CYPHER (raw, may be invalid):\n")
    print(cypher)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Cypher once (filtered mode) for a question")
    parser.add_argument("question", type=str)
    parser.add_argument("--top_k", type=int, default=10)
    args = parser.parse_args()
    generate(args.question, args.top_k)

