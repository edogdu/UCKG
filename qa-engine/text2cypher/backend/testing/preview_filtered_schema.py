import os
import pathlib
import sys

# Ensure backend on path
BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from llm import OllamaLLM
from t2css_integration import create_enhanced_text2cypher


def preview(question: str, top_k: int = 10):
    os.environ["USE_T2CSS"] = "true"
    os.environ["T2CSS_TOP_K"] = str(top_k)

    # Neo4j config
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    llm = OllamaLLM()
    t2c = create_enhanced_text2cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm, use_t2css=True, top_k_schema=top_k)

    # Run only the filtering piece
    # Ensure pipeline is initialized
    if t2c.t2css_pipeline is None:
        t2c._initialize_t2css()

    triples = t2c.t2css_pipeline.filter_schema_by_similarity(question)

    print("="*80)
    print(f"QUESTION: {question}")
    print("="*80)
    print(f"Top-{top_k} schema triples selected:\n")
    for i, tr in enumerate(triples, 1):
        # Show structured view
        print(f"{i}. {tr.subject} -[{tr.predicate}]-> {tr.object}")
        if tr.properties:
            print(f"   Properties (sample): {', '.join(tr.properties[:5])}")
        print(f"   Description: {tr.semantic_description}")
        print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Preview filtered schema subgraph for a question")
    parser.add_argument("question", type=str, help="Natural language question")
    parser.add_argument("--top_k", type=int, default=10)
    args = parser.parse_args()
    preview(args.question, args.top_k)

