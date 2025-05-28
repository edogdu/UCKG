import json
import pandas as pd
from typing import Dict, List, Optional
import logging
from datetime import datetime
from pathlib import Path
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from rag_utils import get_relevant_context, generate_response, get_graph_context
from model_registry import ModelRegistry
import re
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

# Initialize ChromaDB with persistence
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j driver
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def truncate_to_n_sentences(text: str, n: int = 2) -> str:
    # Look behind for sentence boundaries, then look ahead for a space followed by a capital letter.
    # This is a hard guardrail to get the first n (2 by default) sentences of the text.
    sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text.strip())
    return ' '.join(sentences[:n])

class ModelEvaluator:
    def __init__(self, csv_path: str = "Full_Gold_Standard_RAG_Evaluation_Set.csv", model_registry: ModelRegistry = None):
        # Initialize the model registry
        self.model_registry = model_registry
        # Initialize the embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        # Load the test cases from the CSV file
        self.test_cases = self._load_test_cases_from_csv(csv_path)
        # Create the results directory
        self.results_dir = Path("evaluation_results")
        self.results_dir.mkdir(exist_ok=True)

    def _load_test_cases_from_csv(self, path: str) -> List[Dict]:
        # Load test cases from CSV file
        try:
            df = pd.read_csv(path)
            # ERROR HANDLING: If the CSV file is not found, raise an error
        except FileNotFoundError:
            raise FileNotFoundError(f"CSV file not found at path: {path}")
        # Convert the DataFrame to a list of dictionaries
        return df.to_dict(orient="records")

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        # Calculate semantic similarity between two texts
        embeddings = self.embedding_model.encode([text1, text2])
        # Cosine similarity is a measure of the cosine of the angle between two vectors.
        # It ranges from -1 to 1, where 1 indicates the vectors are identical, -1 indicates they are opposite, and 0 indicates no correlation.
        return cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]

    def evaluate_model(self, model_name: str, test_cases: Optional[List[Dict]] = None, use_rag: bool = False, nearest_neighbors: int = 3) -> Dict:
        # Evaluate a model on test cases, optionally using RAG context
        test_cases = test_cases or self.test_cases
        results = []

        for case in test_cases:
            # Initialize the graph context and semantic context
            graph_context = []
            context = []
            # If RAG is used, get the graph context
            if use_rag:
                graph_context = get_graph_context(case["Question"], driver, nearest_neighbors)
            # If RAG is used and no graph context is found, get the semantic context
            if use_rag and graph_context is None:
                logger.warning(f"No graph context found for question: {case['Question']} \n Getting semantic context instead...")
                context = get_relevant_context(case["Question"], n_results=nearest_neighbors)
            
            response = generate_response(
                query=case["Question"],
                context=context,
                model_name=model_name,
                graph_context=graph_context,
                model_registry=self.model_registry
            )
            # Truncate the response to 2 sentences
            response = truncate_to_n_sentences(response, n=2)
            # Calculate the similarity between the response and the expected answer
            similarity = self._calculate_similarity(response, case["Gold_Answer"])
            # Append the results to the list
            results.append({
                "question": case["Question"],
                "expected_answer": case["Gold_Answer"],
                "model_response": response,
                "similarity_score": float(similarity),
                "used_rag": use_rag,
                "nearest_neighbors": nearest_neighbors if use_rag else None
            })

        return {
            "model": model_name,
            "use_rag": use_rag,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "average_similarity": float(np.mean([r["similarity_score"] for r in results]))
        }

    def generate_report(self, results: Dict) -> str:
        # Generate a human-readable evaluation report
        report = ["Model Evaluation Report", "=" * 20, ""]
        # Iterate through the results
        for model_key, model_results in results.items():
            # Append the model name and average similarity score to the report
            report.extend([
                # Append the model name and average similarity score to the report
                f"Model: {model_key}",
                f"Average Similarity Score: {model_results['average_similarity']:.4f}",
                ""
            ])
            # Enumerate is used to get the index and the result
            # The enumerate function returns a tuple containing the index and the value
            # The index is used to number the test cases
            # The case is the result for the given test case
            for idx, case in enumerate(model_results["results"], 1):
                report.extend([
                    f"Test Case {idx}:",
                    f"Question: {case['question']}",
                    f"Expected Answer: {case['expected_answer']}",
                    f"Model Response: {case['model_response']}",
                    f"Similarity Score: {case['similarity_score']:.4f}",
                    f"Used RAG: {case['used_rag']}",
                    ""
                ])

        return "\n".join(report)