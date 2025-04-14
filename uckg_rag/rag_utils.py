import os
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
from dotenv import load_dotenv
import logging
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# Initialize ChromaDB
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

# Initialize LLM
GEN_LLM_MODEL = os.getenv("GEN_LLM_MODEL", "microsoft/phi-2")
tokenizer = AutoTokenizer.from_pretrained(GEN_LLM_MODEL)
model = AutoModelForCausalLM.from_pretrained(
    GEN_LLM_MODEL,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)

def get_relevant_context(text: str, n_results: int = 5) -> List[Dict]:
    """Get relevant context from ChromaDB"""
    try:
        results = collection.query(
            query_texts=[text],
            n_results=n_results
        )
        return [{
            'id': results['ids'][0][i],
            'document': results['documents'][0][i],
            'metadata': results['metadatas'][0][i],
            'distance': results['distances'][0][i]
        } for i in range(len(results['ids'][0]))]
    except Exception as e:
        logger.error(f"Error getting relevant context: {e}")
        return []

def generate_response(query: str, context: List[Dict], graph_context: bool = False) -> str:
    """Generate response using the LLM"""
    try:
        # Format context into structured text
        context_text = ""
        if context:
            context_text = "Relevant Information:\n"
            for idx, doc in enumerate(context, 1):
                context_text += f"{idx}. {doc['document']}\n"
        
        # Create prompt
        prompt = f"""
        Based on the following context, answer the query.
        
        Context:
        {context_text}
        
        Query: {query}
        
        Answer:
        """
        
        # Generate response
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=0.7,
            top_p=0.9,
            do_sample=True
        )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response.split("Answer:")[-1].strip()
        
    except Exception as e:
        logger.error(f"Error generating response: {e}")
        return f"Error generating response: {e}" 