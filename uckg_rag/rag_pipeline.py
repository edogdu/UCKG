# rag_pipeline.py (patched with semantic-rich multi-hop expansion)

import os
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from neo4j import GraphDatabase
from dotenv import load_dotenv
import logging
from shared_state import SharedState
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")
CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
GEN_LLM_MODEL = os.getenv("GEN_LLM_MODEL", "microsoft/phi-2")

# Initialize FastAPI app
app = FastAPI(title="UCKG RAG Service")

# Initialize shared state
shared_state = SharedState()

# Initialize ChromaDB with persistence
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection("uckg", embedding_function=SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL))

# Initialize Neo4j driver
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

# Initialize LLM
logger.info(f"Loading LLM model: {GEN_LLM_MODEL}")
model_name = GEN_LLM_MODEL
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Log CUDA availability and device info
logger.info(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    logger.info(f"CUDA device count: {torch.cuda.device_count()}")
    logger.info(f"Current CUDA device: {torch.cuda.current_device()}")
    logger.info(f"CUDA device name: {torch.cuda.get_device_name()}")

# Load model with more robust device handling
try:
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )
except Exception as e:
    logger.warning(f"Failed to load model with device_map='auto': {str(e)}")
    logger.info("Attempting to load model without device mapping...")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        trust_remote_code=True
    )

# Log model device and dtype after loading
logger.info(f"Model device after loading: {model.device}")
logger.info(f"Model dtype: {model.dtype}")

# Try to get device map info safely
try:
    if hasattr(model.config, 'device_map'):
        logger.info(f"Model config device_map: {model.config.device_map}")
    else:
        logger.info("Model config does not have device_map attribute")
except Exception as e:
    logger.warning(f"Could not access device_map from config: {str(e)}")

# Set padding token if not set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
    model.config.pad_token_id = model.config.eos_token_id

# Configure tokenizer to handle padding properly
tokenizer.padding_side = 'left'
tokenizer.truncation_side = 'left'

@app.get("/")
async def root():
    """Root endpoint with service information and usage instructions"""
    return {
        "status": "running",
        "service": "UCKG RAG Service",
        "endpoints": {
            "/": "This help message",
            "/health": "Service health and embedding progress",
            "/query": "Query the knowledge graph"
        },
        "usage": {
            "query_endpoint": {
                "url": "/query",
                "method": "POST",
                "example_request": {
                    "query": "What is CVE-2023-1234?",
                    "graph_context": True  # Optional: Include related nodes in the response
                },
                "graph_context": {
                    "description": "When set to true, includes related nodes up to 3 hops away in the response",
                    "example": "For a CVE, this will include related CWEs, attack patterns, and other connected vulnerabilities"
                }
            }
        }
    }

class QueryRequest(BaseModel):
    query: str
    graph_context: bool = False

class QueryResponse(BaseModel):
    response: str
    source_node: Optional[Dict] = None
    context: Optional[List[Dict]] = None
    embedding_progress: Dict
    graph_expansion: Optional[str] = None

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "embedding_progress": shared_state.get_progress()}

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process a query and return a response."""
    try:
        # Get relevant context
        context = get_relevant_context(request.query)
        
        # Log context retrieval
        logger.info(f"Retrieved context count: {len(context)}")
        
        # If no context found, try to get graph context directly
        if not context and request.graph_context:
            logger.info("No semantic context found, trying graph context")
            # Try to find the node directly in Neo4j
            query = """
            MATCH (n)
            WHERE n.ucodescription CONTAINS $query
               OR n.ucosummary CONTAINS $query
               OR n.ucocweSummary CONTAINS $query
            RETURN n.uri AS uri,
                   coalesce(n.ucosummary, n.ucocweSummary, n.ucodescription) AS text
            LIMIT 1
            """
            with driver.session() as session:
                result = session.run(query, query=request.query)
                record = result.single()
                if record:
                    context = [{
                        'id': record['uri'],
                        'document': record['text'],
                        'metadata': {'type': 'vulnerability'},
                        'distance': 0.0
                    }]
                    logger.info("Found context through direct Neo4j query")
        
        # Get embedding progress
        progress = shared_state.get_progress()
        
        # Generate response
        response = generate_response(request.query, context, request.graph_context)
        
        # Log response generation
        logger.info(f"Generated response: {response}")
        
        return {
            "response": response,
            "source_node": {"uri": context[0]['id']} if context else None,
            "context": context,
            "embedding_progress": progress,
            "graph_expansion": get_graph_context(context[0]['id']) if context and request.graph_context else None
        }
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        return {
            "response": f"Error processing query: {str(e)}",
            "source_node": None,
            "context": [],
            "embedding_progress": shared_state.get_progress(),
            "graph_expansion": None
        }

def get_embedding_progress():
    """Get the current embedding progress"""
    return shared_state.get_progress()

async def get_graph_context(uri: str) -> Optional[str]:
    """Get graph context from Neo4j for a given URI."""
    try:
        # First, get the source node using the uri index
        query = """
        MATCH (v)
        WHERE v.uri = $uri
        CALL {
            WITH v
            // Use full-text indexes for better performance
            CALL db.index.fulltext.queryNodes("summary_ft_index", v.ucodescription) YIELD node, score
            WHERE score > 0.5
            RETURN node.uri AS uri, 
                   labels(node)[0] AS label, 
                   coalesce(node.ucosummary, node.ucocweSummary, node.ucodescription) AS summary,
                   score AS relevance
            UNION
            // Also get directly connected nodes
            MATCH (v)-[rel:*1..3]-(n)
            WHERE n.ucosummary IS NOT NULL 
               OR n.ucocweSummary IS NOT NULL 
               OR n.ucodescription IS NOT NULL
            RETURN DISTINCT n.uri AS uri, 
                   labels(n)[0] AS label, 
                   coalesce(n.ucosummary, n.ucocweSummary, n.ucodescription) AS summary,
                   1.0 AS relevance
        }
        WITH uri, label, summary, relevance
        ORDER BY relevance DESC
        LIMIT 5
        RETURN collect({
            uri: uri,
            label: label,
            summary: summary
        }) AS context
        """
        
        with driver.session() as session:
            result = session.run(query, uri=uri)
            record = result.single()
            if record and record["context"]:
                return format_context(record["context"])
        return None
    except Exception as e:
        logger.error(f"Error getting graph context: {str(e)}")
        return None

def get_relevant_context(query: str, n_results: int = 5) -> List[Dict]:
    """Get relevant context from ChromaDB."""
    try:
        # Add logging to debug query
        logger.info(f"Searching for query: {query}")
        
        # Get semantically similar nodes
        results = collection.query(
            query_texts=[query],
            n_results=n_results
        )
        
        # Log raw results
        logger.info(f"Raw ChromaDB results: {results}")
        
        # Filter to only include processed URIs
        processed_uris = shared_state.get_processed_uris()
        filtered_results = []
        
        # Log processed URIs count
        logger.info(f"Number of processed URIs: {len(processed_uris)}")
        
        for i in range(len(results['ids'][0])):
            # Extract the URI from the metadata
            uri = results['metadatas'][0][i].get('uri')
            if uri in processed_uris:
                result = {
                    'id': uri,
                    'document': results['documents'][0][i],
                    'metadata': results['metadatas'][0][i],
                    'distance': results['distances'][0][i]
                }
                filtered_results.append(result)
                
        # Log filtered results
        logger.info(f"Filtered results count: {len(filtered_results)}")
        
        return filtered_results
    except Exception as e:
        logger.error(f"Error getting relevant context: {str(e)}")
        return []

def create_enriched_document(base_document: str, neo4j_context: Dict) -> str:
    """Create an enriched document by combining base document with related context"""
    parts = [base_document]
    
    # Add related nodes information
    for related in neo4j_context.get('related_nodes', []):
        if related.get('summary'):
            parts.append(f"Related {related['type']}: {related['summary']}")
    
    return "\n".join(parts)

def get_neo4j_context(uri: str) -> Dict:
    """Get additional context from Neo4j"""
    query = """
    MATCH (n {uri: $uri})
    WITH n
    OPTIONAL MATCH (n)-[r]-(related)
    WHERE related.ucosummary IS NOT NULL 
       OR related.ucocweSummary IS NOT NULL 
       OR related.ucodescription IS NOT NULL
    WITH n, collect({
        uri: related.uri,
        summary: coalesce(related.ucosummary, related.ucocweSummary, related.ucodescription),
        type: labels(related)[0]
    }) as related_nodes
    RETURN {
        uri: n.uri,
        summary: coalesce(n.ucosummary, n.ucocweSummary, n.ucodescription),
        type: labels(n)[0],
        related_nodes: related_nodes
    } as node
    """
    with driver.session() as session:
        result = session.run(query, uri=uri)
        record = result.single()
        return record["node"] if record else None

def generate_response(query: str, context: List[Dict], graph_context: bool = False) -> str:
    """Generate response using the LLM"""
    try:
        # Format context into structured text
        context_text = ""
        if context:
            context_text = "Relevant Information:\n"
            for idx, doc in enumerate(context, 1):
                context_text += f"{idx}. {doc['document']}\n"
        
        # Create a more focused prompt
        prompt = f"""You are a cybersecurity expert. Based on the following information, provide a clear and concise answer to the query.

Query: {query}

{context_text}

Instructions:
1. Focus on technical details and security implications
2. If the information is incomplete, acknowledge the limitations
3. Use clear, professional language
4. If no relevant information is found, state that clearly

Answer:"""
        
        logger.info(f"Input prompt length: {len(prompt)}")
        
        # Generate response with proper attention mask handling
        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
            padding=True,
            return_attention_mask=True
        )
        
        logger.info(f"Input shape: {inputs['input_ids'].shape}")
        logger.info(f"Attention mask shape: {inputs['attention_mask'].shape}")
        
        # Move inputs to the same device as the model
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        logger.info(f"Model device: {model.device}")
        logger.info(f"Input device after moving: {inputs['input_ids'].device}")
        
        # Use a more conservative generation configuration
        try:
            # Ensure model is in eval mode
            model.eval()
            
            with torch.no_grad():
                outputs = model.generate(
                    input_ids=inputs['input_ids'],
                    attention_mask=inputs['attention_mask'],
                    max_new_tokens=256,
                    temperature=0.5,
                    top_p=0.85,
                    do_sample=True,
                    num_beams=1,
                    pad_token_id=tokenizer.pad_token_id,
                    eos_token_id=tokenizer.eos_token_id,
                    repetition_penalty=1.0,
                    no_repeat_ngram_size=0,
                    use_cache=True,
                    output_scores=True,
                    return_dict_in_generate=True
                )
            logger.info("Generation completed successfully")
        except Exception as e:
            logger.error(f"Error during model.generate: {str(e)}")
            logger.error(f"Model config: {model.config}")
            logger.error(f"Input device: {inputs['input_ids'].device}")
            logger.error(f"Model dtype: {model.dtype}")
            raise
        
        # Extract the generated text
        generated_ids = outputs.sequences[0]
        response = tokenizer.decode(generated_ids, skip_special_tokens=True)
        logger.info(f"Generated response length: {len(response)}")
        
        # Extract only the answer part
        if "Answer:" in response:
            response = response.split("Answer:")[-1].strip()
        
        # If response is too short or generic, try to improve it
        if len(response.split()) < 20 or any(generic in response.lower() for generic in ["describes", "explains", "highlights"]):
            # Try to get more specific information
            if context:
                context_text = "Detailed Information:\n"
                for doc in context:
                    context_text += f"- {doc['document']}\n"
                
                prompt = f"""You are a cybersecurity expert. Provide a detailed technical analysis of the following vulnerability or weakness.

Query: {query}

{context_text}

Instructions:
1. Provide specific technical details about the vulnerability
2. Explain the security impact
3. Include any relevant code or system components
4. If information is limited, explain what is known and what is uncertain

Technical Analysis:"""
                
                inputs = tokenizer(
                    prompt,
                    return_tensors="pt",
                    truncation=True,
                    max_length=2048,
                    padding=True,
                    return_attention_mask=True
                )
                inputs = {k: v.to(model.device) for k, v in inputs.items()}
                
                outputs = model.generate(
                    input_ids=inputs['input_ids'],
                    attention_mask=inputs['attention_mask'],
                    max_new_tokens=256,  # Reduced from 512
                    temperature=0.5,  # Reduced from 0.7
                    top_p=0.85,  # Reduced from 0.95
                    do_sample=True,
                    num_beams=1,
                    pad_token_id=tokenizer.pad_token_id,
                    eos_token_id=tokenizer.eos_token_id,
                    repetition_penalty=1.0,  # Removed repetition penalty
                    no_repeat_ngram_size=0,  # Removed n-gram penalty
                    use_cache=True,
                    output_scores=True,  # Enable score output for debugging
                    return_dict_in_generate=True  # Get more detailed output
                )
                
                generated_ids = outputs.sequences[0]
                response = tokenizer.decode(generated_ids, skip_special_tokens=True)
                if "Technical Analysis:" in response:
                    response = response.split("Technical Analysis:")[-1].strip()
        
        return response
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        return f"Error generating response: {str(e)}"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8051)