from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import os
import sys
import logging
from typing import Optional, Dict, Any
from neo4j.graph import Node, Relationship

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our Q&A engines
from graphrag import GraphRAGSimilarity

from text2cypher.backend.text2cypher import Text2Cypher
from text2cypher.backend.ollama_llm import OllamaLLM

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Global instances (initialized on startup)
graphrag_engine = None
text2cypher_engine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown"""
    global graphrag_engine, text2cypher_engine
    
    # Startup
    logger.info("Initializing Q&A engines...")
    
    try:
        # Initialize GraphRAG-Similarity
        logger.info("Initializing GraphRAG-Similarity engine...")
        graphrag_engine = GraphRAGSimilarity()
        logger.info("GraphRAG-Similarity engine initialized successfully")
        
        # Initialize Text2Cypher
        logger.info("Initializing Text2Cypher engine...")
        llm = OllamaLLM(base_url=OLLAMA_URL, model=OLLAMA_MODEL)
        text2cypher_engine = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm)
        
        # Pre-warm by getting schema
        schema = text2cypher_engine.get_schema()
        logger.info("Text2Cypher engine initialized successfully")
        
        logger.info("All Q&A engines initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Q&A engines: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Q&A engines...")
    
    try:
        if graphrag_engine:
            graphrag_engine.close()
            logger.info("GraphRAG-Similarity engine closed")
            
        if text2cypher_engine and hasattr(text2cypher_engine, 'driver'):
            text2cypher_engine.driver.close()
            logger.info("Text2Cypher engine closed")
            
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")

# Create FastAPI app with lifespan
app = FastAPI(
    title="UCKG Q&A Engine",
    description="Unified service for GraphRAG-Similarity and Text2Cypher queries",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class RAGRequest(BaseModel):
    query: str
    mode: str = "auto"
    top_k: int = 5
    include_visualization: bool = True

class Text2CypherRequest(BaseModel):
    question: str
    execute: bool = True
    explain: bool = True

class ChatRequest(BaseModel):
    question: str
    session_id: str

# Response formatting functions
def format_graphrag_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Format GraphRAG-Similarity result for frontend visualization"""
    visualization_data = {
        "nodes": [],
        "relationships": []
    }

    sources = result.get("sources", [])

    # Track added nodes to avoid duplicates
    node_map = {}

    # Process sources into nodes for visualization
    for i, source in enumerate(sources):
        # Handle both semantic and graph result formats
        if "primarySource" in source:
            # Graph result format
            primary = source["primarySource"]
            node_id = str(primary.get("nodeId", f"node_{i}"))
            score = primary.get("score", 0.0)
            node_label = primary.get("nodeLabel", "Unknown")
            node_type = primary.get("nodeType", "Unknown")
            content = primary.get("nodeContent", "")
            all_properties = primary.get("allProperties") or {}  # Handle None values
        else:
            # Semantic result format
            node_id = str(source.get("metadata", {}).get("id", f"node_{i}"))
            score = source.get("score", 0.0)
            node_label = source.get("metadata", {}).get("nodeLabel", "Unknown")
            node_type = source.get("metadata", {}).get("nodeType", "Unknown")
            content = source.get("content", "")
            all_properties = {}

        # Add primary node if not already added
        if node_id not in node_map:
            # Filter out embedding property if it exists
            filtered_properties = {k: v for k, v in all_properties.items() if k != 'embedding'}

            node = {
                "id": node_id,
                "label": node_label,
                "caption": node_label,
                "type": node_type,
                "properties": {
                    **filtered_properties,  # Spread all Neo4j properties first
                    "isRAGResult": True,
                    "score": score,
                    "content": content,
                    "mode": result.get("mode", "unknown"),
                    "hopLevel": 0  # Primary node
                },
                "score": score,
                "color": get_type_color(node_type),
                "size": get_type_size(node_type, hop_level=0)
            }
            visualization_data["nodes"].append(node)
            node_map[node_id] = node

        # Add relationships if available (from graphrag mode)
        if "firstHopNeighbors" in source:
            for rel_idx, rel in enumerate(source["firstHopNeighbors"]):
                primary_node = rel.get("primaryNode", {})
                neighbor_id = str(primary_node.get("nodeId", f"rel_node_{i}_{rel_idx}"))
                all_neighbor_properties = primary_node.get("allProperties") or {}  # Handle None values

                # Add neighbor node if not already added
                if neighbor_id not in node_map:
                    # Filter out embedding property if it exists
                    filtered_neighbor_props = {k: v for k, v in all_neighbor_properties.items() if k != 'embedding'}

                    neighbor_type = primary_node.get("nodeType", "Unknown")
                    neighbor_node = {
                        "id": neighbor_id,
                        "label": primary_node.get("nodeLabel", "Unknown"),
                        "caption": primary_node.get("nodeLabel", "Unknown"),
                        "type": neighbor_type,
                        "properties": {
                            **filtered_neighbor_props,  # Spread all Neo4j properties first
                            "isRAGResult": True,
                            "content": primary_node.get("nodeContent", ""),
                            "mode": result.get("mode", "unknown"),
                            "hopLevel": 1  # 1-hop neighbor
                        },
                        "score": score * 0.8,  # Lower score for neighbors
                        "color": get_type_color(neighbor_type),
                        "size": get_type_size(neighbor_type, hop_level=1)
                    }
                    visualization_data["nodes"].append(neighbor_node)
                    node_map[neighbor_id] = neighbor_node

                # Add relationship (primary -> 1-hop neighbor)
                relationship = {
                    "id": f"rel_{node_id}_{neighbor_id}",
                    "from": node_id,
                    "to": neighbor_id,
                    "type": rel.get("relationshipType", "RELATED"),
                    "caption": rel.get("relationshipType", "RELATED"),
                    "properties": {
                        "isRAGResult": True
                    }
                }
                visualization_data["relationships"].append(relationship)
                
                # Process 2-hop neighbors if present
                second_hop_neighbors = rel.get("secondHopNeighbors", [])
                if second_hop_neighbors:
                    for second_idx, second_hop in enumerate(second_hop_neighbors):
                        second_node = second_hop.get("relatedNode", {})
                        second_node_id = str(second_node.get("nodeId", f"second_node_{i}_{rel_idx}_{second_idx}"))
                        all_second_props = second_node.get("allProperties") or {}  # Handle None values
                        
                        # Add 2-hop node if not already added
                        if second_node_id not in node_map:
                            # Filter out embedding property
                            filtered_second_props = {k: v for k, v in all_second_props.items() if k != 'embedding'}
                            
                            second_node_type = second_node.get("nodeType", "Unknown")
                            second_node_obj = {
                                "id": second_node_id,
                                "label": second_node.get("nodeLabel", "Unknown"),
                                "caption": second_node.get("nodeLabel", "Unknown"),
                                "type": second_node_type,
                                "properties": {
                                    **filtered_second_props,
                                    "isRAGResult": True,
                                    "content": second_node.get("nodeContent", ""),
                                    "mode": result.get("mode", "unknown"),
                                    "hopLevel": 2  # Mark as 2-hop
                                },
                                "score": score * 0.6,  # Even lower score for 2-hop
                                "color": get_type_color(second_node_type),
                                "size": get_type_size(second_node_type, hop_level=2)
                            }
                            visualization_data["nodes"].append(second_node_obj)
                            node_map[second_node_id] = second_node_obj
                        
                        # Add relationship (1-hop neighbor -> 2-hop neighbor)
                        second_relationship = {
                            "id": f"rel_{neighbor_id}_{second_node_id}",
                            "from": neighbor_id,
                            "to": second_node_id,
                            "type": second_hop.get("relationshipType", "RELATED"),
                            "caption": second_hop.get("relationshipType", "RELATED"),
                            "properties": {
                                "isRAGResult": True,
                                "hopLevel": 2  # Mark as 2-hop relationship
                            }
                        }
                        visualization_data["relationships"].append(second_relationship)

    # Format sources for chat display - minimal, modern design
    formatted_sources = []
    for source in sources:
        # Handle both semantic and graph result formats
        if "primarySource" in source:
            primary = source["primarySource"]
            formatted_sources.append({
                "label": primary.get("nodeLabel", "Unknown"),
                "score": round(primary.get("score", 0.0), 3)
            })
        else:
            formatted_sources.append({
                "label": source.get("metadata", {}).get("nodeLabel", "Unknown"),
                "score": round(source.get("score", 0.0), 3)
            })

    # Calculate confidence based on scores
    if formatted_sources:
        avg_score = sum(s["score"] for s in formatted_sources) / len(formatted_sources)
        confidence = min(avg_score * 1.1, 1.0)  # Slight boost, cap at 1.0
    else:
        confidence = 0.0

    return {
        "answer": result.get("answer", "No answer generated"),
        "chat_data": {
            "message": result.get("answer", "No answer generated"),
            "sources": formatted_sources,
            "confidence": confidence,
            "mode": result.get("mode", "unknown")
        },
        "visualization_data": visualization_data,
        "metadata": {
            "mode": result.get("mode", "unknown"),
            "execution_time": 0,
            "total_nodes": len(visualization_data["nodes"]),
            "total_relationships": len(visualization_data["relationships"]),
            "score_statistics": {
                "min": min(s["score"] for s in formatted_sources) if formatted_sources else 0,
                "max": max(s["score"] for s in formatted_sources) if formatted_sources else 0,
                "avg": sum(s["score"] for s in formatted_sources) / len(formatted_sources) if formatted_sources else 0
            }
        }
    }

def format_text2cypher_result(cypher_query: str, execution_result, explanation: str, confidence: float, records_list: list = None) -> Dict[str, Any]:
    """Format Text2Cypher result for frontend with both chat and graph data (LangChain pattern)"""

    # Include Cypher query in code block followed by LLM explanation
    full_message = f"```cypher\n{cypher_query}\n```\n\n{explanation}"

    # Chat/Answer data
    chat_data = {
        "message": full_message,
        "cypher_query": cypher_query,
        "confidence": confidence,
        "query_validated": True
    }
    
    # Graph visualization data - process records_list directly
    graph_data = None
    if records_list:
        # Process the Neo4j records to extract nodes and relationships
        nodes = []
        relationships = []
        node_map = {}
        rel_map = {}

        logger.info(f"Processing {len(records_list)} records for graph visualization")

        for record in records_list:
            logger.info(f"Record keys: {list(record.keys())}")
            for key, value in record.items():
                logger.info(f"Processing key '{key}', value type: {type(value)}, is Node: {isinstance(value, Node)}, is Relationship: {isinstance(value, Relationship)}")

                # Check if it's a Neo4j Node object
                if isinstance(value, Node):
                    # This is a node
                    node_id = str(value.element_id)  # Use element_id instead of identity
                    logger.info(f"✓ Found node with ID: {node_id}, labels: {list(value.labels)}")
                    if node_id not in node_map:
                        labels = list(value.labels) if value.labels else []
                        main_label = labels[1] if len(labels) > 1 else (labels[0] if labels else 'Node')

                        # Neo4j Node objects are dict-like, access properties via dict methods
                        node_props = {}
                        try:
                            # Try to get properties if the node has them
                            for prop_key in value.keys():
                                node_props[prop_key] = value[prop_key]
                        except Exception as e:
                            logger.warning(f"Could not extract properties: {e}")

                        # Determine caption based on node type and properties
                        caption = main_label
                        if 'ucocweID' in node_props:
                            caption = node_props['ucocweID']
                        elif 'ucoCVE_id' in node_props:
                            caption = node_props['ucoCVE_id']
                        elif 'ucoexCAPEC_id' in node_props:
                            caption = f"CAPEC-{node_props['ucoexCAPEC_id']}"
                        elif 'ucoexNAME' in node_props:
                            caption = node_props['ucoexNAME']
                        elif 'cpeName' in node_props:
                            caption = node_props['cpeName'][:50] + '...' if len(node_props.get('cpeName', '')) > 50 else node_props.get('cpeName', caption)
                        elif 'ucocweName' in node_props:
                            caption = node_props['ucocweName'][:50] + '...' if len(node_props.get('ucocweName', '')) > 50 else node_props.get('ucocweName', caption)

                        node = {
                            'id': node_id,
                            'caption': caption,
                            'label': main_label,
                            'properties': node_props,
                            'color': '#4287f5',  # Blue for Cypher results
                            'size': 50
                        }
                        nodes.append(node)
                        node_map[node_id] = node
                        logger.info(f"Added node with caption: {caption}")

                elif isinstance(value, Relationship):
                    # This is a Neo4j Relationship object
                    rel_id = str(value.element_id)  # Use element_id instead of identity
                    logger.info(f"Found relationship with ID: {rel_id}, type: {value.type}")
                    if rel_id not in rel_map:
                        start_id = str(value.start.element_id) if hasattr(value.start, 'element_id') else str(value.start)
                        end_id = str(value.end.element_id) if hasattr(value.end, 'element_id') else str(value.end)

                        # Get relationship properties
                        rel_props = {}
                        try:
                            for prop_key in value.keys():
                                rel_props[prop_key] = value[prop_key]
                        except Exception as e:
                            logger.warning(f"Could not extract relationship properties: {e}")

                        relationship = {
                            'id': rel_id,
                            'from': start_id,
                            'to': end_id,
                            'caption': value.type,
                            'type': value.type,
                            'properties': rel_props,
                            'color': '#1a5cd6',  # Darker blue for relationships
                            'width': 2
                        }
                        relationships.append(relationship)
                        rel_map[rel_id] = relationship
                        logger.info(f"Added relationship: {relationship}")

        graph_data = {
            "type": "graph",
            "nodes": nodes,
            "relationships": relationships
        }
        logger.info(f"Final graph_data: {len(nodes)} nodes, {len(relationships)} relationships")
    
    return {
        # Chat/Answer format
        "answer": full_message,
        "chat_data": chat_data,

        # Graph format (raw Neo4j result for processing)
        "graph_data": graph_data,

        # Legacy format for backward compatibility
        "cypher_query": cypher_query,
        "explanation": full_message,
        "confidence": confidence,
        "query_validated": True
    }

def get_type_color(node_type: str) -> str:
    """Map node types to colors for NVL visualization"""
    type_colors = {
        # Vulnerabilities and Weaknesses (red/orange spectrum)
        "UcoCWE": "#DC143C",           # Crimson - Common Weakness
        "UcoCVE": "#FF6347",           # Tomato - CVE
        "UcoVulnerability": "#FF4500", # OrangeRed - General Vulnerability
        
        # Attack Patterns and Techniques (purple/magenta spectrum)
        "UcoexCAPEC": "#9370DB",       # Medium Purple - Attack Patterns
        "UcoexMITREATTACK": "#8B008B", # Dark Magenta - Attack Techniques
        "UcoexTACTICS": "#BA55D3",     # Medium Orchid - Tactics
        
        # Threat Actors (yellow/gold spectrum)
        "UcoexGROUPS": "#FFD700",      # Gold - Threat Groups
        "UcoexCAMPAIGNS": "#FFA500",   # Orange - Campaigns
        
        # Defenses and Mitigations (green/cyan spectrum)
        "UcoexMITIGATIONS": "#32CD32",    # Lime Green - Mitigations
        "UcoexMITRED3FEND": "#20B2AA",    # Light Sea Green - D3FEND
        
        # Technology and Products (blue spectrum)
        "UcoexSOFTWARE": "#4169E1",    # Royal Blue - Software
        "UcoexCPE": "#87CEEB",         # Sky Blue - CPE/Products
        
        # Examples and Others (gray spectrum)
        "UcoexObservedExample": "#A9A9A9",  # Dark Gray - Examples
        "Unknown": "#808080"            # Gray - Unknown types
    }
    
    return type_colors.get(node_type, "#808080")  # Default gray for unmapped types

def get_type_size(node_type: str, hop_level: int = 0) -> float:
    """Map node types and hop levels to sizes for NVL"""
    # Base sizes by hop level
    if hop_level == 0:  # Primary nodes
        return 35
    elif hop_level == 1:  # 1-hop neighbors
        return 28
    else:  # 2-hop neighbors
        return 22

def infer_node_label_from_uri(uri: str) -> str:
    """Infer node label from URI"""
    if not uri:
        return "Unknown"
    if "CVE-" in uri:
        return "UcoCVE"
    if "CWE-" in uri:
        return "UcoCWE"
    if "cpe:" in uri:
        return "UcoexCPE"
    if "CAPEC-" in uri:
        return "UcoexCAPEC"
    return "Unknown"

# Lifespan management is now handled by the lifespan context manager above

# API Endpoints
@app.get("/")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "UCKG Q&A Engine is running"}

@app.get("/api/schema")
def get_schema():
    """Get detailed schema information"""
    try:
        if not text2cypher_engine:
            raise HTTPException(status_code=503, detail="Text2Cypher engine not initialized")
        
        schema_info = text2cypher_engine.get_schema_info()
        return schema_info
    except Exception as e:
        logger.error(f"Error getting schema: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rag")
async def rag_query(request: RAGRequest):
    """Execute GraphRAG-Similarity query"""
    try:
        if not graphrag_engine:
            raise HTTPException(status_code=503, detail="GraphRAG-Similarity engine not initialized")

        logger.info(f"Processing RAG query: {request.query} (mode: {request.mode})")

        # Execute GraphRAG-Similarity query
        result = graphrag_engine.run(request.query)

        # Format for frontend
        formatted_result = format_graphrag_result(result)

        logger.info(f"RAG query completed successfully")
        return formatted_result

    except Exception as e:
        logger.error(f"Error processing RAG query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/text2cypher")
async def text2cypher_query(request: Text2CypherRequest):
    """Execute Text2Cypher query"""
    try:
        if not text2cypher_engine:
            raise HTTPException(status_code=503, detail="Text2Cypher engine not initialized")
        
        logger.info(f"Processing Text2Cypher query: {request.question}")
        
        # Get schema and generate Cypher
        schema = text2cypher_engine.get_schema()
        cypher_query = text2cypher_engine.text_to_cypher(request.question, schema)
        logger.info(f"Generated Cypher: {cypher_query}")
        
        # Execute query if requested
        execution_result = None
        records_list = []
        result_count = 0
        
        if request.execute:
            try:
                print(f"DEBUG: Executing query: {cypher_query}")
                records_list = text2cypher_engine.run_cypher(cypher_query)
                print(f"DEBUG: Got records_list: {type(records_list)}")
                result_count = len(records_list) if records_list else 0
                print(f"DEBUG: Records list length: {result_count}")
                logger.info(f"Query returned {result_count} results")
                
                # Debug: Log the first few records if any
                if result_count > 0:
                    logger.info(f"First record keys: {list(records_list[0].keys())}")
                    for i, record in enumerate(records_list[:2]):  # Log first 2 records
                        logger.info(f"Record {i}: {dict(record)}")
                else:
                    logger.warning(f"No results returned for query: {cypher_query}")
                    
            except Exception as e:
                logger.error(f"Error executing Cypher query: {str(e)}")
                raise e
        
        # Generate LLM explanation of results (top 5 only)
        explanation = f"Converted '{request.question}' to Cypher query"
        if request.explain and request.execute and records_list:
            try:
                # Use LLM to explain the results (top 5, no embeddings)
                explanation = text2cypher_engine.explain_results(
                    question=request.question,
                    cypher_query=cypher_query,
                    results=records_list,
                    max_results=5
                )
                logger.info(f"Generated LLM explanation: {explanation[:100]}...")
            except Exception as e:
                logger.error(f"Error generating LLM explanation: {str(e)}")
                explanation = f"Converted '{request.question}' to Cypher query and executed successfully, returning {result_count} results."
        elif request.execute:
            explanation += f" and executed successfully, returning {result_count} results."

        # Calculate confidence (simple heuristic)
        confidence = 0.8 if records_list and len(records_list) > 0 else 0.5
        
        # Format for frontend
        formatted_result = format_text2cypher_result(cypher_query, None, explanation, confidence, records_list)
        
        logger.info("Text2Cypher query completed successfully")
        return formatted_result
        
    except Exception as e:
        logger.error(f"Error processing Text2Cypher query: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat_history")
async def chat_history(request: ChatRequest):
    """Chat with history support"""
    try:
        logger.info(f"Chat history query: {request.question}")
        
        # For now, redirect to RAG query
        # In the future, this could implement proper chat history
        rag_request = RAGRequest(query=request.question)
        result = await rag_query(rag_request)
        
        return {"answer": result["answer"]}
        
    except Exception as e:
        logger.error(f"Chat history error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
