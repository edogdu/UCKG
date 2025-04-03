# Module containing prompt templates and Cypher queries for the RAG pipeline.

from typing import Dict, List, Optional

def get_initial_prompt(query: str, context_text: str) -> str:
    # Generate the initial prompt for query processing.
    return f"""You are a cybersecurity expert. Based on the following information, provide a clear and concise answer to the query.
    
    Query: {query}

    Context: {context_text}

    Instructions:
    1. Focus on technical details and security implications
    2. If the information is incomplete, acknowledge the limitations
    3. Use clear, professional language
    4. If no relevant information is found, state that clearly
    
    Answer:"""

def get_technical_analysis_prompt(query: str, context_text: str) -> str:
    # Generate the technical analysis prompt for detailed responses.
    return f"""You are a cybersecurity expert. Provide a detailed technical analysis of the following vulnerability or weakness.

    Query: {query}

    {context_text}

    Instructions:
    1. Provide specific technical details about the vulnerability
    2. Explain the security impact
    3. Include any relevant code or system components
    4. If information is limited, explain what is known and what is uncertain

    Technical Analysis:"""

def get_direct_node_query() -> str:
    # Get the Cypher query for finding nodes directly in Neo4j.
    return """
    MATCH (n)
    WHERE n.ucodescription CONTAINS $query
       OR n.ucosummary CONTAINS $query
       OR n.ucocweSummary CONTAINS $query
    RETURN n.uri AS uri,
           coalesce(n.ucosummary, n.ucocweSummary, n.ucodescription) AS text
    LIMIT 1
    """

def get_graph_context_query() -> str:
    # Get the Cypher query for retrieving graph context.
    return """
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

def get_neo4j_context_query() -> str:
    # Get the Cypher query for retrieving Neo4j context.
    return """
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

def format_context(context: List[Dict]) -> str:
    # Format the context into a readable string.
    formatted_context = []
    for item in context:
        formatted_context.append(f"{item['label']}: {item['summary']}")
    return "\n".join(formatted_context) 