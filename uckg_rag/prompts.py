# Module containing prompt templates and Cypher queries for the RAG pipeline.

from typing import Dict, List, Optional

def get_initial_prompt(query: str, context_text: str) -> str:
    # Generate the initial prompt for query processing.
    return f"""You are a cybersecurity expert. Based on the following information, provide a clear and concise answer to the query that is no more than 2 sentences.
    
    Query: {query}

    Context: {context_text.strip()}

    Instructions:
    1. Focus on technical details and security implications
    2. If the information is incomplete, acknowledge the limitations
    3. Use clear, professional language
    4. If no relevant information is found, state that clearly
    
    Answer:"""

def get_technical_analysis_prompt(query: str, context_text: str) -> str:
    # Generate the technical analysis prompt for detailed responses.
    return f"""You are a cybersecurity expert. Provide a detailed technical analysis of the following vulnerability or weakness that is no more than 2 sentences.

    Query: {query}

    Context: {context_text}

    Instructions:
    1. Provide specific technical details about the vulnerability or weakness
    2. Explain the security impact
    3. If information is limited, explain what is known and what is uncertain

    Answer:"""

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
    # Simple query to get a node and its related nodes within 3 hops
    return """
    MATCH (v {uri: $uri})
    WITH v, {
        uri: v.uri,
        label: labels(v)[0],
        summary: CASE
            WHEN v.ucosummary IS NOT NULL THEN v.ucosummary
            WHEN v.ucocweSummary IS NOT NULL THEN v.ucocweSummary
            ELSE v.ucodescription
        END
    } as source
    OPTIONAL MATCH path = (v)-[*1..3]-(related)
    WHERE related.ucosummary IS NOT NULL 
       OR related.ucocweSummary IS NOT NULL 
       OR related.ucodescription IS NOT NULL
    WITH source, related, length(path) as distance
    ORDER BY distance
    LIMIT $nearest_neighbors
    WITH source, collect({
        uri: related.uri,
        label: labels(related)[0],
        summary: CASE
            WHEN related.ucosummary IS NOT NULL THEN related.ucosummary
            WHEN related.ucocweSummary IS NOT NULL THEN related.ucocweSummary
            ELSE related.ucodescription
        END
    }) as related_nodes
    RETURN collect(source) + related_nodes as context
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
        if not item:  # Skip empty items
            continue
        summary = item.get('summary', [])
        # If summary is an array, take first element
        summary_text = summary[0] if isinstance(summary, list) and summary else ''
        formatted_context.append(f"{item['label']}: {summary_text}")
    return "\n".join(formatted_context) 