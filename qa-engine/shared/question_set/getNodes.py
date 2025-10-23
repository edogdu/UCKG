import os
from dotenv import load_dotenv
from neo4j import GraphDatabase
import re
import json
# from langchain_ollama import OllamaEmbeddings

# Load environment variables
load_dotenv()

# Connect to Neo4j database
driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USER'), os.getenv('NEO4J_PASSWORD'))
)

# Verify connection
try:
    driver.verify_connectivity()
    print("✓ Connected to Neo4j database")
except Exception as e:
    print(f"✗ Failed to connect to Neo4j: {e}")
    exit(1)


def normalize_whitespace(text):
    
    if not isinstance(text, str):
        return text
    
    # Replace multiple spaces with single space
    text = re.sub(r' +', ' ', text)
    # Replace multiple newlines with single newline
    text = re.sub(r'\n\s*\n+', '\n', text)
    # Remove leading/trailing whitespace from each line
    lines = [line.strip() for line in text.split('\n')]
    return '\n'.join(lines).strip()


def filter_node_properties(properties):
    
    keywords = ["name", "summary", "mitigation", "example", "label", "description", "severity", "title", "domain", "definition"]
    filtered = {}
    
    for key, value in properties.items():
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in keywords):
            # Normalize whitespace in string values
            if isinstance(value, str):
                filtered[key] = normalize_whitespace(value)
            else:
                filtered[key] = value
    
    return filtered


def get_single_node(node_id):
    
    with driver.session() as session:
        # Check if ID is numeric (old format) or element ID (new format)
        if isinstance(node_id, str) and node_id.isdigit():
            # Use old id() function for numeric IDs
            id_val = int(node_id)
            query = """
            MATCH (n)
            WHERE id(n) = $node_id
            RETURN n
            """
            result = session.run(query, node_id=id_val)
        else:
            # Use elementId() for new format
            query = """
            MATCH (n)
            WHERE elementId(n) = $node_id
            RETURN n
            """
            result = session.run(query, node_id=node_id)
        
        record = result.single()
        
        if not record:
            return {
                "error": "Node not found",
                "node_id": node_id
            }
        
        node = record["n"]
        
        # Format the response with filtered properties and labels
        node_data = filter_node_properties(dict(node))
        node_data["labels"] = list(node.labels)[0]
        
        response = {
            "node": node_data
        }
        
        return response


def get_two_connected_nodes(node_id_1, node_id_2):
    
    with driver.session() as session:
        # Check if IDs are numeric (old format) or element IDs (new format)
        if isinstance(node_id_1, str) and node_id_1.isdigit():
            # Use old id() function for numeric IDs
            id_1 = int(node_id_1)
            id_2 = int(node_id_2)
            query = """
            MATCH (n1)
            WHERE id(n1) = $node_id_1
            MATCH (n2)
            WHERE id(n2) = $node_id_2
            OPTIONAL MATCH (n1)-[r]-(n2)
            RETURN n1, n2, collect(r) as relationships
            """
            result = session.run(query, node_id_1=id_1, node_id_2=id_2)
        else:
            # Use elementId() for new format
            query = """
            MATCH (n1)
            WHERE elementId(n1) = $node_id_1
            MATCH (n2)
            WHERE elementId(n2) = $node_id_2
            OPTIONAL MATCH (n1)-[r]-(n2)
            RETURN n1, n2, collect(r) as relationships
            """
            result = session.run(query, node_id_1=node_id_1, node_id_2=node_id_2)
        record = result.single()
        
        if not record:
            return {
                "error": "One or both nodes not found",
                "node_id_1": node_id_1,
                "node_id_2": node_id_2
            }
        
        node1 = record["n1"]
        node2 = record["n2"]
        relationships = record["relationships"]
        
        # Format the response with filtered properties and labels included
        node1_data = filter_node_properties(dict(node1))
        node1_data["labels"] = list(node1.labels)[0]
        
        node2_data = filter_node_properties(dict(node2))
        node2_data["labels"] = list(node2.labels)[0]
        
        response = {
            "node1": node1_data,
            "node2": node2_data,
            "relationships": []
        }
        
        # Add relationship types
        for rel in relationships:
            if rel is not None:
                response["relationships"].append({
                    "type": rel.type
                    # "properties": dict(rel)
                })
        
        return response


def get_three_connected_nodes(node_id_1, node_id_2, node_id_3):
    
    with driver.session() as session:
        # Convert string IDs to integers if necessary
        id_1 = int(node_id_1) if isinstance(node_id_1, str) else node_id_1
        id_2 = int(node_id_2) if isinstance(node_id_2, str) else node_id_2
        id_3 = int(node_id_3) if isinstance(node_id_3, str) else node_id_3
        
        # Query to get three nodes in sequential connection
        query = """
        MATCH (n1)
        WHERE id(n1) = $node_id_1
        MATCH (n2)
        WHERE id(n2) = $node_id_2
        MATCH (n3)
        WHERE id(n3) = $node_id_3
        OPTIONAL MATCH (n1)-[r1]-(n2)
        OPTIONAL MATCH (n2)-[r2]-(n3)
        RETURN n1, n2, n3, 
               collect(DISTINCT r1) as rels_1_2,
               collect(DISTINCT r2) as rels_2_3
        """
        
        result = session.run(query, node_id_1=id_1, node_id_2=id_2, node_id_3=id_3)
        record = result.single()
        
        if not record:
            return {
                "error": "One or more nodes not found",
                "node_id_1": node_id_1,
                "node_id_2": node_id_2,
                "node_id_3": node_id_3
            }
        
        node1 = record["n1"]
        node2 = record["n2"]
        node3 = record["n3"]
        rels_1_2 = record["rels_1_2"]
        rels_2_3 = record["rels_2_3"]
        
        # Format the response with filtered properties and labels included
        node1_data = filter_node_properties(dict(node1))
        node1_data["labels"] = list(node1.labels)[0]
        
        node2_data = filter_node_properties(dict(node2))
        node2_data["labels"] = list(node2.labels)[0]
        
        node3_data = filter_node_properties(dict(node3))
        node3_data["labels"] = list(node3.labels)[0]
        
        response = {
            "node1": node1_data,
            "node2": node2_data,
            "node3": node3_data,
            "relationships": {
                "node1_node2": [],
                "node2_node3": []
            }
        }
        
        # Add relationship details between node1 and node2
        for rel in rels_1_2:
            if rel is not None:
                response["relationships"]["node1_node2"].append({
                    "type": rel.type
                    # "properties": dict(rel)
                })
        
        # Add relationship details between node2 and node3
        for rel in rels_2_3:
            if rel is not None:
                response["relationships"]["node2_node3"].append({
                    "type": rel.type
                    # "properties": dict(rel)
                })
        
        return response


# Example usage
if __name__ == "__main__":
    # Example: Replace with actual node IDs from your database
    # You can get node IDs by running: MATCH (n) RETURN elementId(n), n LIMIT 5
    
    # List of node tuples to process (can be 1, 2, or 3 nodes)
    node_groups = [
        # ("782755",)  # 1 node
        ("783461", "2382"),  # 2 nodes
        # ("783162", "6440", "5254"),  # 3 nodes
    ]
    
    # Save results to JSON file
    output_file = "nodes.json"
    all_results = []
    
    for idx, node_ids in enumerate(node_groups, 1):
        num_nodes = len(node_ids)
        
        # Call appropriate function based on number of nodes
        if num_nodes == 1:
            result = get_single_node(node_ids[0])
        elif num_nodes == 2:
            result = get_two_connected_nodes(node_ids[0], node_ids[1])
        elif num_nodes == 3:
            result = get_three_connected_nodes(node_ids[0], node_ids[1], node_ids[2])
        else:
            print(f"Skipping group {idx}: Only 1, 2, or 3 nodes supported")
            continue
        
        all_results.append(result)
    
    # Write all results to JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=4, ensure_ascii=False)
    
    print(f"\n✓ All results saved to {output_file}")
    
    # Close the driver when done
    driver.close()