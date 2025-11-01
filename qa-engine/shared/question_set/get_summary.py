import json
import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate

# Load environment variables
load_dotenv()

# Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found in .env file. Please add it.")

# Load semantic descriptions for context
schema_cache = ""
try:
    with open('semantic_descriptions.txt', 'r', encoding='utf-8') as file:
        schema_cache = file.read()
except FileNotFoundError:
    print("⚠ Warning: semantic_descriptions.txt not found. Proceeding without semantic context.")

# Initialize LLM with OpenAI
print(f"Initializing LLM: {OPENAI_MODEL}")
llm = ChatOpenAI(
    openai_api_key=OPENAI_API_KEY,
    model=OPENAI_MODEL,
    temperature=0.7
)


def summarize_single_node(node_data, schema=""):
    """
    Generate a summary for a single node.
    
    Args:
        node_data: json file containing the single node information
        schema: schema information for context of the relationship between nodes
        
    Returns:
        str: Generated summary
    """
    schema_text = f"## Schema Context (for reference)\n{schema}\n" if schema else ""
    node_data_text = json.dumps(node_data, indent=2)
    
    prompt = PromptTemplate(
        input_variables=['node_data', 'schema'],
        template="""
You are a cybersecurity analyst providing clear, concise summaries of knowledge graph entities.

## Task
Given a single node from a cybersecurity knowledge graph, generate a professional 3-4 sentence summary 
of the single provided node that explains:
1. What this entity is (its type and identifier)
2. Its key characteristics or purpose
3. Its significance in cybersecurity context


## Guidelines
- Be concise and informative (2-3 sentences)
- Use plain language, avoid technical jargon where possible
- Focus on practical meaning and implications
- DO NOT mention property names (like "ucocweSummary", "uri", etc.)
- Make it readable for both technical and non-technical audiences
- Do not go into any of the links in order to explain about the node.
- Just summarize what is presented with the given set of properties.

{schema}

## Node Data
{node_data}

## Summary:
"""
    )
    
    # Use LCEL (LangChain Expression Language) syntax
    chain = prompt | llm
    response = chain.invoke({
        "node_data": node_data_text, 
        "schema": schema_text
    })
    
    return response.content.strip()


def summarize_two_nodes(node1_data, node2_data, relationships, schema=""):
    """
    Generate a summary for two connected nodes with their relationship.
    
    Args:
        node1_data: json file that will contain first node information
        node2_data: json file that will contain the second node information
        relationships: json file of relationship types between the first and the second nodes
        schema: schema information for context of the relationship between nodes
        
    Returns:
        str: Generated summary
    """
    schema_text = f"## Schema Context (for reference)\n{schema}\n" if schema else ""
    node1_text = json.dumps(node1_data, indent=2)
    node2_text = json.dumps(node2_data, indent=2)
    relationships_text = json.dumps(relationships, indent=2)
    
    prompt = PromptTemplate(
        input_variables=['node1_data', 'node2_data', 'relationships', 'schema'],
        template="""
You are a cybersecurity analyst providing clear, concise summaries of knowledge graph relationships.

## Task
Given two connected nodes from a cybersecurity knowledge graph, generate a professional 3-4 sentence summary 
that explains:
1. What each entity is (briefly explain the important context of each node.)
2. How they are related (the relationship between them)
3. Why this relationship matters in cybersecurity context
4. Potential implications or use cases

## Guidelines
- Be concise and informative (3-4 sentences)
- Explain the relationship naturally without using technical relationship names literally
- Focus on the practical meaning of the connection
- DO NOT mention property names or internal field names
- Make it readable and insightful
- Do not go into any of the links in order to explain about the node.
- Just summarize what is presented with the given set of properties.

{schema}

## First Node
{node1_data}

## Second Node
{node2_data}

## Relationship Between Node 1 and Node 2
{relationships}

## Summary:
"""
    )
    
    # Use LCEL (LangChain Expression Language) syntax
    chain = prompt | llm
    response = chain.invoke({
        "node1_data": node1_text,
        "node2_data": node2_text,
        "relationships": relationships_text,
        "schema": schema_text
    })
    
    return response.content.strip()


def summarize_three_nodes(node1_data, node2_data, node3_data, relationships, schema=""):
    """
    Generate a summary for three connected nodes with their relationships.
    
    Args:
        node1_data: json file that will contain the first node information
        node2_data: json file that will contain the second node information (middle node)
        node3_data: json file that will contain the third node information
        relationships: json file of the relationship between the first and the seond node and the second and the third node
        schema: schema information for context
        
    Returns:
        str: Generated summary
    """
    schema_text = f"## Schema Context (for reference)\n{schema}\n" if schema else ""
    node1_text = json.dumps(node1_data, indent=2)
    node2_text = json.dumps(node2_data, indent=2)
    node3_text = json.dumps(node3_data, indent=2)
    relationships_text = json.dumps(relationships, indent=2)
    
    prompt = PromptTemplate(
        input_variables=['node1_data', 'node2_data', 'node3_data', 'relationships', 'schema'],
        template="""
You are a cybersecurity analyst providing clear, concise summaries of complex knowledge graph patterns.

## Task
Given three connected nodes from a cybersecurity knowledge graph (Node1 → Node2 → Node3), 
generate a professional 4-5 sentence summary that explains:
1. What each entity is (briefly explain the important context of each node.)
2. How they are related (the relationship between them)
3. Why this relationship matters in cybersecurity context
4. Potential implications or use cases

## Guidelines
- Be concise but comprehensive (4-5 sentences)
- Tell a coherent story that flows through all three nodes
- Explain how the relationships create a meaningful pattern
- Focus on the "why" and "so what" for cybersecurity
- DO NOT mention property names or internal field names
- Make it insightful and actionable
- Do not go into any of the links in order to explain about the node.
- Just summarize what is presented with the given set of properties.

{schema}

## Node 1 (Start)
{node1_data}

## Node 2 (Middle)
{node2_data}

## Node 3 (End)
{node3_data}

## Relationship Between Node 1 and Node 2
The relationship(s) connecting the first node to the second node:
{relationships}

Note: The relationships data structure contains:
- "node1_to_node2": List of relationship types from Node 1 to Node 2
- "node2_to_node3": List of relationship types from Node 2 to Node 3


## Summary:
"""
    )
    
    # Use LCEL (LangChain Expression Language) syntax
    chain = prompt | llm
    response = chain.invoke({
        "node1_data": node1_text,
        "node2_data": node2_text,
        "node3_data": node3_text,
        "relationships": relationships_text,
        "schema": schema_text
    })
    
    return response.content.strip()


def process_node_groups(input_file, output_file, include_schema=True, output_format='txt'):
    """
    Process node groups from input file and generate summaries.
    
    Args:
        input_file: Path to JSON file with node data
        output_file: Path to save summaries
        include_schema: Whether to include schema context
        output_format: 'txt' for text file, 'json' for JSON file
    """
    # Load input data
    print(f"Loading data from: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    schema = schema_cache if include_schema else ""
    
    results = []
    
    for idx, item in enumerate(data, 1):
        print(f"\n{'='*60}")
        print(f"Processing item {idx}/{len(data)}")
        print(f"{'='*60}")
        
        try:
            # Check if it's an error result
            if "error" in item:
                print(f"⚠ Skipping item {idx}: {item['error']}")
                results.append({
                    "item_number": idx,
                    "status": "error",
                    "error": item["error"],
                    "summary": None
                })
                continue
            
            # Determine the type of data (1, 2, or 3 nodes)
            if "node" in item and "node1" not in item:
                # Single node
                print("Type: Single Node")
                print(f"Node labels: {item['node'].get('labels', [])}")
                
                summary = summarize_single_node(item['node'], schema)
                
                results.append({
                    "item_number": idx,
                    "type": "single_node",
                    "node": item['node'],
                    "summary": summary
                })
                
                print(f"\n✓ Summary generated:")
                print(f"  {summary}")
                
            elif "node1" in item and "node2" in item and "node3" not in item:
                # Two nodes
                print("Type: Two Connected Nodes")
                print(f"Node1 labels: {item['node1'].get('labels', [])}")
                print(f"Node2 labels: {item['node2'].get('labels', [])}")
                print(f"Relationships: {[r['type'] for r in item.get('relationships', [])]}")
                
                summary = summarize_two_nodes(
                    item['node1'],
                    item['node2'],
                    item.get('relationships', []),
                    schema
                )
                
                results.append({
                    "item_number": idx,
                    "type": "two_nodes",
                    "node1": item['node1'],
                    "node2": item['node2'],
                    "relationships": item.get('relationships', []),
                    "summary": summary
                })
                
                print(f"\n✓ Summary generated:")
                print(f"  {summary}")
                
            elif "node1" in item and "node2" in item and "node3" in item:
                # Three nodes
                print("Type: Three Connected Nodes")
                print(f"Node1 labels: {item['node1'].get('labels', [])}")
                print(f"Node2 labels: {item['node2'].get('labels', [])}")
                print(f"Node3 labels: {item['node3'].get('labels', [])}")
                
                rel_info = item.get('relationships', {})
                if isinstance(rel_info, dict):
                    rel_summary = {
                        "node1_to_node2": rel_info.get('node1_node2', []),
                        "node2_to_node3": rel_info.get('node2_node3', [])
                    }
                else:
                    rel_summary = rel_info
                    
                print(f"Relationships: {rel_summary}")
                
                summary = summarize_three_nodes(
                    item['node1'],
                    item['node2'],
                    item['node3'],
                    rel_summary,
                    schema
                )
                
                results.append({
                    "item_number": idx,
                    "type": "three_nodes",
                    "node1": item['node1'],
                    "node2": item['node2'],
                    "node3": item['node3'],
                    "relationships": rel_summary,
                    "summary": summary
                })
                
                print(f"\n✓ Summary generated:")
                print(f"  {summary}")
                
            else:
                print(f"⚠ Unknown data format for item {idx}")
                results.append({
                    "item_number": idx,
                    "status": "unknown_format",
                    "summary": None
                })
                
        except Exception as e:
            print(f"✗ Error processing item {idx}: {e}")
            results.append({
                "item_number": idx,
                "status": "processing_error",
                "error": str(e),
                "summary": None
            })
    
    # Save results
    print(f"\n{'='*60}")
    print(f"Saving results to: {output_file}")
    
    if output_format == 'txt':
        # Save as formatted text file (summaries only)
        with open(output_file, 'w', encoding='utf-8') as f:
            for idx, result in enumerate(results, 1):
                # Write summary only
                if 'summary' in result and result['summary']:
                    f.write(result['summary'])
                    # Add spacing between summaries if there are multiple items
                    if idx < len(results):
                        f.write("\n\n")
                elif 'error' in result:
                    f.write(f"ERROR: {result['error']}")
                    if idx < len(results):
                        f.write("\n\n")
    else:
        # Save as JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"✓ Successfully processed {len(results)} items")
    print(f"{'='*60}\n")
    
    return results


# Example usage
if __name__ == "__main__":
    # Configuration
    INPUT_FILE = "nodes.json"
    OUTPUT_FILE = "summary.txt"
    
    print("="*60)
    print("Node Summarization Script")
    print("="*60)
    print(f"Input file: {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"LLM Model: {OPENAI_MODEL}")
    print("="*60)
    
    # Check if input file exists
    if not os.path.exists(INPUT_FILE):
        print(f"\n✗ Error: Input file '{INPUT_FILE}' not found!")
        print(f"Please make sure the file exists in the current directory.")
        print(f"Current directory: {os.getcwd()}")
        exit(1)
    
    # Process the node groups and generate summaries
    try:
        results = process_node_groups(
            input_file=INPUT_FILE,
            output_file=OUTPUT_FILE,
            include_schema=True,  # Set to False if you don't want schema context
            output_format='txt'  # 'txt' for text file, 'json' for JSON file
        )
        
        print("\n" + "="*60)
        print("SUMMARY STATISTICS")
        print("="*60)
        
        # Count by type
        type_counts = {}
        for result in results:
            result_type = result.get('type', result.get('status', 'unknown'))
            type_counts[result_type] = type_counts.get(result_type, 0) + 1
        
        for result_type, count in type_counts.items():
            print(f"{result_type}: {count}")
        
        print("="*60)
        print(f"\n✓ All summaries saved to: {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
