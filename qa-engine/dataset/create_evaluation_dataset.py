"""
Dataset Generation Pipeline for Graph RAG Evaluation

This script:
1. Reads questions from shared/question_set/ folder JSON files
   - questions_1node.json (0-hop questions)
   - questions_1hop.json (1-hop questions)
   - questions_2hop.json (2-hop questions)
2. Runs each question through the MultiRAG pipeline
3. Captures the exact context provided to the LLM
4. Captures the final text response
5. Saves to a structured JSON dataset

Output Format:
{
    "dataset_metadata": {
        "total_questions": N,
        "generation_date": "...",
        "source_files": [...]
    },
    "samples": [
        {
            "id": 1,
            "question": "...",
            "summary": "...",  # Context from question file (background info)
            "context": "...",  # Exact context passed to LLM
            "response": "...",  # Final generated answer
            "metadata": {
                "mode": "graphrag/hybrid",
                "source_file": "...",
                "hop_count": 0/1/2,
                "question_type": "<s,*,*>" / "<s,p,o>" / "<s,*,o>",
                "node_info": {...}
            }
        },
        ...
    ]
}
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrag import GraphRAGSimilarity

def extract_key_entities(sources: List[Dict]) -> List[str]:
    """Extract unique visited node URIs"""
    uri_set = set()
    
    for source in sources:
        if isinstance(source, dict) and 'metadata' in source:
            metadata = source.get("metadata", {})
            
            # Primary node
            primary = metadata.get("primarySource", {})
            primary_uri = primary.get("allProperties", {}).get("uri")
            if primary_uri:
                uri_set.add(primary_uri)
            
            # All neighbors (1-hop and 2-hop)
            neighbors = metadata.get("firstHopNeighbors", [])
            for neighbor in neighbors:
                # 1-hop
                neighbor_uri = neighbor.get("primaryNode", {}).get("allProperties", {}).get("uri")
                if neighbor_uri:
                    uri_set.add(neighbor_uri)
                
                # 2-hop
                for second_node in neighbor.get("secondHopNeighbors", []):
                    second_uri = second_node.get("relatedNode", {}).get("allProperties", {}).get("uri")
                    if second_uri:
                        uri_set.add(second_uri)
    
    return list(uri_set)

def load_questions_from_file(filepath: str) -> List[Dict[str, Any]]:
    """Load questions from a single JSON file"""
    with open(filepath, 'r') as f:
        data = json.load(f)

    # New format: files are direct arrays (no wrapper object)
    # Old format: files have wrapper with 'questions' or 'question' key
    if isinstance(data, list):
        questions = data
    else:
        # Fallback for old format with wrapper
        questions = data.get('questions', data.get('question', []))

    # Add source file info to each question
    filename = os.path.basename(filepath)
    for q in questions:
        q['source_file'] = filename

    return questions

def load_all_questions(testing_dir: str) -> List[Dict[str, Any]]:
    """Load all questions from question_set/ directory"""
    all_questions = []

    # Load all question files (excluding nodes.json)
    question_files = [
        'questions_0hop.json',
        'questions_0hop_bunny.json',
        'questions_1hop.json',
        'questions_1hop_bunny.json',
        'questions_2hop.json',
        'questions_2hop_bunny.json'
    ]

    print(f"Loading questions from {testing_dir}")

    for json_file in question_files:
        filepath = os.path.join(testing_dir, json_file)
        if os.path.exists(filepath):
            questions = load_questions_from_file(filepath)
            all_questions.extend(questions)
            print(f"  Loaded {len(questions)} questions from {json_file}")
        else:
            print(f"  WARNING: {json_file} not found, skipping...")

    return all_questions

def run_question_through_pipeline(rag_engine: GraphRAGSimilarity, question: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a single question through the GraphRAG pipeline and capture all relevant data

    Returns:
        Dictionary with question, context, response, and metadata
    """
    # Support both old format (key='text') and new format (key='question')
    query_text = question.get('question', question.get('text', ''))

    print(f"  Processing: {query_text[:80]}...")

    # Determine hop count from question type
    question_type = question.get("type", "")
    if question_type == "<s,*,*>":
        hop_count = 0  # 1-node question (no hops)
    elif question.get("third_node") or question.get("relationship_2"):
        hop_count = 2  # 2-hop question
    elif question.get("second_node") or question.get("relationship"):
        hop_count = 1  # 1-hop question
    else:
        hop_count = 0  # Default

    try:
        # Run the full pipeline
        result = rag_engine.run(query_text)

        # Extract the key components
        sample = {
            "question": query_text,
            "summary": question.get("context", ""),  # Background context from question file
            "context": result.get("context", ""),  # The exact formatted context passed to LLM
            "response": result.get("answer", ""),  # The final generated answer
            "key_entities": extract_key_entities(result.get("sources", [])),  # Unique URIs of all visited nodes
            "metadata": {
                "mode": result.get("mode", "unknown"),
                "source_file": question.get("source_file", ""),
                "hop_count": hop_count,
                "question_type": question_type,
                "node_info": {
                    "type": question_type,
                    "first_node": question.get("first_node", ""),
                    "second_node": question.get("second_node", ""),
                    "third_node": question.get("third_node", ""),
                    "relationship_1": question.get("relationship", question.get("relationship_1", "")),
                    "relationship_2": question.get("relationship_2", ""),
                    # "used_properties": {
                    #     "first_node": question.get("used_properties", question.get("used_properties_of_first_node", [])),
                    #     "second_node": question.get("used_properties_of_second_node", []),
                    #     "third_node": question.get("used_properties_of_third_node", [])
                    # }
                },
                "retrieval_stats": {
                    "num_sources": len(result.get("sources", [])),
                    "num_key_entities": len(extract_key_entities(result.get("sources", []))),
                    "node_types": result.get("enhanced_metadata", {}).get("node_types", []),
                    "relationship_types": result.get("enhanced_metadata", {}).get("relationship_types", [])
                }
            }
        }

        return sample

    except Exception as e:
        print(f"    ERROR: {str(e)}")
        return {
            "question": query_text,
            "summary": question.get("context", ""),  # Background context from question file
            "context": "",
            "response": f"ERROR: {str(e)}",
            "key_entities": [],  # Empty key entities on error
            "metadata": {
                "mode": "error",
                "source_file": question.get("source_file", ""),
                "hop_count": hop_count,
                "question_type": question_type,
                "node_info": {
                    "type": question_type,
                    "first_node": question.get("first_node", ""),
                    "second_node": question.get("second_node", ""),
                    "third_node": question.get("third_node", "")
                },
                "error": str(e)
            }
        }

def create_evaluation_dataset(
    testing_dir: str,
    output_file: str,
    limit: int = None
) -> Dict[str, Any]:
    """
    Main function to create the evaluation dataset
    
    Args:
        testing_dir: Path to questionSet/ directory with question JSON files
        output_file: Path to output JSON file
        limit: Optional limit on number of questions to process
    """
    print("="*80)
    print("Graph RAG Evaluation Dataset Generation Pipeline")
    print("="*80)
    
    # Load all questions
    print("\n[1/4] Loading questions from question_set/ directory...")
    all_questions = load_all_questions(testing_dir)
    print(f"Total questions loaded: {len(all_questions)}")
    
    # Apply limit if specified
    if limit:
        all_questions = all_questions[:limit]
        print(f"Limited to first {limit} questions")
    
    # Initialize GraphRAG engine
    print("\n[2/4] Initializing GraphRAG engine...")
    rag_engine = GraphRAGSimilarity()
    print("GraphRAG engine initialized")
    
    # Process each question
    print(f"\n[3/4] Processing {len(all_questions)} questions through pipeline...")
    samples = []
    for idx, question in enumerate(all_questions, 1):
        print(f"[{idx}/{len(all_questions)}]", end=" ")
        sample = run_question_through_pipeline(rag_engine, question)
        sample['id'] = idx  # Add sequential ID
        samples.append(sample)
    
    # Close engine
    rag_engine.close()
    
    # Create final dataset structure
    print("\n[4/4] Creating final dataset structure...")
    dataset = {
        "dataset_metadata": {
            "total_questions": len(samples),
            "generation_date": datetime.now().isoformat(),
            "source_files": list(set(q.get("source_file", "") for q in all_questions)),
            "pipeline": "GraphRAG 4-Stage Pipeline",
            "description": "Dataset for Graph RAG evaluation containing questions, exact LLM context, and generated responses"
        },
        "samples": samples
    }
    
    # Save to file
    print(f"Saving dataset to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\n✓ Dataset saved successfully!")
    print(f"  Total samples: {len(samples)}")
    print(f"  Output file: {output_file}")
    print(f"  File size: {os.path.getsize(output_file) / 1024:.2f} KB")
    
    return dataset

def main():
    """Main entry point"""
    # Configuration
    TESTING_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared", "question_set")
    OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "evaluation_dataset.json")
    
    # Optional: Limit number of questions for testing
    # Set to None to process all questions
    LIMIT = None  # Change to e.g., 10 for testing
    
    # Verify question_set directory exists
    if not os.path.exists(TESTING_DIR):
        print(f"ERROR: question_set directory not found at {TESTING_DIR}")
        return
    
    # Create dataset
    dataset = create_evaluation_dataset(
        testing_dir=TESTING_DIR,
        output_file=OUTPUT_FILE,
        limit=LIMIT
    )
    
    # Print summary statistics
    print("\n" + "="*80)
    print("DATASET SUMMARY")
    print("="*80)
    print(f"Total samples: {dataset['dataset_metadata']['total_questions']}")
    print(f"Source files: {', '.join(dataset['dataset_metadata']['source_files'])}")
    print(f"Generation date: {dataset['dataset_metadata']['generation_date']}")
    
    # Mode distribution
    modes = {}
    for sample in dataset['samples']:
        mode = sample['metadata']['mode']
        modes[mode] = modes.get(mode, 0) + 1
    
    print(f"\nMode distribution:")
    for mode, count in modes.items():
        print(f"  {mode}: {count}")
    
    # Hop count distribution
    hop_counts = {}
    for sample in dataset['samples']:
        hops = sample['metadata']['hop_count']
        hop_counts[hops] = hop_counts.get(hops, 0) + 1

    print(f"\nHop count distribution:")
    for hops, count in sorted(hop_counts.items()):
        hop_label = {0: "0-hop (1-node)", 1: "1-hop", 2: "2-hop"}.get(hops, f"{hops}-hop")
        print(f"  {hop_label}: {count}")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    main()

