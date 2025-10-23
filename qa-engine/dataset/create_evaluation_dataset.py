"""
Dataset Generation Pipeline for Graph RAG Evaluation

This script:
1. Reads questions from questionSet/ folder JSON files
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
            "context": "...",  # Exact context passed to LLM
            "response": "...",  # Final generated answer
            "metadata": {
                "mode": "graphrag/hybrid",
                "source_file": "...",
                "difficulty": 1,
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

from multiRAG import MultiRAG

def load_questions_from_file(filepath: str) -> List[Dict[str, Any]]:
    """Load questions from a single JSON file"""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Handle different key names (question vs questions)
    questions = data.get('questions', data.get('question', []))
    
    # Add source file info to each question
    filename = os.path.basename(filepath)
    for q in questions:
        q['source_file'] = filename
    
    return questions

def load_all_questions(testing_dir: str) -> List[Dict[str, Any]]:
    """Load all questions from questionSet/ directory"""
    all_questions = []
    json_files = [f for f in os.listdir(testing_dir) if f.endswith('.json')]
    
    print(f"Found {len(json_files)} JSON files in {testing_dir}")
    
    for json_file in sorted(json_files):
        filepath = os.path.join(testing_dir, json_file)
        questions = load_questions_from_file(filepath)
        all_questions.extend(questions)
        print(f"  Loaded {len(questions)} questions from {json_file}")
    
    return all_questions

def run_question_through_pipeline(rag_engine: MultiRAG, question: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a single question through the MultiRAG pipeline and capture all relevant data
    
    Returns:
        Dictionary with question, context, response, and metadata
    """
    query_text = question['text']
    
    print(f"  Processing: {query_text[:80]}...")
    
    try:
        # Run the full pipeline
        result = rag_engine.run(query_text)
        
        # Extract the key components
        sample = {
            "question": query_text,
            "context": result.get("context", ""),  # The exact formatted context passed to LLM
            "response": result.get("answer", ""),  # The final generated answer
            "metadata": {
                "mode": result.get("mode", "unknown"),
                "source_file": question.get("source_file", ""),
                "difficulty": question.get("difficulty", 0),
                "node_info": {
                    "start_node": question.get("start_node", ""),
                    "1-hop_node": question.get("1-hop_node", ""),
                    "2-hop_node": question.get("2-hop_node", "")
                },
                "retrieval_stats": {
                    "num_sources": len(result.get("sources", [])),
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
            "context": "",
            "response": f"ERROR: {str(e)}",
            "metadata": {
                "mode": "error",
                "source_file": question.get("source_file", ""),
                "difficulty": question.get("difficulty", 0),
                "node_info": {
                    "start_node": question.get("start_node", ""),
                    "1-hop_node": question.get("1-hop_node", ""),
                    "2-hop_node": question.get("2-hop_node", "")
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
    print("\n[1/4] Loading questions from questionSet/ directory...")
    all_questions = load_all_questions(testing_dir)
    print(f"Total questions loaded: {len(all_questions)}")
    
    # Apply limit if specified
    if limit:
        all_questions = all_questions[:limit]
        print(f"Limited to first {limit} questions")
    
    # Initialize MultiRAG engine
    print("\n[2/4] Initializing MultiRAG engine...")
    rag_engine = MultiRAG()
    print("MultiRAG engine initialized")
    
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
            "pipeline": "MultiRAG GraphRAG 4-Stage Pipeline",
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
    TESTING_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "questionSet")
    OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "evaluation_dataset.json")
    
    # Optional: Limit number of questions for testing
    # Set to None to process all questions
    LIMIT = None  # Change to e.g., 10 for testing
    
    # Verify questionSet directory exists
    if not os.path.exists(TESTING_DIR):
        print(f"ERROR: questionSet directory not found at {TESTING_DIR}")
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
    
    # Difficulty distribution
    difficulties = {}
    for sample in dataset['samples']:
        diff = sample['metadata']['difficulty']
        difficulties[diff] = difficulties.get(diff, 0) + 1
    
    print(f"\nDifficulty distribution:")
    for diff, count in sorted(difficulties.items()):
        print(f"  Level {diff}: {count}")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    main()

