"""
Dataset Generation Pipeline for Graph RAG Evaluation

This script:
1. Reads questions from shared/question_set/ folder JSON files
   - questions_0hop.json (0-hop questions)
   - questions_1hop.json (1-hop questions)
   - questions_2hop.json (2-hop questions)
2. Runs each question through the GraphRAG pipeline with specified configuration
3. Captures the exact context provided to the LLM
4. Captures the final text response
5. Saves to a structured JSON dataset in experiment directory

Features:
- Checkpoint/resume: Automatically saves progress and can resume after interruption
- Graceful shutdown: Press Ctrl+C to stop and save progress

Usage:
    # Run with specific experiment configuration
    python create_evaluation_dataset.py --experiment nomic_baseline

    # Resume interrupted experiment (auto-detected)
    python create_evaluation_dataset.py --experiment nomic_baseline

    # Force restart (ignore checkpoint)
    python create_evaluation_dataset.py --experiment nomic_baseline --restart

    # Run with limit for testing
    python create_evaluation_dataset.py --experiment nomic_baseline --limit 10

    # List available experiments
    python create_evaluation_dataset.py --list

Output: experiments/<experiment_name>/
    - config.json: Experiment configuration
    - evaluation_dataset.json: Generated dataset
    - .checkpoint.json: Temporary checkpoint (removed on completion)
"""

import os
import json
import argparse
import signal
import time
from datetime import datetime
from dataclasses import asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrag import GraphRAGPipeline
from experiment_config import (
    EXPERIMENTS,
    get_experiment_config,
    get_experiment_metadata,
    list_experiments
)


def _load_pipeline(pipeline_name: str, graphrag_config):
    """
    Factory function to create the appropriate pipeline.

    Args:
        pipeline_name: "graphrag" or "subgraphrag"
        graphrag_config: GraphRAGConfig instance (used for graphrag; ignored for subgraphrag)

    Returns:
        Pipeline instance with a .run(query) method and .close() method
    """
    if pipeline_name == "subgraphrag":
        from graphrag.baselines.subgraphrag import SubgraphRAGPipeline, SubgraphRAGConfig
        # Map experiment config fields to SubgraphRAGConfig where applicable
        subgraph_config = SubgraphRAGConfig()
        if graphrag_config is not None:
            # Mirror embedding settings from experiment config
            subgraph_config.embedding_backend = graphrag_config.embedding_backend
            subgraph_config.embedding_model = graphrag_config.embedding_model
            subgraph_config.embedding_query_prefix = graphrag_config.embedding_query_prefix
            subgraph_config.embedding_query_prompt = graphrag_config.embedding_query_prompt
            subgraph_config.embedding_doc_prompt = graphrag_config.embedding_doc_prompt
            # Apply scoring_mode if set in experiment config
            scoring_mode = getattr(graphrag_config, "_subgraphrag_scoring_mode", None)
            if scoring_mode:
                subgraph_config.scoring_mode = scoring_mode
            model_path = getattr(graphrag_config, "_subgraphrag_model_path", None)
            if model_path:
                subgraph_config.model_path = model_path
        return SubgraphRAGPipeline(subgraph_config)
    else:
        # Default: graphrag
        if graphrag_config:
            return GraphRAGPipeline(graphrag_config)
        return GraphRAGPipeline()


# Global flag for graceful shutdown
_shutdown_requested = False
_rag_engine = None


def signal_handler(signum, frame):
    """Handle interrupt signal for graceful shutdown"""
    global _shutdown_requested
    if _shutdown_requested:
        print("\n\nForce quitting...")
        sys.exit(1)
    print("\n\n⚠ Interrupt received. Saving progress and shutting down gracefully...")
    print("  (Press Ctrl+C again to force quit)")
    _shutdown_requested = True


def extract_key_entities(result: Dict) -> List[str]:
    """
    Extract key entities from pipeline result.
    Uses pre-extracted URIs if available (from pipeline), otherwise falls back to source extraction.

    Args:
        result: Pipeline result dictionary containing 'key_entities' and/or 'sources'

    Returns:
        List of unique URIs for all visited nodes
    """
    # Use pre-extracted key_entities if available (Option 4 - extracted at retrieval time)
    if "key_entities" in result and result["key_entities"]:
        return result["key_entities"]

    # Fallback: extract from sources (legacy support)
    return _extract_uris_from_sources(result.get("sources", []))


def _extract_uris_from_sources(sources: List[Dict]) -> List[str]:
    """
    Fallback extraction from source items.
    Handles both formats: with/without 'metadata' wrapper.
    """
    uri_set = set()

    for source in sources:
        # Handle post-reranking format (primarySource at top level)
        if 'primarySource' in source:
            primary = source.get("primarySource", {})
            neighbors = source.get("firstHopNeighbors", [])
        # Handle raw retrieval format (nested under metadata)
        elif 'metadata' in source:
            metadata = source.get("metadata", {})
            primary = metadata.get("primarySource", {})
            neighbors = metadata.get("firstHopNeighbors", [])
        else:
            continue

        # Primary node URI
        primary_uri = primary.get("allProperties", {}).get("uri")
        if primary_uri:
            uri_set.add(primary_uri)

        # 1-hop neighbor URIs
        for neighbor in neighbors:
            neighbor_uri = neighbor.get("primaryNode", {}).get("allProperties", {}).get("uri")
            if neighbor_uri:
                uri_set.add(neighbor_uri)

            # 2-hop neighbor URIs
            for second_hop in neighbor.get("secondHopNeighbors", []):
                second_uri = second_hop.get("relatedNode", {}).get("allProperties", {}).get("uri")
                if second_uri:
                    uri_set.add(second_uri)

    return list(uri_set)


def load_questions_from_file(filepath: str) -> List[Dict[str, Any]]:
    """Load questions from a single JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
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
        'questions_1hop.json',
        'questions_2hop.json'
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


def run_question_through_pipeline(rag_engine, question: Dict[str, Any]) -> Dict[str, Any]:
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
        t0 = time.perf_counter()
        result = rag_engine.run(query_text)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        pruning_metadata = result.get("pruning_metadata", {}) or {}
        pruning_status = pruning_metadata.get("status", "")
        pruning_enabled = pruning_status == "applied"

        # Extract the key components
        key_entities = extract_key_entities(result)  # Use pre-extracted URIs from pipeline

        # Save ranked primary sources for Hit@k/MRR evaluation
        ranked_sources = []
        for rank, src in enumerate(result.get("sources", []), 1):
            primary = src.get("primarySource", {})
            ranked_sources.append({
                "rank": rank,
                "uri": primary.get("allProperties", {}).get("uri", ""),
                "nodeLabel": primary.get("nodeLabel", ""),
                "nodeType": primary.get("nodeType", ""),
                "score": primary.get("score", 0.0),
            })

        sample = {
            "question": query_text,
            "summary": question.get("context", ""),  # Background context from question file
            "context": result.get("context", ""),  # The exact formatted context passed to LLM
            "response": result.get("answer", ""),  # The final generated answer
            "key_entities": key_entities,  # Unique URIs of all visited nodes
            "ranked_sources": ranked_sources,  # Ordered primary sources for Hit@k/MRR
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
                },
                "retrieval_stats": {
                    "num_sources": len(result.get("sources", [])),
                    "num_key_entities": len(key_entities),
                    "node_types": result.get("enhanced_metadata", {}).get("node_types", []),
                    "relationship_types": result.get("enhanced_metadata", {}).get("relationship_types", []),
                    "pruning_enabled": pruning_enabled,
                    "pruning_budget": pruning_metadata.get("budget"),
                    "pre_nodes": pruning_metadata.get("pre_nodes"),
                    "post_nodes": pruning_metadata.get("post_nodes"),
                    "prune_ratio": pruning_metadata.get("prune_ratio"),
                },
                "latency_ms": latency_ms,
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


def save_checkpoint(output_dir: str, samples: List[Dict], start_idx: int, total: int, experiment_name: str):
    """Save checkpoint for resume capability"""
    checkpoint_file = os.path.join(output_dir, ".checkpoint.json")
    checkpoint = {
        "experiment_name": experiment_name,
        "processed_count": len(samples),
        "total_questions": total,
        "start_idx": start_idx,
        "last_saved": datetime.now().isoformat(),
        "samples": samples
    }
    with open(checkpoint_file, 'w', encoding='utf-8') as f:
        json.dump(checkpoint, f, indent=2, ensure_ascii=False)


def load_checkpoint(output_dir: str, experiment_name: str) -> Optional[Dict]:
    """Load checkpoint if exists and matches experiment"""
    checkpoint_file = os.path.join(output_dir, ".checkpoint.json")
    if not os.path.exists(checkpoint_file):
        return None

    try:
        with open(checkpoint_file, 'r', encoding='utf-8') as f:
            checkpoint = json.load(f)

        # Verify experiment name matches
        if checkpoint.get("experiment_name") != experiment_name:
            print(f"  Checkpoint is for different experiment: {checkpoint.get('experiment_name')}")
            return None

        return checkpoint
    except Exception as e:
        print(f"  Warning: Could not load checkpoint: {e}")
        return None


def remove_checkpoint(output_dir: str):
    """Remove checkpoint file after successful completion"""
    checkpoint_file = os.path.join(output_dir, ".checkpoint.json")
    if os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)


def create_evaluation_dataset(
    testing_dir: str,
    output_dir: str,
    experiment_name: str,
    graphrag_config=None,
    limit: int = None,
    force_restart: bool = False,
    pipeline_name: str = "graphrag",
) -> Dict[str, Any]:
    """
    Main function to create the evaluation dataset with checkpoint/resume support

    Args:
        testing_dir: Path to questionSet/ directory with question JSON files
        output_dir: Path to experiment output directory
        experiment_name: Name of the experiment
        graphrag_config: GraphRAGConfig instance (optional, uses default if None)
        limit: Optional limit on number of questions to process
        force_restart: If True, ignore existing checkpoint and start fresh

    Returns:
        Generated dataset dictionary
    """
    global _shutdown_requested, _rag_engine

    print("=" * 80)
    print("Graph RAG Evaluation Dataset Generation Pipeline")
    print("=" * 80)
    print(f"Experiment: {experiment_name}")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Check for existing checkpoint
    samples = []
    start_idx = 0
    checkpoint = None

    if not force_restart:
        checkpoint = load_checkpoint(output_dir, experiment_name)
        if checkpoint:
            samples = checkpoint.get("samples", [])
            start_idx = len(samples)
            print(f"\n✓ Resuming from checkpoint: {start_idx}/{checkpoint.get('total_questions', '?')} completed")

    # Save experiment config
    config_file = os.path.join(output_dir, "config.json")
    experiment_metadata = get_experiment_metadata(experiment_name)
    if not checkpoint:
        experiment_metadata["generation_started"] = datetime.now().isoformat()

    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(experiment_metadata, f, indent=2, ensure_ascii=False)

    if not checkpoint:
        print(f"Config saved to: {config_file}")

    # Load all questions
    print("\n[1/4] Loading questions from question_set/ directory...")
    all_questions = load_all_questions(testing_dir)
    total_questions = len(all_questions)
    print(f"Total questions loaded: {total_questions}")

    # Apply limit if specified
    if limit:
        all_questions = all_questions[:limit]
        total_questions = len(all_questions)
        print(f"Limited to first {limit} questions")

    # Check if already complete
    if start_idx >= total_questions:
        print(f"\n✓ All {total_questions} questions already processed!")
        remove_checkpoint(output_dir)
        # Load existing dataset
        output_file = os.path.join(output_dir, "evaluation_dataset.json")
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"samples": samples}

    # Initialize pipeline engine with config
    print(f"\n[2/4] Initializing {pipeline_name} engine...")
    print(f"  Using experiment config: {experiment_name}")
    _rag_engine = _load_pipeline(pipeline_name, graphrag_config)
    print(f"{pipeline_name} engine initialized")

    # Set up signal handlers for graceful shutdown (SIGINT=Ctrl+C, SIGTERM=kill/Docker)
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    # Process each question
    remaining = total_questions - start_idx
    print(f"\n[3/4] Processing {remaining} questions through pipeline...")
    if start_idx > 0:
        print(f"  (Resuming from question {start_idx + 1})")

    try:
        for idx in range(start_idx, total_questions):
            if _shutdown_requested:
                print(f"\n  Stopping at question {idx}/{total_questions}")
                break

            question = all_questions[idx]
            print(f"[{idx + 1}/{total_questions}]", end=" ")
            sample = run_question_through_pipeline(_rag_engine, question)
            sample['id'] = idx + 1  # Add sequential ID
            samples.append(sample)

            # Save checkpoint every 5 questions
            if (idx + 1) % 5 == 0 or idx == total_questions - 1:
                save_checkpoint(output_dir, samples, start_idx, total_questions, experiment_name)

    except Exception as e:
        print(f"\n  Error during processing: {e}")
        print("  Saving checkpoint before exit...")
        save_checkpoint(output_dir, samples, start_idx, total_questions, experiment_name)
        raise

    finally:
        # Close engine
        if _rag_engine:
            _rag_engine.close()

    # Check if we completed or were interrupted
    completed = len(samples) >= total_questions and not _shutdown_requested

    if completed:
        # Create final dataset structure
        print("\n[4/4] Creating final dataset structure...")
        dataset = {
            "dataset_metadata": {
                "experiment_name": experiment_name,
                "total_questions": len(samples),
                "generation_date": datetime.now().isoformat(),
                "source_files": list(set(q.get("source_file", "") for q in all_questions)),
                "pipeline": "GraphRAG 4-Stage Pipeline",
                "description": "Dataset for Graph RAG evaluation containing questions, exact LLM context, and generated responses",
                "config": experiment_metadata.get("config", {})
            },
            "samples": samples
        }

        # Save to file
        output_file = os.path.join(output_dir, "evaluation_dataset.json")
        print(f"Saving dataset to {output_file}...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)

        # Update config with completion time
        experiment_metadata["generation_completed"] = datetime.now().isoformat()
        experiment_metadata["total_samples"] = len(samples)
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(experiment_metadata, f, indent=2, ensure_ascii=False)

        # Remove checkpoint
        remove_checkpoint(output_dir)

        print(f"\n✓ Dataset saved successfully!")
        print(f"  Total samples: {len(samples)}")
        print(f"  Output directory: {output_dir}")
        print(f"  Dataset file: {output_file}")
        print(f"  File size: {os.path.getsize(output_file) / 1024:.2f} KB")

        return dataset

    else:
        # Save checkpoint and exit
        save_checkpoint(output_dir, samples, start_idx, total_questions, experiment_name)
        print(f"\n⚠ Generation interrupted. Progress saved.")
        print(f"  Completed: {len(samples)}/{total_questions} questions")
        print(f"  Resume with: python create_evaluation_dataset.py --experiment {experiment_name}")

        return {"samples": samples, "interrupted": True}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate evaluation dataset for GraphRAG experiments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python create_evaluation_dataset.py --experiment nomic_baseline
  python create_evaluation_dataset.py --experiment nomic_baseline --limit 10
  python create_evaluation_dataset.py --experiment nomic_baseline --restart
  python create_evaluation_dataset.py --list
        """
    )

    parser.add_argument(
        "--experiment", "-e",
        type=str,
        help="Name of the experiment configuration to use"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=None,
        help="Limit number of questions to process (for testing)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available experiment configurations"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=None,
        help="Custom output directory (default: experiments/<experiment_name>)"
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Force restart, ignoring any existing checkpoint"
    )
    parser.add_argument(
        "--pipeline", "-p",
        type=str,
        default="graphrag",
        choices=["graphrag", "subgraphrag"],
        help="Pipeline to use for evaluation (default: graphrag)"
    )

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    # List experiments if requested
    if args.list:
        list_experiments()
        return

    # Require experiment name
    if not args.experiment:
        print("ERROR: --experiment is required. Use --list to see available experiments.")
        return

    # Validate experiment exists
    if args.experiment not in EXPERIMENTS:
        print(f"ERROR: Unknown experiment '{args.experiment}'")
        list_experiments()
        return

    # Configuration
    script_dir = os.path.dirname(os.path.abspath(__file__))
    testing_dir = os.path.join(os.path.dirname(script_dir), "shared", "question_set")

    # Output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(script_dir, "experiments", args.experiment)

    # Verify question_set directory exists
    if not os.path.exists(testing_dir):
        print(f"ERROR: question_set directory not found at {testing_dir}")
        return

    # Get experiment config
    graphrag_config = get_experiment_config(args.experiment)

    # Create dataset
    dataset = create_evaluation_dataset(
        testing_dir=testing_dir,
        output_dir=output_dir,
        experiment_name=args.experiment,
        graphrag_config=graphrag_config,
        limit=args.limit,
        force_restart=args.restart,
        pipeline_name=args.pipeline,
    )

    # Print summary statistics (only if completed)
    if not dataset.get("interrupted", False):
        print("\n" + "=" * 80)
        print("DATASET SUMMARY")
        print("=" * 80)
        print(f"Experiment: {args.experiment}")
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

        print(f"\nOutput directory: {output_dir}")
        print("\nNext step: Run evaluation with:")
        print(f"  python evaluate_node_coverage.py --experiment {args.experiment}")
        print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
