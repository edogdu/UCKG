"""
Evaluate Retrieval Metrics: Precision, Recall, F1, and Entity Statistics

This script evaluates GraphRAG retrieval performance using metrics aligned with:
- Zhu et al. (2025) "Knowledge graph based question-answering model with subgraph retrieval optimization"

Metrics:
- Recall (Node Coverage): |G ∩ E| / |G| - What % of gold nodes were retrieved
- Precision (Answer Coverage Rate): |G ∩ E| / |E| - What % of retrieved are relevant
- F1 Score: Harmonic mean of Precision and Recall
- Average Retrieved Entities: Mean count of key_entities per query

Usage:
    # Evaluate specific experiment
    python evaluate_node_coverage.py --experiment baseline_vector

    # Evaluate legacy dataset (backward compatibility)
    python evaluate_node_coverage.py --dataset evaluation_dataset.json

    # List available experiments
    python evaluate_node_coverage.py --list
"""

import json
import os
import csv
import argparse
from typing import Dict, List, Any
from collections import defaultdict

from experiment_config import EXPERIMENTS, list_experiments


def evaluate_sample_coverage(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate coverage for a single sample
    
    Args:
        sample: Sample from evaluation dataset
        
    Returns:
        Dictionary with coverage metrics for this sample
    """
    metadata = sample.get('metadata', {})
    node_info = metadata.get('node_info', {})
    key_entities = sample.get('key_entities', [])
    
    # Extract ground truth node URIs
    first_node = node_info.get('first_node', '')
    second_node = node_info.get('second_node', '')
    third_node = node_info.get('third_node', '')
    
    # Convert key_entities to set for fast lookup
    key_entities_set = set(key_entities)
    
    # Check which nodes are found
    first_found = first_node in key_entities_set if first_node else False
    second_found = second_node in key_entities_set if second_node else False
    third_found = third_node in key_entities_set if third_node else False
    
    # Collect all ground truth nodes (non-empty)
    gold_nodes = [n for n in [first_node, second_node, third_node] if n]
    nodes_found = []
    if first_found:
        nodes_found.append(first_node)
    if second_found:
        nodes_found.append(second_node)
    if third_found:
        nodes_found.append(third_node)
    
    # Calculate coverage metrics
    coverage_count = sum([first_found, second_found, third_found])
    total_gold_nodes = len(gold_nodes)
    key_entities_count = len(key_entities)

    # Recall (Node Coverage): |G ∩ E| / |G|
    recall = coverage_count / total_gold_nodes if total_gold_nodes > 0 else 0.0

    # Precision (Answer Coverage Rate): |G ∩ E| / |E|
    precision = coverage_count / key_entities_count if key_entities_count > 0 else 0.0

    # F1 Score: 2 * P * R / (P + R)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Get retrieval stats
    retrieval_stats = metadata.get('retrieval_stats', {})
    num_sources = retrieval_stats.get('num_sources', 0)

    return {
        'sample_id': sample.get('id', 0),
        'question': sample.get('question', '')[:60] + '...' if len(sample.get('question', '')) > 60 else sample.get('question', ''),
        'hop_count': metadata.get('hop_count', 0),
        'question_type': node_info.get('type', ''),
        'gold_nodes': gold_nodes,
        'nodes_found': nodes_found,
        'first_node': first_node,
        'second_node': second_node,
        'third_node': third_node,
        'first_found': first_found,
        'second_found': second_found,
        'third_found': third_found,
        'coverage_count': coverage_count,
        'total_gold_nodes': total_gold_nodes,
        'coverage_ratio': recall,  # Keep for backward compatibility
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'key_entities_count': key_entities_count,
        'num_sources': num_sources
    }


def evaluate_dataset(dataset_path: str) -> Dict[str, Any]:
    """
    Evaluate entire dataset
    
    Args:
        dataset_path: Path to evaluation dataset JSON file
        
    Returns:
        Dictionary with aggregate metrics
    """
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    samples = data.get('samples', [])
    
    print(f"Evaluating {len(samples)} samples...")
    print("=" * 80)
    
    # Aggregate metrics by hop count
    metrics_by_hop = defaultdict(lambda: {
        'total': 0,
        'coverage_counts': [],  # List of coverage counts (0, 1, 2, or 3)
        'recalls': [],  # List of recall values (0.0 to 1.0)
        'precisions': [],  # List of precision values (0.0 to 1.0)
        'f1s': [],  # List of F1 scores (0.0 to 1.0)
        'key_entities_counts': [],  # List of retrieved entity counts
        'num_sources_list': [],  # List of source counts
        'perfect_coverage': 0,  # Count of samples with 100% recall
        'partial_coverage': 0,  # Count of samples with >0% but <100% recall
        'no_coverage': 0,  # Count of samples with 0% recall
    })

    # Aggregate by question type
    metrics_by_type = defaultdict(lambda: {
        'total': 0,
        'coverage_counts': [],
        'recalls': [],
        'precisions': [],
        'f1s': [],
        'key_entities_counts': [],
        'num_sources_list': [],
        'perfect_coverage': 0,
        'partial_coverage': 0,
        'no_coverage': 0,
    })
    
    all_results = []
    
    for i, sample in enumerate(samples, 1):
        print(f"[{i}/{len(samples)}] Evaluating sample {sample.get('id', i)}...", end='\r')
        
        result = evaluate_sample_coverage(sample)
        all_results.append(result)
        
        hop_count = result['hop_count']
        question_type = result['question_type']
        
        # Update aggregates
        metrics_by_hop[hop_count]['total'] += 1
        metrics_by_type[question_type]['total'] += 1

        metrics_by_hop[hop_count]['coverage_counts'].append(result['coverage_count'])
        metrics_by_type[question_type]['coverage_counts'].append(result['coverage_count'])

        metrics_by_hop[hop_count]['recalls'].append(result['recall'])
        metrics_by_type[question_type]['recalls'].append(result['recall'])

        metrics_by_hop[hop_count]['precisions'].append(result['precision'])
        metrics_by_type[question_type]['precisions'].append(result['precision'])

        metrics_by_hop[hop_count]['f1s'].append(result['f1'])
        metrics_by_type[question_type]['f1s'].append(result['f1'])

        metrics_by_hop[hop_count]['key_entities_counts'].append(result['key_entities_count'])
        metrics_by_type[question_type]['key_entities_counts'].append(result['key_entities_count'])

        metrics_by_hop[hop_count]['num_sources_list'].append(result['num_sources'])
        metrics_by_type[question_type]['num_sources_list'].append(result['num_sources'])

        # Update coverage categories
        if result['recall'] == 1.0:
            metrics_by_hop[hop_count]['perfect_coverage'] += 1
            metrics_by_type[question_type]['perfect_coverage'] += 1
        elif result['recall'] > 0.0:
            metrics_by_hop[hop_count]['partial_coverage'] += 1
            metrics_by_type[question_type]['partial_coverage'] += 1
        else:
            metrics_by_hop[hop_count]['no_coverage'] += 1
            metrics_by_type[question_type]['no_coverage'] += 1
    
    print()  # New line after progress
    
    # Calculate aggregate statistics
    results = {
        'total_samples': len(samples),
        'by_hop_count': {},
        'by_question_type': {},
        'overall': {
            'avg_recall': 0.0,
            'avg_precision': 0.0,
            'avg_f1': 0.0,
            'avg_coverage_count': 0.0,
            'avg_key_entities': 0.0,
            'avg_num_sources': 0.0,
            'perfect_coverage_pct': 0.0,
            'partial_coverage_pct': 0.0,
            'no_coverage_pct': 0.0,
        },
        'detailed_results': all_results
    }
    
    # Aggregate by hop count
    for hop, stats in metrics_by_hop.items():
        hop_label = {0: '0-hop', 1: '1-hop', 2: '2-hop'}.get(hop, f'{hop}-hop')
        total = stats['total']

        results['by_hop_count'][hop_label] = {
            'total_questions': total,
            'avg_recall': sum(stats['recalls']) / len(stats['recalls']) if stats['recalls'] else 0.0,
            'avg_precision': sum(stats['precisions']) / len(stats['precisions']) if stats['precisions'] else 0.0,
            'avg_f1': sum(stats['f1s']) / len(stats['f1s']) if stats['f1s'] else 0.0,
            'avg_coverage_count': sum(stats['coverage_counts']) / len(stats['coverage_counts']) if stats['coverage_counts'] else 0.0,
            'avg_key_entities': sum(stats['key_entities_counts']) / len(stats['key_entities_counts']) if stats['key_entities_counts'] else 0.0,
            'avg_num_sources': sum(stats['num_sources_list']) / len(stats['num_sources_list']) if stats['num_sources_list'] else 0.0,
            'perfect_coverage': stats['perfect_coverage'],
            'perfect_coverage_pct': (stats['perfect_coverage'] / total * 100) if total > 0 else 0.0,
            'partial_coverage': stats['partial_coverage'],
            'partial_coverage_pct': (stats['partial_coverage'] / total * 100) if total > 0 else 0.0,
            'no_coverage': stats['no_coverage'],
            'no_coverage_pct': (stats['no_coverage'] / total * 100) if total > 0 else 0.0,
        }
    
    # Aggregate by question type
    for qtype, stats in metrics_by_type.items():
        total = stats['total']

        results['by_question_type'][qtype] = {
            'total_questions': total,
            'avg_recall': sum(stats['recalls']) / len(stats['recalls']) if stats['recalls'] else 0.0,
            'avg_precision': sum(stats['precisions']) / len(stats['precisions']) if stats['precisions'] else 0.0,
            'avg_f1': sum(stats['f1s']) / len(stats['f1s']) if stats['f1s'] else 0.0,
            'avg_coverage_count': sum(stats['coverage_counts']) / len(stats['coverage_counts']) if stats['coverage_counts'] else 0.0,
            'avg_key_entities': sum(stats['key_entities_counts']) / len(stats['key_entities_counts']) if stats['key_entities_counts'] else 0.0,
            'avg_num_sources': sum(stats['num_sources_list']) / len(stats['num_sources_list']) if stats['num_sources_list'] else 0.0,
            'perfect_coverage': stats['perfect_coverage'],
            'perfect_coverage_pct': (stats['perfect_coverage'] / total * 100) if total > 0 else 0.0,
            'partial_coverage': stats['partial_coverage'],
            'partial_coverage_pct': (stats['partial_coverage'] / total * 100) if total > 0 else 0.0,
            'no_coverage': stats['no_coverage'],
            'no_coverage_pct': (stats['no_coverage'] / total * 100) if total > 0 else 0.0,
        }
    
    # Calculate overall statistics
    all_recalls = [r['recall'] for r in all_results]
    all_precisions = [r['precision'] for r in all_results]
    all_f1s = [r['f1'] for r in all_results]
    all_coverage_counts = [r['coverage_count'] for r in all_results]
    all_key_entities = [r['key_entities_count'] for r in all_results]
    all_num_sources = [r['num_sources'] for r in all_results]

    results['overall']['avg_recall'] = sum(all_recalls) / len(all_recalls) if all_recalls else 0.0
    results['overall']['avg_precision'] = sum(all_precisions) / len(all_precisions) if all_precisions else 0.0
    results['overall']['avg_f1'] = sum(all_f1s) / len(all_f1s) if all_f1s else 0.0
    results['overall']['avg_coverage_count'] = sum(all_coverage_counts) / len(all_coverage_counts) if all_coverage_counts else 0.0
    results['overall']['avg_key_entities'] = sum(all_key_entities) / len(all_key_entities) if all_key_entities else 0.0
    results['overall']['avg_num_sources'] = sum(all_num_sources) / len(all_num_sources) if all_num_sources else 0.0

    perfect = sum(1 for r in all_results if r['recall'] == 1.0)
    partial = sum(1 for r in all_results if 0.0 < r['recall'] < 1.0)
    none = sum(1 for r in all_results if r['recall'] == 0.0)

    results['overall']['perfect_coverage_pct'] = (perfect / len(samples) * 100) if samples else 0.0
    results['overall']['partial_coverage_pct'] = (partial / len(samples) * 100) if samples else 0.0
    results['overall']['no_coverage_pct'] = (none / len(samples) * 100) if samples else 0.0
    
    return results


def export_to_csv(all_results: List[Dict[str, Any]], output_path: str):
    """
    Export detailed results to CSV file
    
    Args:
        all_results: List of evaluation results
        output_path: Path to output CSV file
    """
    if not all_results:
        print("No results to export")
        return
    
    fieldnames = [
        'sample_id',
        'question',
        'hop_count',
        'question_type',
        'first_node',
        'first_found',
        'second_node',
        'second_found',
        'third_node',
        'third_found',
        'coverage_count',
        'total_gold_nodes',
        'recall',
        'precision',
        'f1',
        'key_entities_count',
        'num_sources',
        'nodes_found',
        'gold_nodes'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in all_results:
            row = {
                'sample_id': result['sample_id'],
                'question': result['question'],
                'hop_count': result['hop_count'],
                'question_type': result['question_type'],
                'first_node': result['first_node'],
                'first_found': 'Yes' if result['first_found'] else 'No',
                'second_node': result['second_node'],
                'second_found': 'Yes' if result['second_found'] else 'No',
                'third_node': result['third_node'],
                'third_found': 'Yes' if result['third_found'] else 'No',
                'coverage_count': result['coverage_count'],
                'total_gold_nodes': result['total_gold_nodes'],
                'recall': f"{result['recall']:.4f}",
                'precision': f"{result['precision']:.4f}",
                'f1': f"{result['f1']:.4f}",
                'key_entities_count': result['key_entities_count'],
                'num_sources': result['num_sources'],
                'nodes_found': '; '.join(result['nodes_found']) if result['nodes_found'] else '',
                'gold_nodes': '; '.join(result['gold_nodes']) if result['gold_nodes'] else ''
            }
            writer.writerow(row)
    
    print(f"CSV exported to: {output_path}")


def print_detailed_coverage(all_results: List[Dict[str, Any]], limit: int = 10):
    """
    Print detailed coverage information for samples

    Args:
        all_results: List of evaluation results
        limit: Maximum number of samples to print
    """
    print("\n" + "=" * 80)
    print("DETAILED SAMPLE ANALYSIS (First {} samples)".format(limit))
    print("=" * 80)

    for i, result in enumerate(all_results[:limit], 1):
        print(f"\nQ{result['sample_id']}: {result['coverage_count']}/{result['total_gold_nodes']} gold nodes found in {result['key_entities_count']} retrieved")
        print(f"  Question: {result['question']}")
        print(f"  Recall: {result['recall']:.1%} | Precision: {result['precision']:.1%} | F1: {result['f1']:.1%}")
        print(f"  1st Node: {'✓' if result['first_found'] else '✗'} {result['first_node'][:60]}..." if len(result['first_node']) > 60 else f"  1st Node: {'✓' if result['first_found'] else '✗'} {result['first_node']}")
        if result['second_node']:
            print(f"  2nd Node: {'✓' if result['second_found'] else '✗'} {result['second_node'][:60]}..." if len(result['second_node']) > 60 else f"  2nd Node: {'✓' if result['second_found'] else '✗'} {result['second_node']}")
        if result['third_node']:
            print(f"  3rd Node: {'✓' if result['third_found'] else '✗'} {result['third_node'][:60]}..." if len(result['third_node']) > 60 else f"  3rd Node: {'✓' if result['third_found'] else '✗'} {result['third_node']}")

    if len(all_results) > limit:
        print(f"\n... and {len(all_results) - limit} more samples")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Evaluate GraphRAG retrieval metrics (Precision, Recall, F1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evaluate_node_coverage.py --experiment baseline_vector
  python evaluate_node_coverage.py --dataset evaluation_dataset.json
  python evaluate_node_coverage.py --list
        """
    )

    parser.add_argument(
        "--experiment", "-e",
        type=str,
        help="Name of the experiment to evaluate (reads from experiments/<name>/)"
    )
    parser.add_argument(
        "--dataset", "-d",
        type=str,
        help="Path to evaluation dataset JSON file (for backward compatibility)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available experiments"
    )
    parser.add_argument(
        "--no-details",
        action="store_true",
        help="Skip detailed sample analysis output"
    )

    return parser.parse_args()


def print_results(results: Dict[str, Any], experiment_name: str = None):
    """Print evaluation results to console."""
    print()
    print("=" * 80)
    print("EVALUATION RESULTS")
    if experiment_name:
        print(f"Experiment: {experiment_name}")
    print("=" * 80)
    print()

    print(f"Total Samples: {results['total_samples']}")
    print()

    print("Overall Retrieval Metrics:")
    print("-" * 80)
    overall = results['overall']
    print(f"  Recall (Node Coverage):     {overall['avg_recall']:.2%}")
    print(f"  Precision (Answer Coverage): {overall['avg_precision']:.2%}")
    print(f"  F1 Score:                    {overall['avg_f1']:.2%}")
    print()
    print("  Retrieval Statistics:")
    print(f"    Avg Gold Nodes Found:      {overall['avg_coverage_count']:.2f}")
    print(f"    Avg Retrieved Entities:    {overall['avg_key_entities']:.2f}")
    print(f"    Avg Sources:               {overall['avg_num_sources']:.2f}")
    print()
    print("  Coverage Categories:")
    print(f"    Perfect (100% Recall):     {overall['perfect_coverage_pct']:.1f}%")
    print(f"    Partial (>0% Recall):      {overall['partial_coverage_pct']:.1f}%")
    print(f"    None (0% Recall):          {overall['no_coverage_pct']:.1f}%")

    print()
    print("Results by Hop Count:")
    print("-" * 80)
    for hop, metrics in sorted(results['by_hop_count'].items()):
        print(f"\n{hop}:")
        print(f"  Questions: {metrics['total_questions']}")
        print(f"  Recall:    {metrics['avg_recall']:.2%}  |  Precision: {metrics['avg_precision']:.2%}  |  F1: {metrics['avg_f1']:.2%}")
        print(f"  Avg Retrieved Entities: {metrics['avg_key_entities']:.1f}  |  Avg Sources: {metrics['avg_num_sources']:.1f}")
        print(f"  Coverage: Perfect {metrics['perfect_coverage']} ({metrics['perfect_coverage_pct']:.1f}%) | "
              f"Partial {metrics['partial_coverage']} ({metrics['partial_coverage_pct']:.1f}%) | "
              f"None {metrics['no_coverage']} ({metrics['no_coverage_pct']:.1f}%)")

    print()
    print("Results by Question Type:")
    print("-" * 80)
    for qtype, metrics in sorted(results['by_question_type'].items()):
        print(f"\n{qtype}:")
        print(f"  Questions: {metrics['total_questions']}")
        print(f"  Recall:    {metrics['avg_recall']:.2%}  |  Precision: {metrics['avg_precision']:.2%}  |  F1: {metrics['avg_f1']:.2%}")
        print(f"  Avg Retrieved Entities: {metrics['avg_key_entities']:.1f}  |  Avg Sources: {metrics['avg_num_sources']:.1f}")
        print(f"  Coverage: Perfect {metrics['perfect_coverage']} ({metrics['perfect_coverage_pct']:.1f}%) | "
              f"Partial {metrics['partial_coverage']} ({metrics['partial_coverage_pct']:.1f}%) | "
              f"None {metrics['no_coverage']} ({metrics['no_coverage_pct']:.1f}%)")


def main():
    args = parse_args()

    # List experiments if requested
    if args.list:
        list_experiments()
        # Also show existing experiment results
        script_dir = os.path.dirname(os.path.abspath(__file__))
        experiments_dir = os.path.join(script_dir, "experiments")
        if os.path.exists(experiments_dir):
            print("\nExisting experiment results:")
            print("-" * 70)
            for exp_name in sorted(os.listdir(experiments_dir)):
                exp_path = os.path.join(experiments_dir, exp_name)
                if os.path.isdir(exp_path):
                    dataset_file = os.path.join(exp_path, "evaluation_dataset.json")
                    results_file = os.path.join(exp_path, "retrieval_metrics_results.json")
                    has_dataset = os.path.exists(dataset_file)
                    has_results = os.path.exists(results_file)
                    status = []
                    if has_dataset:
                        status.append("dataset")
                    if has_results:
                        status.append("evaluated")
                    print(f"  {exp_name:25} [{', '.join(status) if status else 'empty'}]")
        return

    # Get dataset path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    experiment_name = None

    if args.experiment:
        # Use experiment directory
        experiment_name = args.experiment
        experiment_dir = os.path.join(script_dir, "experiments", args.experiment)
        dataset_path = os.path.join(experiment_dir, "evaluation_dataset.json")
        output_dir = experiment_dir

        if not os.path.exists(dataset_path):
            print(f"ERROR: Dataset not found at {dataset_path}")
            print(f"Run first: python create_evaluation_dataset.py --experiment {args.experiment}")
            return

    elif args.dataset:
        # Use specified dataset file
        dataset_path = args.dataset
        output_dir = os.path.dirname(dataset_path) or script_dir

        if not os.path.exists(dataset_path):
            print(f"ERROR: Dataset not found at {dataset_path}")
            return

    else:
        # Default: use legacy evaluation_dataset.json
        dataset_path = os.path.join(script_dir, 'evaluation_dataset.json')
        output_dir = script_dir

        if not os.path.exists(dataset_path):
            print("ERROR: No dataset specified and default evaluation_dataset.json not found.")
            print("Use --experiment <name> or --dataset <path>")
            return

    print("=" * 80)
    print("GraphRAG Retrieval Evaluation")
    print("=" * 80)
    if experiment_name:
        print(f"Experiment: {experiment_name}")
    print(f"Dataset: {dataset_path}")
    print()

    # Run evaluation
    results = evaluate_dataset(dataset_path)

    # Add experiment name to results
    if experiment_name:
        results['experiment_name'] = experiment_name

    # Print results
    print_results(results, experiment_name)

    # Print detailed coverage for first few samples
    if not args.no_details:
        print_detailed_coverage(results['detailed_results'], limit=10)

    print()
    print("=" * 80)

    # Save results to JSON
    json_output_file = os.path.join(output_dir, 'retrieval_metrics_results.json')
    with open(json_output_file, 'w', encoding='utf-8') as f:
        # Remove detailed_results from saved output to keep file size manageable
        save_results = {k: v for k, v in results.items() if k != 'detailed_results'}
        json.dump(save_results, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {json_output_file}")

    # Export detailed results to CSV for visualization
    csv_output_file = os.path.join(output_dir, 'retrieval_metrics_detailed.csv')
    export_to_csv(results['detailed_results'], csv_output_file)

    if experiment_name:
        print(f"\nTo compare experiments, run:")
        print(f"  python compare_experiments.py")


if __name__ == "__main__":
    main()
