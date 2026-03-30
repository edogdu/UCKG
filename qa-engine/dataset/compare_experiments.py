"""
Compare Experiments: Generate comparison reports across multiple GraphRAG experiments

This script loads evaluation results from multiple experiments and generates
comparison tables and reports.

Supports the naming convention: {embedding}_{retrieval_method}
  - Groups results by embedding model (nomic, gemma, etc.)
  - Compares retrieval methods within and across embedding models

Usage:
    # Compare all experiments with results
    python compare_experiments.py

    # Compare specific experiments
    python compare_experiments.py --experiments nomic_baseline nomic_hybrid_04

    # Filter by embedding model
    python compare_experiments.py --embedding nomic

    # Export comparison to CSV
    python compare_experiments.py --output comparison.csv
"""

import os
import json
import argparse
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

from experiment_config import EXPERIMENTS, EMBEDDING_CONFIGS


def extract_embedding_model(experiment_name: str) -> str:
    """Extract embedding model prefix from experiment name"""
    for emb_name in EMBEDDING_CONFIGS.keys():
        if experiment_name.startswith(f"{emb_name}_"):
            return emb_name
    return "unknown"


def extract_retrieval_method(experiment_name: str) -> str:
    """Extract retrieval method suffix from experiment name"""
    for emb_name in EMBEDDING_CONFIGS.keys():
        if experiment_name.startswith(f"{emb_name}_"):
            return experiment_name[len(emb_name) + 1:]
    return experiment_name


def load_experiment_results(experiments_dir: str, experiment_names: Optional[List[str]] = None,
                           embedding_filter: Optional[str] = None) -> Dict[str, Dict]:
    """
    Load evaluation results from experiment directories.

    Args:
        experiments_dir: Path to experiments directory
        experiment_names: Optional list of specific experiments to load
        embedding_filter: Optional embedding model to filter by

    Returns:
        Dictionary mapping experiment names to their results
    """
    results = {}

    if not os.path.exists(experiments_dir):
        return results

    # Get list of experiments to check
    if experiment_names:
        dirs_to_check = experiment_names
    else:
        dirs_to_check = [d for d in os.listdir(experiments_dir)
                        if os.path.isdir(os.path.join(experiments_dir, d))]

    for exp_name in sorted(dirs_to_check):
        # Apply embedding filter if specified
        if embedding_filter and not exp_name.startswith(f"{embedding_filter}_"):
            continue

        exp_dir = os.path.join(experiments_dir, exp_name)
        results_file = os.path.join(exp_dir, "retrieval_metrics_results.json")
        config_file = os.path.join(exp_dir, "config.json")

        if os.path.exists(results_file):
            with open(results_file, 'r', encoding='utf-8') as f:
                exp_results = json.load(f)

            # Load config if available
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    exp_config = json.load(f)
                exp_results['config'] = exp_config

            # Add extracted metadata
            exp_results['embedding_model'] = extract_embedding_model(exp_name)
            exp_results['retrieval_method'] = extract_retrieval_method(exp_name)

            results[exp_name] = exp_results

    return results


def generate_comparison_table(results: Dict[str, Dict]) -> str:
    """
    Generate a formatted comparison table grouped by embedding model.

    Args:
        results: Dictionary of experiment results

    Returns:
        Formatted table string
    """
    if not results:
        return "No experiment results found."

    # Header
    lines = []
    lines.append("=" * 110)
    lines.append("EXPERIMENT COMPARISON REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 110)
    lines.append("")

    # Group experiments by embedding model
    by_embedding = defaultdict(dict)
    for exp_name, exp_results in results.items():
        emb = exp_results.get('embedding_model', 'unknown')
        by_embedding[emb][exp_name] = exp_results

    # Overall metrics table (grouped by embedding)
    for emb_name in sorted(by_embedding.keys()):
        emb_results = by_embedding[emb_name]
        emb_model = EMBEDDING_CONFIGS.get(emb_name, {}).get('embedding_model', emb_name)

        lines.append(f"[{emb_name.upper()}] {emb_model}")
        lines.append("-" * 110)
        header = f"  {'Experiment':<28} {'Recall':>10} {'Precision':>10} {'F1':>10} {'Avg Entities':>15} {'Samples':>10}"
        lines.append(header)
        lines.append("-" * 110)

        # Sort by F1 score descending
        sorted_experiments = sorted(
            emb_results.items(),
            key=lambda x: x[1].get('overall', {}).get('avg_f1', 0),
            reverse=True
        )

        for exp_name, exp_results in sorted_experiments:
            overall = exp_results.get('overall', {})
            recall = overall.get('avg_recall', 0) * 100
            precision = overall.get('avg_precision', 0) * 100
            f1 = overall.get('avg_f1', 0) * 100
            avg_entities = overall.get('avg_key_entities', 0)
            samples = exp_results.get('total_samples', 0)

            # Show just retrieval method for cleaner output
            display_name = exp_results.get('retrieval_method', exp_name)
            line = f"  {display_name:<28} {recall:>9.2f}% {precision:>9.2f}% {f1:>9.2f}% {avg_entities:>15.1f} {samples:>10}"
            lines.append(line)

        lines.append("")

    # Best metrics summary (across all embeddings)
    lines.append("=" * 110)
    lines.append("BEST PERFORMERS (Overall)")
    lines.append("-" * 110)

    metrics = [
        ('Recall', 'avg_recall'),
        ('Precision', 'avg_precision'),
        ('F1 Score', 'avg_f1'),
    ]

    for metric_name, metric_key in metrics:
        best_exp = max(results.items(), key=lambda x: x[1].get('overall', {}).get(metric_key, 0))
        best_value = best_exp[1].get('overall', {}).get(metric_key, 0) * 100
        lines.append(f"  Best {metric_name:<12}: {best_exp[0]} ({best_value:.2f}%)")

    lines.append("")

    # Breakdown by hop count (grouped by embedding)
    lines.append("=" * 110)
    lines.append("BREAKDOWN BY HOP COUNT")
    lines.append("-" * 110)

    for emb_name in sorted(by_embedding.keys()):
        emb_results = by_embedding[emb_name]
        lines.append(f"\n[{emb_name.upper()}]")

        sorted_experiments = sorted(
            emb_results.items(),
            key=lambda x: x[1].get('overall', {}).get('avg_f1', 0),
            reverse=True
        )

        for hop in ['0-hop', '1-hop', '2-hop']:
            lines.append(f"  {hop}:")
            header = f"    {'Method':<26} {'Recall':>10} {'Precision':>10} {'F1':>10}"
            lines.append(header)

            for exp_name, exp_results in sorted_experiments:
                hop_metrics = exp_results.get('by_hop_count', {}).get(hop, {})
                if hop_metrics:
                    recall = hop_metrics.get('avg_recall', 0) * 100
                    precision = hop_metrics.get('avg_precision', 0) * 100
                    f1 = hop_metrics.get('avg_f1', 0) * 100
                    display_name = exp_results.get('retrieval_method', exp_name)
                    line = f"    {display_name:<26} {recall:>9.2f}% {precision:>9.2f}% {f1:>9.2f}%"
                    lines.append(line)
            lines.append("")

    lines.append("=" * 110)

    return "\n".join(lines)


def export_comparison_csv(results: Dict[str, Dict], output_path: str):
    """
    Export comparison results to CSV.

    Args:
        results: Dictionary of experiment results
        output_path: Path to output CSV file
    """
    import csv

    rows = []
    for exp_name, exp_results in sorted(results.items()):
        overall = exp_results.get('overall', {})
        config = exp_results.get('config', {}).get('config', {})

        row = {
            'experiment': exp_name,
            'embedding_model': exp_results.get('embedding_model', ''),
            'retrieval_method': exp_results.get('retrieval_method', ''),
            'description': exp_results.get('config', {}).get('description', ''),
            'total_samples': exp_results.get('total_samples', 0),
            'recall': overall.get('avg_recall', 0),
            'precision': overall.get('avg_precision', 0),
            'f1': overall.get('avg_f1', 0),
            'avg_key_entities': overall.get('avg_key_entities', 0),
            'avg_num_sources': overall.get('avg_num_sources', 0),
            'perfect_coverage_pct': overall.get('perfect_coverage_pct', 0),
            'no_coverage_pct': overall.get('no_coverage_pct', 0),
            # Config flags
            'enable_hybrid_retrieval': config.get('enable_hybrid_retrieval', False),
            'enable_cross_encoder': config.get('enable_cross_encoder', False),
            'enable_second_hop': config.get('enable_second_hop', True),
            'bm25_weight': config.get('bm25_weight', 0),
            'vector_weight': config.get('vector_weight', 0),
        }

        # Add hop-specific metrics
        for hop in ['0-hop', '1-hop', '2-hop']:
            hop_metrics = exp_results.get('by_hop_count', {}).get(hop, {})
            row[f'{hop}_recall'] = hop_metrics.get('avg_recall', 0)
            row[f'{hop}_precision'] = hop_metrics.get('avg_precision', 0)
            row[f'{hop}_f1'] = hop_metrics.get('avg_f1', 0)

        rows.append(row)

    # Write CSV
    if rows:
        fieldnames = rows[0].keys()
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Comparison exported to: {output_path}")


def save_comparison_json(results: Dict[str, Dict], output_path: str):
    """
    Save comparison results to JSON.

    Args:
        results: Dictionary of experiment results
        output_path: Path to output JSON file
    """
    comparison = {
        "generated_at": datetime.now().isoformat(),
        "num_experiments": len(results),
        "experiments": {}
    }

    for exp_name, exp_results in results.items():
        comparison["experiments"][exp_name] = {
            "embedding_model": exp_results.get("embedding_model", ""),
            "retrieval_method": exp_results.get("retrieval_method", ""),
            "overall": exp_results.get("overall", {}),
            "by_hop_count": exp_results.get("by_hop_count", {}),
            "by_question_type": exp_results.get("by_question_type", {}),
            "total_samples": exp_results.get("total_samples", 0),
            "config": exp_results.get("config", {})
        }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)

    print(f"Comparison JSON saved to: {output_path}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Compare GraphRAG experiment results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python compare_experiments.py
  python compare_experiments.py --experiments nomic_baseline nomic_hybrid_04
  python compare_experiments.py --embedding nomic
  python compare_experiments.py --output comparison.csv
        """
    )

    parser.add_argument(
        "--experiments", "-e",
        nargs="+",
        help="Specific experiments to compare (default: all with results)"
    )
    parser.add_argument(
        "--embedding",
        type=str,
        choices=list(EMBEDDING_CONFIGS.keys()),
        help="Filter by embedding model (e.g., nomic, gemma)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path for CSV export"
    )
    parser.add_argument(
        "--json",
        type=str,
        help="Output file path for JSON export"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Get experiments directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    experiments_dir = os.path.join(script_dir, "experiments")

    # Load results
    results = load_experiment_results(
        experiments_dir,
        args.experiments,
        embedding_filter=args.embedding
    )

    if not results:
        print("No experiment results found.")
        print(f"Looking in: {experiments_dir}")
        print("\nTo run an experiment:")
        print("  python create_evaluation_dataset.py --experiment nomic_baseline")
        print("  python evaluate_node_coverage.py --experiment nomic_baseline")
        return

    # Generate and print comparison table
    table = generate_comparison_table(results)
    print(table)

    # Export to CSV if requested
    if args.output:
        export_comparison_csv(results, args.output)

    # Export to JSON if requested
    if args.json:
        save_comparison_json(results, args.json)

    # Always save comparison JSON to experiments directory
    default_json = os.path.join(experiments_dir, "comparison_report.json")
    save_comparison_json(results, default_json)


if __name__ == "__main__":
    main()
