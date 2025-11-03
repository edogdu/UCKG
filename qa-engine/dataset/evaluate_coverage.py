"""
Evaluate GraphRAG Sub-graph Coverage Against Gold Standard

This script evaluates how well the retrieved sub-graphs cover the gold standard
sub-graphs from the question metadata.

Metrics:
- Node Coverage: Recall/Precision of nodes
- Relationship Coverage: Recall of relationship types
- Path Coverage: Whether complete paths are retrieved
"""

import json
import re
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict


def normalize_node_name(name: str) -> str:
    """
    Normalize node names for matching
    Remove special characters, convert to lowercase
    """
    if not name:
        return ""
    # Remove CWE/CVE/CAPEC IDs and special chars for fuzzy matching
    normalized = re.sub(r'(CWE-\d+|CVE-\d+-\d+|CAPEC-\d+):\s*', '', name)
    normalized = normalized.lower().strip()
    # Remove special punctuation
    normalized = re.sub(r'[:\-\(\)\[\]]', ' ', normalized)
    normalized = ' '.join(normalized.split())  # Normalize whitespace
    return normalized


def extract_node_id(name: str) -> Optional[str]:
    """Extract CWE/CVE/CAPEC ID from node name"""
    if not name:
        return None
    match = re.search(r'(CWE-\d+|CVE-\d+-\d+|CAPEC-\d+)', name, re.IGNORECASE)
    return match.group(1).upper() if match else None


def parse_context_for_missing_info(context: str, question_type: str) -> Dict[str, Any]:
    """
    Parse the context field to extract missing information for wildcard questions

    Args:
        context: The context string from question metadata
        question_type: The query pattern (e.g., "<s,p,*>")

    Returns:
        Dictionary with extracted information
    """
    result = {}

    if question_type == "<s,p,*>":
        # Extract target node from context
        # Pattern: mentions "CWE-XXX" or "CAPEC-XXX" or "CVE-XXXX-XXXX"
        patterns = [
            r'(CWE-\d+)[,\s"].*?"([^"]+)"',  # CWE-805, "Buffer Access..."
            r'(CAPEC-\d+)[,\s"].*?"([^"]+)"',
            r'(CVE-\d+-\d+)[,\s"].*?"([^"]+)"',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, context)
            if matches:
                # Get the last match (usually the target node)
                result['second_node'] = f"{matches[-1][0]}: {matches[-1][1]}"
                break

    elif question_type == "<s,*,o>":
        # Extract relationship from context
        # Look for relationship keywords
        relationship_map = {
            'related weakness': 'UCOEXHASRELATEDWEAKNESS',
            'has a related weakness': 'UCOEXHASRELATEDWEAKNESS',
            'has weakness': 'UCOHASWEAKNESS',
            'has vulnerability': 'UCOHASVULNERABILITY',
            'observed example': 'UCOHASOBSERVEDEXAMPLE',
            'has observed example': 'UCOHASOBSERVEDEXAMPLE',
        }
        context_lower = context.lower()
        for phrase, rel_type in relationship_map.items():
            if phrase in context_lower:
                result['relationship'] = rel_type
                break

    return result


def match_node_in_retrieved(gold_node: str, retrieved_sources: List[Dict]) -> Tuple[bool, Optional[Dict]]:
    """
    Check if a gold standard node appears in retrieved sources

    Returns:
        (found, matched_source)
    """
    if not gold_node:
        return False, None

    gold_id = extract_node_id(gold_node)
    gold_normalized = normalize_node_name(gold_node)

    for source in retrieved_sources:
        # Check primary node
        primary = source.get('primarySource', {})
        primary_label = primary.get('nodeLabel', '')

        # Try ID-based matching first
        if gold_id:
            primary_id = extract_node_id(primary_label)
            if primary_id and primary_id == gold_id:
                return True, {'type': 'primary', 'source': source}

        # Try fuzzy name matching
        if gold_normalized and normalize_node_name(primary_label) == gold_normalized:
            return True, {'type': 'primary', 'source': source}

        # Check neighbors
        neighbors = source.get('firstHopNeighbors', [])
        for neighbor in neighbors:
            neighbor_node = neighbor.get('primaryNode', {})
            neighbor_label = neighbor_node.get('nodeLabel', '')

            # Try ID-based matching
            if gold_id:
                neighbor_id = extract_node_id(neighbor_label)
                if neighbor_id and neighbor_id == gold_id:
                    return True, {'type': 'neighbor', 'source': source, 'neighbor': neighbor}

            # Try fuzzy name matching
            if gold_normalized and normalize_node_name(neighbor_label) == gold_normalized:
                return True, {'type': 'neighbor', 'source': source, 'neighbor': neighbor}

            # Check second-hop neighbors
            second_hop = neighbor.get('secondHopNeighbors', [])
            for sh in second_hop:
                sh_node = sh.get('relatedNode', {})
                sh_label = sh_node.get('nodeLabel', '')

                if gold_id:
                    sh_id = extract_node_id(sh_label)
                    if sh_id and sh_id == gold_id:
                        return True, {'type': 'second_hop', 'source': source, 'neighbor': neighbor, 'second_hop': sh}

                if gold_normalized and normalize_node_name(sh_label) == gold_normalized:
                    return True, {'type': 'second_hop', 'source': source, 'neighbor': neighbor, 'second_hop': sh}

    return False, None


def check_relationship_in_retrieved(gold_rel: str, retrieved_sources: List[Dict]) -> bool:
    """Check if a relationship type appears in retrieved sources"""
    if not gold_rel:
        return False

    gold_rel_normalized = gold_rel.upper().strip()

    for source in retrieved_sources:
        neighbors = source.get('firstHopNeighbors', [])
        for neighbor in neighbors:
            rel_type = neighbor.get('relationshipType', '').upper().strip()
            if rel_type == gold_rel_normalized:
                return True

            # Check second-hop relationships
            second_hop = neighbor.get('secondHopNeighbors', [])
            for sh in second_hop:
                sh_rel = sh.get('relationshipType', '').upper().strip()
                if sh_rel == gold_rel_normalized:
                    return True

    return False


def check_path_in_retrieved(first_node: str, relationship: str, second_node: str,
                            retrieved_sources: List[Dict]) -> bool:
    """
    Check if a complete path (first_node)-[relationship]->(second_node) exists
    """
    # Find source containing first_node
    first_found, first_match = match_node_in_retrieved(first_node, retrieved_sources)
    if not first_found or first_match['type'] != 'primary':
        return False

    # Check if second_node is a neighbor with the correct relationship
    source = first_match['source']
    neighbors = source.get('firstHopNeighbors', [])

    second_id = extract_node_id(second_node)
    second_normalized = normalize_node_name(second_node)
    rel_normalized = relationship.upper().strip() if relationship else None

    for neighbor in neighbors:
        # Check relationship
        if rel_normalized:
            neighbor_rel = neighbor.get('relationshipType', '').upper().strip()
            if neighbor_rel != rel_normalized:
                continue

        # Check if this neighbor is the second node
        neighbor_node = neighbor.get('primaryNode', {})
        neighbor_label = neighbor_node.get('nodeLabel', '')

        # Try ID matching
        if second_id:
            neighbor_id = extract_node_id(neighbor_label)
            if neighbor_id and neighbor_id == second_id:
                return True

        # Try name matching
        if second_normalized and normalize_node_name(neighbor_label) == second_normalized:
            return True

    return False


def parse_retrieved_context(context_str: str) -> List[Dict]:
    """
    Parse the formatted context string to extract retrieved nodes and relationships

    Context format:
    [1] PRIMARY NODE: Node Name
        Type: NodeType
        Content: ...
        Semantic Score: 0.XXX

        RELATIONSHIPS:
        ├── RELATIONSHIPTYPE → NeighborName
            Content: ...
    """
    sources = []

    # Split by PRIMARY NODE
    node_blocks = re.split(r'\[\d+\]\s+PRIMARY NODE:', context_str)[1:]  # Skip first empty

    for block in node_blocks:
        lines = block.strip().split('\n')
        if not lines:
            continue

        # Extract primary node info
        node_label = lines[0].strip()
        node_type = ""
        score = 0.0

        for line in lines[1:]:
            if line.strip().startswith('Type:'):
                node_type = line.split('Type:')[1].strip()
            elif 'Score:' in line:
                score_match = re.search(r'(\d+\.\d+)', line)
                if score_match:
                    score = float(score_match.group(1))
                break

        # Extract relationships
        neighbors = []
        relationship_section = False
        current_rel = None

        for line in lines:
            if 'RELATIONSHIPS:' in line:
                relationship_section = True
                continue

            if relationship_section:
                # Look for relationship pattern: ├── or └── RELATIONSHIPTYPE → TargetNode
                rel_match = re.search(r'[├└]──\s+(\w+)\s+→\s+(.+)', line)
                if rel_match:
                    rel_type = rel_match.group(1)
                    target_label = rel_match.group(2).strip()

                    neighbors.append({
                        'relationshipType': rel_type,
                        'primaryNode': {
                            'nodeLabel': target_label,
                            'nodeType': ''  # Not easily extractable from formatted text
                        }
                    })

        source = {
            'primarySource': {
                'nodeLabel': node_label,
                'nodeType': node_type,
                'score': score
            },
            'firstHopNeighbors': neighbors
        }
        sources.append(source)

    return sources


def evaluate_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a single sample

    Returns metrics for this sample
    """
    metadata = sample.get('metadata', {})
    node_info = metadata.get('node_info', {})
    question_type = node_info.get('type', '')

    # Extract gold standard
    first_node = node_info.get('first_node', '')
    second_node = node_info.get('second_node', '')
    third_node = node_info.get('third_node', '')
    relationship = node_info.get('relationship_1', '') or node_info.get('relationship', '')
    relationship_2 = node_info.get('relationship_2', '')

    # Parse context for missing info in wildcard questions
    context = sample.get('summary', '')
    parsed_info = parse_context_for_missing_info(context, question_type)

    # Fill in wildcards from context
    if not second_node and 'second_node' in parsed_info:
        second_node = parsed_info['second_node']
    if not relationship and 'relationship' in parsed_info:
        relationship = parsed_info['relationship']

    # Get retrieved sources - check if structured sources exist, otherwise parse context
    retrieved_sources = sample.get('sources', [])
    if not retrieved_sources:
        # Parse from formatted context string
        retrieved_context = sample.get('context', '')
        retrieved_sources = parse_retrieved_context(retrieved_context)

    # Initialize metrics
    metrics = {
        'question_type': question_type,
        'hop_count': metadata.get('hop_count', 0),
        'gold_nodes': [],
        'gold_relationships': [],
        'retrieved_nodes': 0,
        'nodes_found': [],
        'relationships_found': [],
        'node_recall': 0.0,
        'relationship_recall': 0.0,
        'path_found': False,
    }

    # Collect gold nodes
    gold_nodes = [n for n in [first_node, second_node, third_node] if n]
    gold_rels = [r for r in [relationship, relationship_2] if r]

    metrics['gold_nodes'] = gold_nodes
    metrics['gold_relationships'] = gold_rels

    # Count total retrieved nodes
    total_retrieved = len(retrieved_sources)
    for source in retrieved_sources:
        total_retrieved += len(source.get('firstHopNeighbors', []))
    metrics['retrieved_nodes'] = total_retrieved

    # Evaluate node coverage
    nodes_found = []
    for gold_node in gold_nodes:
        found, match = match_node_in_retrieved(gold_node, retrieved_sources)
        if found:
            nodes_found.append(gold_node)

    metrics['nodes_found'] = nodes_found
    metrics['node_recall'] = len(nodes_found) / len(gold_nodes) if gold_nodes else 0.0

    # Evaluate relationship coverage
    relationships_found = []
    for gold_rel in gold_rels:
        if check_relationship_in_retrieved(gold_rel, retrieved_sources):
            relationships_found.append(gold_rel)

    metrics['relationships_found'] = relationships_found
    metrics['relationship_recall'] = len(relationships_found) / len(gold_rels) if gold_rels else 0.0

    # Evaluate path coverage (for 1-hop and 2-hop)
    if len(gold_nodes) >= 2 and relationship:
        # Check if complete path exists
        metrics['path_found'] = check_path_in_retrieved(
            first_node, relationship, second_node, retrieved_sources
        )

    return metrics


def evaluate_dataset(dataset_path: str) -> Dict[str, Any]:
    """
    Evaluate entire dataset

    Returns aggregate metrics
    """
    with open(dataset_path, 'r') as f:
        data = json.load(f)

    samples = data.get('samples', [])

    print(f"Evaluating {len(samples)} samples...")
    print("="*80)

    # Aggregate metrics by hop count
    metrics_by_hop = defaultdict(lambda: {
        'total': 0,
        'node_recalls': [],
        'relationship_recalls': [],
        'paths_found': 0,
    })

    # Aggregate by question type
    metrics_by_type = defaultdict(lambda: {
        'total': 0,
        'node_recalls': [],
        'relationship_recalls': [],
        'paths_found': 0,
    })

    all_metrics = []

    for i, sample in enumerate(samples, 1):
        print(f"[{i}/{len(samples)}] Evaluating sample {sample.get('id', i)}...", end='\r')

        metrics = evaluate_sample(sample)
        all_metrics.append(metrics)

        hop_count = metrics['hop_count']
        question_type = metrics['question_type']

        # Update aggregates
        metrics_by_hop[hop_count]['total'] += 1
        metrics_by_type[question_type]['total'] += 1

        if metrics['node_recall'] > 0:
            metrics_by_hop[hop_count]['node_recalls'].append(metrics['node_recall'])
            metrics_by_type[question_type]['node_recalls'].append(metrics['node_recall'])

        if metrics['relationship_recall'] > 0:
            metrics_by_hop[hop_count]['relationship_recalls'].append(metrics['relationship_recall'])
            metrics_by_type[question_type]['relationship_recalls'].append(metrics['relationship_recall'])

        if metrics['path_found']:
            metrics_by_hop[hop_count]['paths_found'] += 1
            metrics_by_type[question_type]['paths_found'] += 1

    print()  # New line after progress

    # Calculate aggregate statistics
    results = {
        'total_samples': len(samples),
        'by_hop_count': {},
        'by_question_type': {},
        'overall': {
            'avg_node_recall': 0.0,
            'avg_relationship_recall': 0.0,
            'path_coverage': 0.0,
        }
    }

    # Aggregate by hop count
    for hop, stats in metrics_by_hop.items():
        hop_label = {0: '0-hop', 1: '1-hop', 2: '2-hop'}.get(hop, f'{hop}-hop')
        results['by_hop_count'][hop_label] = {
            'total_questions': stats['total'],
            'avg_node_recall': sum(stats['node_recalls']) / len(stats['node_recalls']) if stats['node_recalls'] else 0.0,
            'avg_relationship_recall': sum(stats['relationship_recalls']) / len(stats['relationship_recalls']) if stats['relationship_recalls'] else 0.0,
            'path_coverage': stats['paths_found'] / stats['total'] if stats['total'] > 0 else 0.0,
        }

    # Aggregate by question type
    for qtype, stats in metrics_by_type.items():
        results['by_question_type'][qtype] = {
            'total_questions': stats['total'],
            'avg_node_recall': sum(stats['node_recalls']) / len(stats['node_recalls']) if stats['node_recalls'] else 0.0,
            'avg_relationship_recall': sum(stats['relationship_recalls']) / len(stats['relationship_recalls']) if stats['relationship_recalls'] else 0.0,
            'path_coverage': stats['paths_found'] / stats['total'] if stats['total'] > 0 else 0.0,
        }

    return results


def main():
    dataset_path = 'dataset/evaluation_dataset.json'

    print("="*80)
    print("GraphRAG Sub-graph Coverage Evaluation")
    print("="*80)
    print()

    results = evaluate_dataset(dataset_path)

    print()
    print("="*80)
    print("EVALUATION RESULTS")
    print("="*80)
    print()

    print(f"Total Samples: {results['total_samples']}")
    print()

    print("Results by Hop Count:")
    print("-" * 80)
    for hop, metrics in sorted(results['by_hop_count'].items()):
        print(f"\n{hop}:")
        print(f"  Questions: {metrics['total_questions']}")
        print(f"  Avg Node Recall: {metrics['avg_node_recall']:.2%}")
        print(f"  Avg Relationship Recall: {metrics['avg_relationship_recall']:.2%}")
        print(f"  Path Coverage: {metrics['path_coverage']:.2%}")

    print()
    print("Results by Question Type:")
    print("-" * 80)
    for qtype, metrics in sorted(results['by_question_type'].items()):
        print(f"\n{qtype}:")
        print(f"  Questions: {metrics['total_questions']}")
        print(f"  Avg Node Recall: {metrics['avg_node_recall']:.2%}")
        print(f"  Avg Relationship Recall: {metrics['avg_relationship_recall']:.2%}")
        print(f"  Path Coverage: {metrics['path_coverage']:.2%}")

    print()
    print("="*80)


if __name__ == "__main__":
    main()
