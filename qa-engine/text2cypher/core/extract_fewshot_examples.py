"""
Extract Few-Shot Examples from Dataset

Selects 5 high-quality candidate examples from each category in the dataset
for use in dynamic few-shot selection.
"""

import pandas as pd
import json
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass, asdict


@dataclass
class FewShotCandidate:
    """Few-shot example candidate"""
    category: str
    nl: str
    cypher: str
    hops: int
    expected_labels: List[str]
    expected_relationships: List[str]
    expected_properties: List[str]


def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load the technical dataset"""
    return pd.read_csv(csv_path)


def select_diverse_examples(df: pd.DataFrame, category: str, n: int = 5) -> List[FewShotCandidate]:
    """
    Select diverse, high-quality examples from a category
    
    Selection criteria:
    1. Variety of hop counts (0, 1, 2+)
    2. Different query patterns (MATCH, WHERE, RETURN variations)
    3. Coverage of different node labels and relationships
    4. Reasonable query length (not too simple, not too complex)
    """
    category_df = df[df['Category'] == category].copy()
    
    if len(category_df) == 0:
        return []
    
    # Parse JSON columns
    for col in ['ExpectedNodeLabels', 'ExpectedRelationshipTypes', 'ExpectedProperties']:
        category_df[col] = category_df[col].apply(lambda x: json.loads(x) if pd.notna(x) else [])
    
    # Add query length as a metric
    category_df['query_length'] = category_df['CypherQuery'].str.len()
    
    # Strategy: Select diverse examples
    selected = []
    
    # 1. Try to get examples with different hop counts
    hop_counts = sorted(category_df['Hops'].unique())
    
    for hop in hop_counts:
        if len(selected) >= n:
            break
        
        hop_df = category_df[category_df['Hops'] == hop]
        
        # Sort by query length (prefer medium complexity)
        hop_df = hop_df.sort_values('query_length')
        
        # Pick from middle of the range (not too simple, not too complex)
        if len(hop_df) > 0:
            mid_idx = len(hop_df) // 2
            row = hop_df.iloc[mid_idx]
            
            selected.append(FewShotCandidate(
                category=category,
                nl=row['NaturalLanguageQuestion'],
                cypher=row['CypherQuery'],
                hops=int(row['Hops']),
                expected_labels=row['ExpectedNodeLabels'],
                expected_relationships=row['ExpectedRelationshipTypes'],
                expected_properties=row['ExpectedProperties']
            ))
    
    # 2. Fill remaining slots with diverse examples
    remaining = n - len(selected)
    if remaining > 0:
        # Get examples not yet selected
        selected_indices = [ex.nl for ex in selected]
        remaining_df = category_df[~category_df['NaturalLanguageQuestion'].isin(selected_indices)]
        
        # Sample diverse examples based on different criteria
        if len(remaining_df) > 0:
            # Sort by number of unique labels (prefer examples with variety)
            remaining_df['label_count'] = remaining_df['ExpectedNodeLabels'].apply(len)
            remaining_df = remaining_df.sort_values('label_count', ascending=False)
            
            for _, row in remaining_df.head(remaining).iterrows():
                selected.append(FewShotCandidate(
                    category=category,
                    nl=row['NaturalLanguageQuestion'],
                    cypher=row['CypherQuery'],
                    hops=int(row['Hops']),
                    expected_labels=row['ExpectedNodeLabels'],
                    expected_relationships=row['ExpectedRelationshipTypes'],
                    expected_properties=row['ExpectedProperties']
                ))
    
    return selected[:n]


def extract_all_categories(csv_path: str, output_path: str = None):
    """
    Extract 5 examples from each category
    
    Args:
        csv_path: Path to the dataset CSV
        output_path: Path to save the output JSON (optional)
    """
    df = load_dataset(csv_path)
    
    # Get all unique categories
    categories = df['Category'].unique()
    
    print(f"Found {len(categories)} categories:")
    for cat in categories:
        count = len(df[df['Category'] == cat])
        print(f"  - {cat}: {count} queries")
    
    print("\n" + "="*80)
    print("Extracting 5 examples from each category...")
    print("="*80 + "\n")
    
    # Extract examples for each category
    all_examples = {}
    
    for category in categories:
        examples = select_diverse_examples(df, category, n=5)
        all_examples[category] = examples
        
        print(f"\n{category} ({len(examples)} examples):")
        print("-" * 80)
        
        for i, ex in enumerate(examples, 1):
            print(f"\n{i}. NL: {ex.nl[:80]}...")
            print(f"   Cypher: {ex.cypher[:80]}...")
            print(f"   Hops: {ex.hops}, Labels: {len(ex.expected_labels)}, Rels: {len(ex.expected_relationships)}")
    
    # Save to JSON if output path provided
    if output_path:
        # Convert to serializable format
        output_data = {}
        for category, examples in all_examples.items():
            output_data[category] = [asdict(ex) for ex in examples]
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n\n{'='*80}")
        print(f"✅ Saved {sum(len(exs) for exs in all_examples.values())} examples to: {output_path}")
        print("="*80)
    
    return all_examples


def format_for_prompt(examples: List[FewShotCandidate]) -> str:
    """
    Format examples for use in prompts
    
    Args:
        examples: List of few-shot examples
        
    Returns:
        Formatted string for prompt
    """
    formatted = []
    for ex in examples:
        formatted.append(f"EXAMPLE NL: {ex.nl}\nEXAMPLE CYPHER: {ex.cypher}")
    
    return "\n\n".join(formatted)


if __name__ == "__main__":
    # Paths
    dataset_path = Path(__file__).parent.parent / "dataset" / "technical_dataset_Second_COMPLETION.csv"
    output_path = Path(__file__).parent.parent / "configt2c" / "fewshot_candidates.json"
    
    print("="*80)
    print("Few-Shot Example Extraction")
    print("="*80)
    print(f"\nDataset: {dataset_path}")
    print(f"Output: {output_path}\n")
    
    # Extract examples
    examples = extract_all_categories(str(dataset_path), str(output_path))
    
    # Show example usage
    print("\n\n" + "="*80)
    print("EXAMPLE USAGE IN PROMPT")
    print("="*80)
    
    # Get examples from one category
    category = "Node Lookup Queries"
    if category in examples:
        sample_examples = examples[category][:2]  # Take first 2
        formatted = format_for_prompt(sample_examples)
        print(f"\nFormatted examples for '{category}':\n")
        print(formatted)

