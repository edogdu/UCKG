"""
Dynamic Rule Selection for T2CSS

Simple deterministic rule selection based on intent classification:
- Same intent classification used for scaffold selection
- Global rules (always active)
- Intent-specific rules (based on classified intent)
- Micro-rules (feature-based activation)
"""

import re
from typing import List, Tuple
from dataclasses import dataclass


# --- Global Rules (Always Active) ---

GLOBAL_RULES = [
    "Copy labels/relationship types/property names verbatim from the provided schema slice and Allowed lists.",
    "Use labeled nodes and typed relationships (e.g., (cv:UcoCVE)-[:UCOEXHASCPE]->(p:UcoexCPE)).",
    "Structure queries as MATCH → (optional WHERE) → RETURN; never omit RETURN.",
    "Quote strings; use = for exact matches; use CONTAINS for substrings.",
    "Use DISTINCT when returning identifiers that may repeat.",
    "For numeric comparisons on string fields, cast with toFloat().",
    "Prefer the shortest valid chain of relationships that answers the question.",
    "Add LIMIT for potentially large result sets."
]


# --- Intent-Specific Rules ---

INTENT_RULES = {
    "Aggregation and Counting": [
        "Use RETURN count(*) or count(alias) with an alias.",
        "For averages/sums/min/max, project aggregates with aliases.",
        "Add WHERE filters before aggregation.",
        "If ranking/count-by-group: WITH key AS k, count(*) AS c RETURN k, c ORDER BY c DESC LIMIT K."
    ],
    
    "Comparative and Ranking": [
        "Use WHERE with > < >= <= on numeric fields; cast with toFloat() if needed.",
        "Use ORDER BY <metric> (DESC/ASC) and LIMIT K.",
        "For 'top by count': group with WITH, then order and limit."
    ],
    
    "Path Queries (Variable-length)": [
        "Use MATCH p = shortestPath((a)-[:REL*..N]-(b)) (bound N if needed).",
        "Label both endpoints and project p.",
        "Do not mix aggregates with a single path result."
    ],
    
    "Multi-hop Queries": [
        "Chain multiple MATCH clauses following the shown relations.",
        "Prefer a minimal chain; avoid redundant hops.",
        "Use RETURN DISTINCT <target> to deduplicate results."
    ],
    
    "Graph Pattern Matching": [
        "Use multiple MATCHes that must all hold for the same anchor node.",
        "If multiple patterns share an alias, keep the alias consistent.",
        "RETURN DISTINCT the anchor or requested projection."
    ],
    
    "Existence and Set Operations Queries": [
        "Use EXISTS{ ... } or OPTIONAL MATCH + WHERE alias IS NULL for 'without'.",
        "Use WHERE id(a) IN [...] / NOT IN for set inclusion/exclusion.",
        "Keep projections minimal; no unnecessary properties."
    ],
    
    "Conditional and Boolean Queries": [
        "Combine filters with AND/OR/NOT; parenthesize to enforce precedence.",
        "Mix exact and substring matches deliberately (= vs CONTAINS).",
        "Project only requested fields."
    ],
    
    "Relationship Traversal Queries": [
        "Use a single typed relationship (a)-[:REL]->(b) or its reverse as needed.",
        "Return b (or a property of b) or use DISTINCT b if plural.",
        "Add WHERE on either node if the question constrains attributes."
    ],
    
    "Node Lookup Queries": [
        "Match on the canonical identifier (e.g., cv.label = 'CVE-YYYY-NNNNN', t.ucoexNAME = 'T1059').",
        "Return a small set of fields; add LIMIT.",
        "Avoid relation traversal unless asked."
    ]
}


# --- Micro-Rules (Feature-Based) ---

MICRO_RULES = {
    "has_year": "Use date(field).year = YYYY for year constraints.",
    "has_date_range": "Constrain with two date(field) comparisons for date ranges.",
    "has_topk": "Add ORDER BY <metric> DESC LIMIT K for top-K queries.",
    "plural_targets": "Add DISTINCT to projection when returning multiple items.",
    "mentions_substring": "Use CONTAINS on the named property for substring matching.",
    "mentions_exact": "Use strict = for exact ID/name matching.",
    "mentions_numeric": "Use toFloat(prop) before numeric comparison.",
    "asks_path_bound": "Use [:REL*..N] in shortestPath for bounded path queries."
}


# --- Feature Detection ---

@dataclass
class QueryFeatures:
    """Detected features from the question"""
    has_year: bool = False
    has_date_range: bool = False
    has_topk: bool = False
    plural_targets: bool = False
    mentions_substring: bool = False
    mentions_exact: bool = False
    mentions_numeric: bool = False
    asks_path_bound: bool = False
    
    def to_dict(self):
        return {
            "has_year": self.has_year,
            "has_date_range": self.has_date_range,
            "has_topk": self.has_topk,
            "plural_targets": self.plural_targets,
            "mentions_substring": self.mentions_substring,
            "mentions_exact": self.mentions_exact,
            "mentions_numeric": self.mentions_numeric,
            "asks_path_bound": self.asks_path_bound
        }
    
    def active_features(self):
        """Return list of active feature names"""
        return [k for k, v in self.to_dict().items() if v]


def detect_features(question: str) -> QueryFeatures:
    """
    Detect features from the question
    
    Args:
        question: Natural language question
        
    Returns:
        QueryFeatures object with detected boolean flags
    """
    q_lower = question.lower()
    features = QueryFeatures()
    
    # Detect year mentions
    features.has_year = bool(re.search(r'\b(19|20)\d{2}\b', question))
    
    # Detect date ranges
    features.has_date_range = bool(re.search(r'\bbetween\b.*\b(19|20)\d{2}\b.*\b(and|to)\b.*\b(19|20)\d{2}\b', q_lower))
    
    # Detect top-K queries
    features.has_topk = bool(re.search(r'\btop\s*\d+|\bhighest|\blowest|\bmost|\bleast|\bfirst\s*\d+', q_lower))
    
    # Detect plural targets
    features.plural_targets = bool(re.search(r'\b(which|what|list|show|find|all)\s+(cves|campaigns|groups|techniques|weaknesses|vulnerabilities)', q_lower))
    
    # Detect substring mentions
    features.mentions_substring = bool(re.search(r'\bcontains?|\bincludes?|\bhas\s+\w+\s+in|\bmatching\b', q_lower))
    
    # Detect exact matching
    features.mentions_exact = bool(re.search(r'\bexact|\b(cve|capec|cwe|t)-\d+', q_lower, re.I))
    
    # Detect numeric comparisons
    features.mentions_numeric = bool(re.search(r'\b(greater|less|higher|lower|above|below|more|score|severity|impact|exploitability)\b.*\b(than|\d+)', q_lower))
    
    # Detect path bounds
    features.asks_path_bound = bool(re.search(r'\bup to\s+\d+\s+(hop|step|level)|\bwithin\s+\d+\s+(hop|step)', q_lower))
    
    return features


# --- Dynamic Rule Selection ---

def select_rules_for_intent(intent: str, question: str) -> Tuple[List[str], QueryFeatures]:
    """
    Select rules based on intent and detected features
    
    Simple deterministic selection:
    - Global rules (always)
    - Intent-specific rules (based on classified intent)
    - Micro-rules (based on detected features)
    
    Args:
        intent: Classified intent (same as used for scaffold)
        question: Natural language question
        
    Returns:
        (selected_rules, features)
    """
    # Step 1: Detect features
    features = detect_features(question)
    
    # Step 2: Build rule set
    rules = []
    
    # Always include global rules
    rules.extend(GLOBAL_RULES)
    
    # Add intent-specific rules
    if intent in INTENT_RULES:
        rules.extend(INTENT_RULES[intent])
    
    # Add micro-rules based on active features
    for feature_name in features.active_features():
        if feature_name in MICRO_RULES:
            rules.append(MICRO_RULES[feature_name])
    
    return rules, features


# --- Example Usage ---

if __name__ == "__main__":
    # Test with different intents
    test_cases = [
        ("Aggregation and Counting", "How many campaigns are attributed to APT28?"),
        ("Comparative and Ranking", "Find the top 5 CVEs with highest severity published in 2021"),
        ("Path Queries (Variable-length)", "What is the shortest path between Cobalt Strike and APT29?"),
        ("Node Lookup Queries", "Show me CVEs that affect Windows"),
        ("Multi-hop Queries", "List all techniques used by FIN7 via their toolset")
    ]
    
    print("="*80)
    print("DYNAMIC RULE SELECTION TEST (Deterministic)")
    print("="*80)
    
    for i, (intent, question) in enumerate(test_cases, 1):
        print(f"\n{i}. Intent: {intent}")
        print(f"   Question: {question}")
        print("-"*80)
        
        rules, features = select_rules_for_intent(intent, question)
        
        active = features.active_features()
        print(f"   Features: {active if active else 'None'}")
        print(f"   Rules: {len(rules)} total ({len(GLOBAL_RULES)} global + {len(rules) - len(GLOBAL_RULES)} intent/micro)")
        
        # Show non-global rules
        if len(rules) > len(GLOBAL_RULES):
            print(f"\n   Intent/Micro Rules:")
            for j, rule in enumerate(rules[len(GLOBAL_RULES):], 1):
                print(f"     {j}. {rule}")

