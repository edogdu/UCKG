"""
Enhanced T2CSS Pipeline with Ollama Integration

Combines the best features from t2css_new.py with Ollama Nomic embeddings:
- Semantic schema JSON-based approach
- Intent classification (9 categories)
- Bilingual rendering (semantic → physical)
- Weighted retrieval with keyword/type bonuses
- Dynamic few-shot selection
- Local Llama3 LLM and Nomic embeddings
"""

import re
import json
import numpy as np
import os
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

# Import unified embeddings
from embeddings import OllamaEmbeddings, batch_cosine_similarity

# Import dynamic rule selection
from dynamic_rules import select_rules_for_intent, GLOBAL_RULES


# --- Data Classes ---

@dataclass
class FewShotExample:
    """Few-shot example with natural language and Cypher"""
    nl: str
    cypher: str


# --- Load Semantic Schema ---

def load_semantic_schema(path: str = None) -> Dict:
    """Load semantic schema JSON configuration"""
    if path is None:
        path = Path(__file__).parent.parent / 'configt2c' / 'semantic_schema_uckg.json'
    
    with open(path, "r") as f:
        return json.load(f)


# --- Build Mappings ---

def build_maps(semantic_schema: Dict) -> Tuple[Dict, Dict]:
    """
    Build semantic→physical mappings
    
    Returns:
        (label_map, relationship_map)
    """
    label_map = {
        c["semantic"]: c["physical_labels"] 
        for c in semantic_schema["classes"]
    }
    
    rel_map = {
        p["semantic"]: p["physical_rel"] 
        for p in semantic_schema["object_properties"]
    }
    
    return label_map, rel_map


# --- Intent Classification ---

INTENT_ORDER = [
    "Aggregation and Counting",
    "Comparative and Ranking",
    "Path Queries (Variable-length)",
    "Multi-hop Queries",
    "Graph Pattern Matching",
    "Existence and Set Operations Queries",
    "Conditional and Boolean Queries",
    "Relationship Traversal Queries",
    "Node Lookup Queries"
]

INTENT_PATTERNS = {
    "Aggregation and Counting": [
        r"\bcount|how many|number of|sum|average|avg|min|max|top\s*\d+|top\b|rank|most|least"
    ],
    "Comparative and Ranking": [
        r">\s*|<\s*|>=|<=|higher than|greater than|less than|at least|more than|"
        r"largest|smallest|highest|lowest|order by|sort|top\b"
    ],
    "Path Queries (Variable-length)": [
        r"\bshortest path|path between|connected to|via any path|degrees? of separation|hops?\b"
    ],
    "Multi-hop Queries": [
        r"\bvia\b|\bthrough\b|\bchain\b|\blinked through\b"
    ],
    "Graph Pattern Matching": [
        r"\b(use|uses|mitigates|targets)\b.*\b(and|also)\b.*\b(use|uses|mitigates|targets)\b"
    ],
    "Existence and Set Operations Queries": [
        r"\bexists|is there|any\b|\bwithout\b|\bonly those\b|\bnot in\b|\bexcept\b|"
        r"\boverlap\b|\bintersection\b"
    ],
    "Conditional and Boolean Queries": [
        r"\b(and|or|not)\b"
    ],
    "Relationship Traversal Queries": [
        r"\blinked to|associated with|uses|targets|mitigates|maps to|related to"
    ],
    "Node Lookup Queries": [
        r".*"  # Default catch-all
    ]
}


def classify_intent(question: str) -> str:
    """
    Classify query intent into one of 9 categories
    
    Args:
        question: Natural language question
        
    Returns:
        Intent category name
    """
    for category in INTENT_ORDER:
        patterns = INTENT_PATTERNS[category]
        if any(re.search(p, question, re.I) for p in patterns):
            return category
    
    return "Node Lookup Queries"


# --- ID Normalization ---

def normalize_ids(question: str) -> str:
    """
    Normalize CVE/CAPEC/Technique IDs to standard format
    
    Args:
        question: Input question
        
    Returns:
        Question with normalized IDs
    """
    # CVE-YYYY-NNNNN
    question = re.sub(
        r'\bcve-(\d{4})-(\d{4,7})\b', 
        r'CVE-\1-\2', 
        question, 
        flags=re.I
    )
    
    # TXXXX or TXXXX.XXX (MITRE techniques)
    question = re.sub(
        r'\b(t\d{4}(?:\.\d{3})?)\b', 
        lambda m: m.group(1).upper(), 
        question, 
        flags=re.I
    )
    
    # CAPEC-NNN
    question = re.sub(
        r'\bcapec-(\d+)\b', 
        lambda m: f'CAPEC-{m.group(1)}'.upper(), 
        question, 
        flags=re.I
    )
    
    return question


# --- Weighted Retrieval ---

def retrieve_semantic_slice(
    embedder: OllamaEmbeddings,
    question: str,
    sem_lines: List[str],
    sem_embeddings: np.ndarray,
    intent: str,
    k: int = 10
) -> List[str]:
    """
    Retrieve top-k relevant semantic schema lines using weighted similarity
    
    Args:
        embedder: Ollama embeddings instance
        question: User question
        sem_lines: Semantic schema lines (corpus)
        sem_embeddings: Pre-computed embeddings for corpus
        intent: Classified intent category
        k: Number of results to return
        
    Returns:
        List of top-k relevant schema lines
    """
    # Get query embedding
    query_emb = embedder.encode(question, normalize_embeddings=True)
    
    # Calculate base cosine similarities
    sims = batch_cosine_similarity(query_emb, sem_embeddings)
    
    # Define bonus functions
    def keyword_bonus(line: str) -> float:
        """Boost lines containing key cybersecurity terms"""
        keywords = [
            "cve", "capec", "cwe", "technique", "campaign", "group",
            "cpe", "mitigation", "d3fend", "severity", "score",
            "date", "id", "name"
        ]
        line_lower = line.lower()
        return 0.06 if any(kw in line_lower for kw in keywords) else 0.0
    
    def type_bonus(line: str) -> float:
        """Boost lines matching query intent type"""
        # Check if line is a relationship (vs property/prototype)
        is_relationship = (" has " not in line) and \
                         ("Prototype" not in line) and \
                         ("Bridge" not in line)
        
        # Boost relationships for path/traversal queries
        if any(x in intent for x in ["Path", "Multi-hop", "Relationship", "Pattern"]):
            return 0.07 if is_relationship else 0.0
        
        # Boost properties for aggregation/filtering queries
        if any(x in intent for x in ["Comparative", "Aggregation", "Conditional"]):
            return 0.07 if (" has " in line or "Prototype" in line) else 0.0
        
        return 0.0
    
    # Calculate weighted scores
    weights = np.array([
        sims[i] + keyword_bonus(sem_lines[i]) + type_bonus(sem_lines[i])
        for i in range(len(sem_lines))
    ])
    
    # Get top-k indices
    top_k_indices = np.argsort(weights)[::-1][:k]
    
    return [sem_lines[i] for i in top_k_indices]


# --- Bilingual Rendering ---

# Property mapping (semantic → physical)
PROP_MAP = {
    "Vulnerability": {
        "cveId": ["label", "cveId"],
        "baseSeverity": ["ucobaseSeverity"],
        "exploitabilityScore": ["ucoexploitabilityScore"],
        "impactScore": ["ucoimpactScore"],
        "publishedDate": ["ucopublishedDateTime"],
        "lastModifiedDate": ["ucolastModifiedDateTime"],
        "vulnStatus": ["ucovulnStatus"]
    },
    "Weakness": {
        "cweId": ["ucocweID"],
        "cweName": ["ucocweName"]
    },
    "AttackPattern": {
        "capecId": ["ucoexCAPEC_id"],
        "capecName": ["ucoexCAPEC_name"]
    },
    "Technique": {
        "techniqueId": ["ucoexNAME"],
        "techniqueName": ["ucoexNAME"]
    },
    "Campaign": {"name": ["ucoexNAME"]},
    "Group": {"name": ["ucoexNAME"]},
    "Software": {"name": ["ucoexNAME"]},
    "CPE": {"cpeName": ["cpeName"]}
}


def format_labels(semantic_class: str, label_map: Dict[str, List[str]]) -> str:
    """Format semantic class with physical labels"""
    physical_labels = label_map.get(semantic_class, [])
    if physical_labels:
        return f"{semantic_class} ({'|'.join(physical_labels)})"
    return semantic_class


def bilingualize_line(line: str, label_map: Dict, rel_map: Dict) -> str:
    """
    Convert semantic schema line to bilingual format (semantic + physical)
    
    Args:
        line: Semantic schema line
        label_map: Semantic→physical label mapping
        rel_map: Semantic→physical relationship mapping
        
    Returns:
        Bilingual formatted line
    """
    # Pattern 1: "Subject Relationship Object" (e.g., "Campaign uses Technique")
    m = re.match(r"^([A-Za-z]+)\s+([A-Za-z]+)\s+([A-Za-z]+)$", line.strip())
    if m:
        subject, rel, obj = m.groups()
        subject_fmt = format_labels(subject, label_map)
        obj_fmt = format_labels(obj, label_map)
        rel_physical = rel_map.get(rel, rel)
        return f"{subject_fmt} -[:{rel_physical}]-> {obj_fmt}"
    
    # Pattern 2: "Subject has property" (e.g., "Vulnerability has cveId")
    m = re.match(r"^([A-Za-z]+)\s+has\s+([A-Za-z][A-Za-z0-9_]*)$", line.strip())
    if m:
        subject, prop = m.groups()
        subject_fmt = format_labels(subject, label_map)
        physical_props = PROP_MAP.get(subject, {}).get(prop, [])
        prop_str = f" [{', '.join(physical_props)}]" if physical_props else ""
        return f"{subject_fmt} has property {prop}{prop_str}"
    
    # Pattern 3: Prototypes/Bridges - annotate classes inline
    result = line
    for semantic_class in label_map.keys():
        result = re.sub(
            rf"\b{semantic_class}\b",
            format_labels(semantic_class, label_map),
            result
        )
    return result


def bilingualize_slice(
    sem_slice: List[str],
    label_map: Dict,
    rel_map: Dict
) -> List[str]:
    """Convert list of semantic lines to bilingual format"""
    return [bilingualize_line(line, label_map, rel_map) for line in sem_slice]


def allowed_lists_block(label_map: Dict, rel_map: Dict) -> str:
    """Generate allowed labels and relationships block for prompt"""
    labels = sorted({p for lst in label_map.values() for p in lst})
    rels = sorted(rel_map.values())
    
    return (
        "Allowed Labels: " + ", ".join(labels) + "\n" +
        "Allowed Relationships: " + ", ".join(rels)
    )


# --- Clause Scaffolding ---

def clause_scaffold(intent: str) -> str:
    """
    Get Cypher clause scaffold based on query intent
    
    Args:
        intent: Classified intent category
        
    Returns:
        Clause structure guidance
    """
    scaffolds = {
        "Aggregation and Counting": 
            "Use MATCH + optional WHERE, then RETURN count()/aggregates with an alias.",
        
        "Comparative and Ranking":
            "Use MATCH + WHERE with toFloat() for numeric compares, ORDER BY, LIMIT.",
        
        "Path Queries (Variable-length)":
            "Use shortestPath((a)-[:REL*..]-(b)) and RETURN p.",
        
        "Multi-hop Queries":
            "Chain the shown relations with multiple MATCH clauses, then RETURN DISTINCT the target.",
        
        "Relationship Traversal Queries":
            "Use one MATCH (a)-[:REL]->(b) and RETURN b.",
        
        "Graph Pattern Matching":
            "Use multiple MATCH patterns that must co-hold, then RETURN DISTINCT the anchor node.",
        
        "Existence and Set Operations Queries":
            "Use EXISTS(), OPTIONAL MATCH with NULL checks; then RETURN set.",
        
        "Conditional and Boolean Queries":
            "Use MATCH + WHERE with AND/OR/NOT, then RETURN projection."
    }
    
    return scaffolds.get(
        intent,
        "Use MATCH/WHERE/RETURN with labeled nodes and typed relationships."
    )


# --- Rules ---

BASE_RULES = [
    "Use only labels/relationships/properties shown in the schema context and Allowed lists; copy them verbatim.",
    "Compose the shortest valid MATCH chain that answers the question.",
    "Include MATCH (and optional WHERE) and a final RETURN clause.",
    "Use lowercase aliases; quote string literals; cast numeric strings with toFloat().",
    "Use DISTINCT when listing identifiers; use ORDER BY/LIMIT when ranking.",
    "The query must be executable with valid labels, relationships, and properties."
]


# --- Prompt Assembly ---

def assemble_prompt(
    question: str,
    sem_bilingual: List[str],
    rules: List[str],
    scaffold: str,
    fewshot_text: str
) -> str:
    """
    Assemble complete prompt for LLM
    
    Args:
        question: User's natural language question
        sem_bilingual: Bilingual semantic schema lines
        rules: List of rules
        scaffold: Clause scaffold for this query type
        fewshot_text: Few-shot examples text (can be empty)
        
    Returns:
        Complete prompt string
    """
    header = (
        "You are a Neo4j Cypher expert for the Unified Cybersecurity Knowledge Graph (UCKG). "
        "Translate the question into a valid, executable Cypher query using only the provided schema context."
    )
    
    schema = "Semantic Schema (relevant concepts & relations):\n- " + "\n- ".join(sem_bilingual)
    rules_txt = "Rules:\n- " + "\n- ".join(rules)
    
    # Only include few-shot section if examples are provided
    fewshot_section = ""
    if fewshot_text and fewshot_text.strip():
        fewshot_section = f"\nFew-shot Examples:\n{fewshot_text}\n"
    
    return f"""{header}

Clause Scaffold:
{scaffold}

{schema}

{rules_txt}{fewshot_section}
Question:
{question}

Return only the Cypher query."""


# --- Dynamic Few-Shot Selection ---

class FewShotStore:
    """Store and retrieve few-shot examples by similarity"""
    
    def __init__(self, examples: List[FewShotExample], embedder: OllamaEmbeddings):
        """
        Initialize few-shot store
        
        Args:
            examples: List of few-shot examples
            embedder: Ollama embeddings instance
        """
        self.examples = examples
        self.embedder = embedder
        
        # Pre-compute embeddings
        nl_texts = [ex.nl for ex in examples]
        self.embeddings = embedder.encode(nl_texts, normalize_embeddings=True)
    
    def get_top_k(self, question: str, k: int = 2) -> List[FewShotExample]:
        """
        Retrieve top-k most similar examples
        
        Args:
            question: User question
            k: Number of examples to return
            
        Returns:
            List of top-k similar examples
        """
        # Get question embedding
        question_emb = self.embedder.encode(question, normalize_embeddings=True)
        
        # Calculate similarities
        sims = batch_cosine_similarity(question_emb, self.embeddings)
        
        # Get top-k indices
        top_k_indices = np.argsort(sims)[::-1][:k]
        
        return [self.examples[i] for i in top_k_indices]
    
    def format_examples(self, examples: List[FewShotExample]) -> str:
        """Format examples as text for prompt"""
        return "\n\n".join([
            f"EXAMPLE NL: {ex.nl}\nEXAMPLE CYPHER: {ex.cypher}"
            for ex in examples
        ])


# --- Main Pipeline Class ---

class EnhancedT2CSSPipeline:
    """
    Enhanced T2CSS Pipeline with Ollama Integration
    
    Combines semantic schema approach with local Llama3/Nomic embeddings
    and dynamic few-shot selection
    """
    
    def __init__(
        self,
        semantic_schema_path: str = None,
        embedding_model: str = "nomic-embed-text",
        top_k: int = 10,
        fewshot_k: int = 2,
        fewshot_candidates_path: str = None,
        auto_load_fewshot: bool = True
    ):
        """
        Initialize enhanced T2CSS pipeline
        
        Args:
            semantic_schema_path: Path to semantic schema JSON
            embedding_model: Ollama embedding model name
            top_k: Number of schema elements to retrieve
            fewshot_k: Number of few-shot examples to select
            fewshot_candidates_path: Path to few-shot candidates JSON
            auto_load_fewshot: Automatically load few-shot candidates
        """
        # Load semantic schema
        self.semantic_schema = load_semantic_schema(semantic_schema_path)
        self.label_map, self.rel_map = build_maps(self.semantic_schema)
        
        # Initialize embedder
        self.embedder = OllamaEmbeddings(model=embedding_model)
        self.top_k = top_k
        self.fewshot_k = fewshot_k
        
        # Pre-compute schema embeddings
        self.corpus_lines = self.semantic_schema["embedding_corpus"]
        self.corpus_embeddings = self.embedder.encode(
            self.corpus_lines,
            normalize_embeddings=True
        )
        
        print(f"[Enhanced T2CSS] Initialized with {len(self.corpus_lines)} schema elements")
        
        # Initialize few-shot store
        self.fewshot_store = None
        if auto_load_fewshot:
            self._load_fewshot_candidates(fewshot_candidates_path)
    
    def _load_fewshot_candidates(self, fewshot_path: str = None):
        """
        Load few-shot candidates from JSON file
        
        Args:
            fewshot_path: Path to fewshot_candidates.json (optional)
        """
        if fewshot_path is None:
            # Default path
            fewshot_path = Path(__file__).parent.parent / 'configt2c' / 'fewshot_candidates.json'
        
        try:
            with open(fewshot_path, 'r') as f:
                candidates_data = json.load(f)
            
            # Flatten all examples from all categories
            all_examples = []
            for category, examples in candidates_data.items():
                for ex in examples:
                    all_examples.append(FewShotExample(
                        nl=ex['nl'],
                        cypher=ex['cypher']
                    ))
            
            # Create few-shot store with pre-computed embeddings
            self.fewshot_store = FewShotStore(all_examples, self.embedder)
            
            print(f"[Enhanced T2CSS] Loaded {len(all_examples)} few-shot examples from {len(candidates_data)} categories")
            
        except FileNotFoundError:
            print(f"[Warning] Few-shot candidates file not found at {fewshot_path}")
            print("[Warning] Dynamic few-shot selection will be disabled")
            self.fewshot_store = None
        except Exception as e:
            print(f"[Error] Failed to load few-shot candidates: {e}")
            self.fewshot_store = None
    
    def generate_cypher(
        self,
        question: str,
        fewshot_store: FewShotStore = None,
        llm = None
    ) -> str:
        """
        Generate Cypher query from natural language question
        
        Args:
            question: User's natural language question
            fewshot_store: Optional few-shot example store (uses self.fewshot_store if None)
            llm: LLM instance (OllamaLLM)
            
        Returns:
            Generated Cypher query
        """
        # Step 1: Normalize IDs
        question = normalize_ids(question)
        
        # Step 2: Classify intent (same as used for scaffold)
        intent = classify_intent(question)
        print(f"[Intent] {intent}")
        
        # Step 3: Select dynamic rules based on intent + features
        dynamic_rules, features = select_rules_for_intent(intent, question)
        active_features = features.active_features()
        if active_features:
            print(f"[Features] {active_features}")
        print(f"[Rules] {len(dynamic_rules)} total ({len(GLOBAL_RULES)} global + {len(dynamic_rules) - len(GLOBAL_RULES)} intent/micro)")
        
        # Step 4: Retrieve relevant schema
        relevant_schema = retrieve_semantic_slice(
            self.embedder,
            question,
            self.corpus_lines,
            self.corpus_embeddings,
            intent,
            k=self.top_k
        )
        
        # Step 5: Bilingualize schema
        bilingual_schema = bilingualize_slice(
            relevant_schema,
            self.label_map,
            self.rel_map
        )
        
        # Step 6: Get clause scaffold (same intent used for rules)
        scaffold = clause_scaffold(intent)
        
        # Step 7: Select few-shot examples (use internal store if available)
        store_to_use = fewshot_store if fewshot_store is not None else self.fewshot_store
        
        if store_to_use:
            examples = store_to_use.get_top_k(question, k=self.fewshot_k)
            fewshot_text = store_to_use.format_examples(examples)
            print(f"[Few-Shot] Selected {len(examples)} relevant examples")
        else:
            fewshot_text = ""
            print("[Few-Shot] No examples available (dynamic selection disabled)")
        
        # Step 8: Assemble prompt with dynamic rules
        prompt = assemble_prompt(
            question,
            bilingual_schema,
            dynamic_rules,  # Dynamic rules: global + intent-specific + micro-rules
            scaffold,
            fewshot_text
        )
        
        # Step 9: Generate with LLM
        if llm:
            cypher = llm.invoke(prompt)
            # Clean up response
            cypher = cypher.strip()
            if cypher.startswith('```'):
                lines = cypher.split('\n')
                cypher = '\n'.join(lines[1:-1]) if len(lines) > 2 else cypher
            cypher = cypher.replace('```cypher', '').replace('```', '').strip()
            return cypher
        else:
            # Return prompt for inspection
            return prompt


# Example usage
if __name__ == "__main__":
    print("="*80)
    print("Enhanced T2CSS Pipeline Test with Dynamic Few-Shot Selection")
    print("="*80)
    
    # Initialize pipeline (automatically loads few-shot candidates)
    pipeline = EnhancedT2CSSPipeline(
        top_k=10,
        fewshot_k=2,  # Select top-2 most relevant examples
        auto_load_fewshot=True  # Automatically load fewshot_candidates.json
    )
    
    # Test questions
    test_questions = [
        "Find all CVEs related to Microsoft Windows with critical severity",
        "How many campaigns are attributed to APT28?",
        "What is the shortest path between Cobalt Strike and APT29?"
    ]
    
    for i, question in enumerate(test_questions, 1):
        print(f"\n{'='*80}")
        print(f"TEST {i}: {question}")
        print("="*80)
        
        # Generate (without LLM, just show prompt)
        prompt = pipeline.generate_cypher(question)
        
        print("\n" + "-"*80)
        print("Generated Prompt Preview (first 500 chars):")
        print("-"*80)
        print(prompt[:500] + "..." if len(prompt) > 500 else prompt)
    
    print("\n" + "="*80)
    print("✅ Test Complete - Dynamic Few-Shot Selection Working!")
    print("="*80)

