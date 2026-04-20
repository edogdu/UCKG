# NER (Named Entity Recognition) Upgrade Plan

## Why NER?

The current `QueryClassifier` uses pure heuristics to classify queries:
- Regex for structured IDs (CVE-*, CWE-*, CAPEC-*, ATT&CK IDs) //////////////////
- Token count and capitalization for everything else

This fails for mixed queries like *"How does Log4Shell affect Apache servers via CVE-2021-44228"*:
- The classifier sees >8 tokens + question word "How" → classifies as **SEMANTIC**
- SEMANTIC gives BM25 only 20% weight → exact-match retrieval underperforms
- `entity_name_lookup(query)` runs a CONTAINS on the full 10-word string → many false positives

**NER fixes both problems:** detects entity spans → corrects misclassification → enables per-entity precise lookups.

---

## Architecture Overview

```
USER QUERY
    │
    ▼
┌─────────────────────────────┐
│  CybersecurityNERExtractor  │  ← NEW  (graphrag/retrieval/ner.py)
│                             │
│  Pass 1: Regex              │  → CVE, CWE, CAPEC, MITRE IDs
│  Pass 2: spaCy EntityRuler  │  → SOFTWARE, GROUP, TACTIC names
│                             │
│  Returns: NERResult         │
└──────────────┬──────────────┘
               │
       ┌───────┴────────────────────────────────────┐
       │                                            │
       ▼                                            ▼
┌──────────────────┐                   ┌─────────────────────────┐
│  QueryClassifier │  ← MODIFIED       │  Entity Boosting Block  │  ← MODIFIED
│  (classifier.py) │                   │  (pipeline.py)          │
│                  │                   │                         │
│  NER override:   │                   │  OLD: CONTAINS(query)   │
│  SEMANTIC→MIXED  │                   │  NEW: per-entity lookup │
│  if SW/CVE found │                   │  CONTAINS(entity.text)  │
└────────┬─────────┘                   └─────────────────────────┘
         │
         ▼
┌─────────────────────┐
│  HybridRetriever    │  ← MINOR THREAD-THROUGH
│  (hybrid.py)        │  (passes _current_ner_result to classifier)
└─────────────────────┘
```

---

## Data Structures

```python
# graphrag/retrieval/ner.py

class CyberEntityType(str, Enum):
    CVE          = "CVE"           # CVE-2021-44228
    CWE          = "CWE"           # CWE-79
    CAPEC        = "CAPEC"         # CAPEC-66
    MITRE_ATTACK = "MITRE_ATTACK"  # T1059, S0154, G0016
    SOFTWARE     = "SOFTWARE"      # "Apache Log4j", "WannaCry"
    GROUP        = "GROUP"         # "APT29", "Lazarus Group"
    TACTIC       = "TACTIC"        # "Lateral Movement"

@dataclass
class CyberEntity:
    text: str           # e.g. "Log4Shell", "CVE-2021-44228"
    entity_type: CyberEntityType
    start: int          # char offset in query
    end: int
    confidence: float   # 1.0 = regex, 0.9 = EntityRuler

@dataclass
class NERResult:
    entities: List[CyberEntity]
    query: str
    # Computed properties:
    # .has_entities          → bool
    # .has_structured_ids    → True if CVE/CWE/CAPEC/MITRE present
    # .has_software_entities → True if SOFTWARE present
    # .all_entity_texts()    → deduplicated entity span strings
```

---

## Files Changed

### 1. `graphrag/retrieval/ner.py` — NEW FILE

```
CybersecurityNERExtractor
├── __init__()           → tries to load spaCy, sets self._available
├── _try_load_spacy()    → import spacy, load en_core_web_sm or blank("en")
├── _add_entity_ruler()  → adds SOFTWARE/GROUP/TACTIC phrase patterns
├── available (property) → bool
└── extract(query)       → NERResult
    ├── Pass 1: _ID_PATTERN.finditer(query) → CVE/CWE/CAPEC/MITRE entities
    └── Pass 2: nlp(query).ents → SOFTWARE/GROUP/TACTIC entities (if spaCy available)
```

**EntityRuler seed patterns:**
- SOFTWARE: `Apache Log4j`, `Log4Shell`, `OpenSSL`, `Cobalt Strike`, `Mimikatz`, `WannaCry`, `EternalBlue`, `Spring4Shell`, `ProxyLogon`, `SolarWinds Orion`, ...
- GROUP: `APT28`, `APT29`, `APT41`, `Lazarus Group`, `Cozy Bear`, `Fancy Bear`, `REvil`, `LockBit`, `DarkSide`, `Scattered Spider`, ...
- TACTIC: `Initial Access`, `Lateral Movement`, `Defense Evasion`, `Credential Access`, `Privilege Escalation`, `Exfiltration`, `Impact`, ...

**Graceful degradation chain:**
1. spaCy not installed → `_available=False`, Pass 2 skipped, Pass 1 still runs
2. `en_core_web_sm` not downloaded → `spacy.blank("en")` used, EntityRuler still works
3. Any exception in `extract()` → returns empty `NERResult`, pipeline continues normally

---

### 2. `graphrag/utils.py` — Add 4 Config Fields

Added to `GraphRAGConfig` dataclass after `enable_entity_name_boosting`:

```python
# NER configuration
enable_ner: bool = False              # Opt-in; requires spaCy
ner_override_classifier: bool = True  # Allow NER to override SEMANTIC → MIXED
ner_entity_lookup_limit: int = 3      # Max per-entity DB lookups
ner_min_confidence: float = 0.8       # Min confidence threshold for boosting
```

Default `enable_ner=False` means zero code path is exercised without explicit opt-in.

---

### 3. `graphrag/retrieval/classifier.py` — NER Override Path

`classify()` and `get_weights()` gain an optional backward-compatible parameter:

```python
def classify(self, query: str, ner_result: Optional[NERResult] = None) -> QueryType:

    # Rule 1: Regex ID (unchanged)
    if _ID_PATTERN.search(query):
        return QueryType.KEYWORD

    # Rule 1b: NER override (NEW — runs only if ner_result provided)
    if ner_result and ner_result.has_entities:
        if ner_result.has_structured_ids:
            return QueryType.KEYWORD          # CVE/CWE in a long question → KEYWORD
        if ner_result.has_software_entities:
            # "How does Log4Shell affect Apache..." → MIXED instead of SEMANTIC
            if n > _SEMANTIC_LENGTH_THRESHOLD and lowered & _QUESTION_WORDS:
                return QueryType.MIXED

    # Rule 2-4: unchanged heuristics
    ...
```

Effect on BM25/vector weights (from existing `_WEIGHT_TABLE`):

| Scenario | Old type | Old BM25 | New type | New BM25 |
|---|---|---|---|---|
| "How does Log4Shell affect..." | SEMANTIC | 0.20 | MIXED | 0.40 |
| "CVE-2021-44228 impact" (any length) | KEYWORD (regex) | 0.65 | KEYWORD | 0.65 (unchanged) |

---

### 4. `graphrag/retrieval/hybrid.py` — Thread NER Result

Two callsites where `get_weights()` is called gain `ner_result` pass-through:

```python
# In retrieve() and _retrieve_late_expand():
qt, bm25_w, vector_w = self.classifier.get_weights(
    query, depth,
    self.config.bm25_weight, self.config.vector_weight,
    ner_result=getattr(self, '_current_ner_result', None),   # NEW
)
```

`_current_ner_result` is set on the retriever by the pipeline before calling `retrieve()` and cleared after.

---

### 5. `graphrag/pipeline.py` — Central Orchestration

#### Initialization (follows `_initialize_ppr()` pattern)

```python
# In __init__() after PPR block:
self.ner_extractor = None
if self.config.enable_ner:
    self._initialize_ner()

def _initialize_ner(self):
    extractor = CybersecurityNERExtractor()
    if extractor.available:
        self.ner_extractor = extractor
        logger.info("NER extractor initialized (spaCy EntityRuler)")
    else:
        logger.warning("spaCy not available. pip install spacy && python -m spacy download en_core_web_sm")
        self.config.enable_ner = False
```

#### `_execute_pipeline()` — Two Injection Points

```
_execute_pipeline(query)
    │
    ├── [Optional HyDE — unchanged]
    │
    ├── NER EXTRACTION (NEW)
    │   ner_result = ner_extractor.extract(query)   ← always on raw query
    │
    ├── INJECTION POINT 1: Classifier correction
    │   retriever._current_ner_result = ner_result
    │   items = retriever.retrieve(query, top_k, hop_depth)
    │   retriever._current_ner_result = None          ← clear after
    │
    ├── [Relationship retrieval — unchanged]
    │
    ├── INJECTION POINT 2: Entity boosting
    │   IF enable_ner AND ner_result.has_entities:
    │       entity_matches = _ner_entity_lookup(ner_result)  ← per-entity
    │   ELSE:
    │       entity_matches = entity_name_lookup(query)       ← existing fallback
    │
    ├── [PPR, reranking, pruning — unchanged]
    │
    └── return {..., "ner_entities": [...]}   ← NEW additive key
```

#### New method `_ner_entity_lookup(ner_result)`

```
_ner_entity_lookup(ner_result)
    │
    ├── Filter: entities with confidence >= ner_min_confidence
    ├── Sort: CVE > CWE > CAPEC > MITRE > SOFTWARE > GROUP > TACTIC
    ├── Cap: at most ner_entity_lookup_limit lookups
    │
    └── For each entity:
            vector_retriever.entity_name_lookup(entity.text, limit=3)
            │  ← reuses existing method, passes entity SPAN not full query
            └── deduplicate by nodeId → return merged list
```

The existing `entity_name_lookup()` in `vector.py` is **not modified** — it already accepts any string and runs `CONTAINS` on it. Passing `"Apache Log4j"` instead of `"How does Log4Shell affect Apache servers via CVE-2021-44228"` makes the match far more precise.

---

### 6. `graphrag/retrieval/__init__.py` — 1 Line Added

```python
from .ner import CybersecurityNERExtractor, NERResult, CyberEntityType, CyberEntity
```

---

## End-to-End Example

**Query:** `"How does Log4Shell affect Apache servers via CVE-2021-44228"`

```
NER extraction:
  Pass 1 (regex): CVE-2021-44228 → CyberEntity(text="CVE-2021-44228", type=CVE, confidence=1.0)
  Pass 2 (spaCy): Log4Shell      → CyberEntity(text="Log4Shell",      type=SOFTWARE, confidence=0.9)
                  Apache         → CyberEntity(text="Apache",          type=SOFTWARE, confidence=0.9)

NERResult.has_structured_ids = True (CVE present)

Classifier (Rule 1b): CVE found → QueryType.KEYWORD
  Old result: SEMANTIC  (bm25=0.20, vector=0.80)
  New result: KEYWORD   (bm25=0.65, vector=0.35)

Entity boosting (3 separate lookups):
  entity_name_lookup("CVE-2021-44228") → hits UcoCVE node
  entity_name_lookup("Log4Shell")      → hits UcoexSOFTWARE node
  entity_name_lookup("Apache")         → hits UcoexSOFTWARE nodes

  Old: CONTAINS("How does Log4Shell affect Apache servers via CVE-2021-44228") → 0 hits
  New: 3 targeted lookups → 3+ precise hits injected into candidate pool
```

---

## Installation

```bash
pip install spacy>=3.7
python -m spacy download en_core_web_sm   # ~12 MB
```

Not required until `enable_ner=True` is set (default is `False`). No `requirements.txt` changes needed for opt-in deployment.

---

## Verification Tests

```python
# 1. NER extractor
extractor = CybersecurityNERExtractor()
result = extractor.extract("How does Log4Shell affect Apache servers via CVE-2021-44228")
assert result.has_structured_ids           # CVE-2021-44228 detected
assert result.has_software_entities        # Log4Shell detected

# 2. Classifier override
clf = QueryClassifier()
ner = NERResult(entities=[CyberEntity("CVE-2021-44228", CyberEntityType.CVE, 0, 14, 1.0)])
assert clf.classify("How does this CVE affect systems", ner_result=ner) == QueryType.KEYWORD
assert clf.classify("How does this CVE affect systems") == QueryType.SEMANTIC  # unchanged without NER

# 3. Regression: enable_ner=False (default) — all existing tests pass unmodified
pipeline = GraphRAGPipeline()           # enable_ner defaults to False
assert pipeline.ner_extractor is None   # NER not loaded
```
