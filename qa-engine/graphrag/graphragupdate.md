# GraphRAG Update — Adaptive RRF Weighting

**Date:** 2026-04-13
**Branch:** qa-engine
**Scope:** Stage 1 Retrieval — Hybrid BM25 + Vector fusion
---
## Problem Statement

The hybrid retrieval stage fused BM25 and Vector search results using pure Reciprocal Rank Fusion (RRF):
```
score = Σ  1 / (60 + rank + 1)   [same formula applied to both lists equally]
```

Both retrieval lists were treated with **identical rank weight**, regardless of what kind of query was asked. This is suboptimal because BM25 and Vector search have fundamentally different strengths:

| Retrieval Method | Strong At | Weak At |
|---|---|---|
| **BM25** | Exact identifiers (CVE-2021-44228, T1059, CWE-79), entity names (Mimikatz, Log4Shell), acronyms | Conceptual/semantic similarity, paraphrased queries |
| **Vector** | Semantic similarity, natural language questions, paraphrased or conceptual queries | Exact string match, rare/specific identifiers |

Additionally, two config fields `bm25_weight=0.4` and `vector_weight=0.6` already existed in `GraphRAGConfig` but were **dead code** — defined but never referenced anywhere in the pipeline.

---

## Thought Process

### Step 1 — Identify the gap
Examining `hybrid.py:_merge_results_rrf()` confirmed that the RRF formula applied `1/(k+rank+1)` identically to both BM25 and vector rank lists. The existing config weights were never passed into this function.

### Step 2 — Characterise query types in the UCKG domain
In a cybersecurity knowledge graph, queries naturally fall into distinct categories:

- **KEYWORD queries** — contain explicit cybersecurity identifiers or entity names. BM25 tokenises these exactly, giving near-perfect recall. Vector embeddings often dilute specificity for rare IDs.
  - Examples: `"CVE-2021-44228"`, `"T1059.001"`, `"Mimikatz"`, `"Log4Shell"`

- **SEMANTIC queries** — natural language questions that require conceptual understanding. Vector embeddings capture the meaning even when exact words differ.
  - Examples: `"how does lateral movement work?"`, `"explain credential dumping techniques"`

- **MIXED queries** — neither clearly keyword nor semantic; a balanced split is appropriate.
  - Examples: `"credential dumping windows"`, `"phishing email indicators"`

### Step 3 — Factor in hop depth
At higher hop depths, graph traversal already enriches the result set with structural context (neighbors, relationships). This means:
- At **hop=0**: retrieval quality depends almost entirely on the initial candidate pool — weight differentiation matters most.
- At **hop=2**: even a coarser initial seed gets enriched by 2-hop graph expansion. The BM25 advantage for KEYWORD queries is slightly reduced (BM25 weight trends down from 0.70 to 0.60 as hop depth increases).

### Step 4 — Design the weight table
Rather than a complex learned model, a simple lookup table indexed by `(QueryType, hop_depth)` provides transparent, auditable, easily tunable behavior with zero runtime cost:

| Query Type | Hop 0 | Hop 1 | Hop 2 |
|---|---|---|---|
| KEYWORD  | (0.70, 0.30) | (0.65, 0.35) | (0.60, 0.40) |
| MIXED    | (0.40, 0.60) | (0.40, 0.60) | (0.45, 0.55) |
| SEMANTIC | (0.20, 0.80) | (0.25, 0.75) | (0.30, 0.70) |

### Step 5 — Design the classifier
A lightweight heuristic classifier was chosen over an LLM-based approach for latency reasons (classification must complete in <1ms, not 1-3 seconds). Three prioritised rules:

1. **Regex for known cybersecurity IDs** → KEYWORD (highest confidence signal)
2. **Short query (≤5 tokens) + capitalised term** → KEYWORD (entity name lookup)
3. **Long query (>8 tokens) + question word** → SEMANTIC
4. **Fallback** → MIXED

### Step 6 — Activate dead config fields
The existing `bm25_weight` and `vector_weight` in `GraphRAGConfig` were repurposed as fallback values passed into the classifier's `get_weights()` method, ensuring any edge cases not covered by the lookup table still respect operator-configured defaults.

### Step 7 — Optional LLM refinement pass
For ambiguous (MIXED) queries, an optional LLM refinement call can be enabled via `enable_llm_classification=True` in `GraphRAGConfig`. When enabled, heuristic rule 4 (MIXED fallback) triggers a `ChatOllama(temperature=0)` call via LangChain instead of returning MIXED directly. The LLM is given a structured prompt and must output a `_ClassifyResult` Pydantic model. On any error, it falls back to MIXED — the pipeline is never blocked. The chain is built lazily on the first MIXED query to avoid startup cost when the feature is disabled.

---

## Files Modified

| File | Change Type | Summary |
|---|---|---|
| `retrieval/classifier.py` | **NEW** | `QueryType` enum, `QueryClassifier` class, `_WEIGHT_TABLE` |
| `retrieval/__init__.py` | Modified | Added `QueryClassifier, QueryType` exports |
| `retrieval/hybrid.py` | Modified | Classifier integrated into `__init__`, `retrieve()`, `_merge_results_rrf()`, `_retrieve_late_expand()` |
| `pipeline.py` | Modified | `QueryType` import; `query_type` propagated through `_execute_pipeline()` and `run()` |
| `utils.py` | Modified | Added `enable_llm_classification: bool = False` and `classifier_llm_model: str = "llama3:8b"` to `GraphRAGConfig`; `bm25_weight`/`vector_weight` activated as fallback |

---

## Detailed Changes

### `retrieval/classifier.py` (new file)

```
QueryType (str Enum)
  KEYWORD | SEMANTIC | MIXED

_ID_PATTERN (compiled regex)
  Matches: CVE-YYYY-N, CWE-N, CAPEC-N, T1234(.001), S1234, G1234, MA1234, C1234

_WEIGHT_TABLE (module-level constant)
  Dict[(QueryType, hop_depth)] -> (bm25_weight, vector_weight)
  hop_depth clamped to [0, 2] before lookup

QueryClassifier(enable_llm=False, llm_model="llama3:8b")
  .classify(query) -> QueryType
    Rule 1: ID regex match          -> KEYWORD
    Rule 2: short + capitalised     -> KEYWORD
    Rule 3: long + question word    -> SEMANTIC
    else if enable_llm              -> LLM call (falls back to MIXED on error)
    else                            -> MIXED

  .get_weights(query, hop_depth, fallback_bm25, fallback_vector)
    -> (QueryType, bm25_weight, vector_weight)
    Returns 3-tuple to avoid double classification for logging

  LLM path (lazy):
    Built on first MIXED query; uses ChatOllama(temperature=0)
    Structured output via PydanticOutputParser(_ClassifyResult)
    Enabled via GraphRAGConfig.enable_llm_classification=True
    Model configurable via GraphRAGConfig.classifier_llm_model
```

### `retrieval/hybrid.py` changes

**`__init__`** — two new instance variables:
```python
self.classifier = QueryClassifier(
    enable_llm=config.enable_llm_classification,
    llm_model=config.classifier_llm_model,
)
self._last_query_type: Optional[QueryType] = None
```

**`retrieve()`** — before calling `_merge_results_rrf()`:
```python
depth = hop_depth if hop_depth is not None else 0
qt, bm25_w, vector_w = self.classifier.get_weights(
    query, depth, self.config.bm25_weight, self.config.vector_weight
)
self._last_query_type = qt
# logs: [HybridRetriever] query_type=keyword hop=2 bm25_w=0.60 vector_w=0.40
merged_results = self._merge_results_rrf(
    bm25_results, vector_results, bm25_weight=bm25_w, vector_weight=vector_w
)
```

**`_merge_results_rrf()`** — new signature + weighted accumulation:
```python
# Before:
rrf_scores[node_id] += 1.0 / (k + rank + 1)          # BM25 and Vector identical

# After:
rrf_scores[node_id] += bm25_weight * (1.0 / (k + rank + 1))    # BM25 list
rrf_scores[node_id] += vector_weight * (1.0 / (k + rank + 1))  # Vector list
```
Default parameters `bm25_weight=0.5, vector_weight=0.5` preserve backward compatibility for any direct caller.

**`_retrieve_late_expand()`** — adaptive weights at hop=0 (seeds are always flat):
```python
qt, bm25_w, vector_w = self.classifier.get_weights(
    query, 0, self.config.bm25_weight, self.config.vector_weight
)
seeds = self._merge_results_rrf(
    bm25_results, vector_results, bm25_weight=bm25_w, vector_weight=vector_w
)[:top_k]
```

### `pipeline.py` changes

- Added `from .retrieval import QueryType`
- After `self.retriever.retrieve(...)`, reads `self.retriever._last_query_type` when retriever is `HybridRetriever`
- `_execute_pipeline()` return dict gains `"query_type": query_type_str`
- `run()` gains `"query_type": query_type` in its return dict

---

## Overall Workflow — Before vs After

### BEFORE

```
User Query
    │
    ▼
[Optional HyDE]
    │
    ▼
Hop Depth Determination (static from config)
    │
    ▼
HybridRetriever.retrieve()
    ├─ BM25 search  ──────────────────────────────┐
    │                                             │
    └─ Vector search ─────────────────────────────┤
                                                  ▼
                                         _merge_results_rrf()
                                           score = 1/(60+rank+1)  ← SAME for both lists
                                           [bm25_weight and vector_weight in config
                                            but NEVER USED — dead code]
    │
    ▼
Entity Name Boosting
    │
    ▼
PPR (optional)
    │
    ▼
Cross-Encoder Reranking (2-pass)
    │
    ▼
Subgraph Pruning (optional)
    │
    ▼
Context Formatting + LLM Generation
    │
    ▼
{ answer, sources, context, pruning_metadata }
   [no query_type in output]
```

### AFTER

```
User Query
    │
    ▼
[Optional HyDE]
    │
    ▼
Hop Depth Determination (static from config)
    │
    ▼
HybridRetriever.retrieve()
    ├─ BM25 search  ──────────────────────────────┐
    │                                             │
    └─ Vector search ─────────────────────────────┤
                                                  ▼
                                        QueryClassifier.get_weights(query, hop_depth)
                                          Rule 1: CVE/CWE/ATT&CK ID?  → KEYWORD
                                          Rule 2: short + capitalised? → KEYWORD
                                          Rule 3: long + question?     → SEMANTIC
                                          else                         → MIXED
                                                  │
                                                  ▼
                                        Lookup _WEIGHT_TABLE[(QueryType, hop_depth)]
                                          e.g. KEYWORD+hop2  → bm25=0.60, vec=0.40
                                               SEMANTIC+hop2  → bm25=0.30, vec=0.70
                                               MIXED+hop1     → bm25=0.40, vec=0.60
                                                  │
                                                  ▼
                                        _merge_results_rrf(bm25_weight, vector_weight)
                                          score = bm25_w/(60+rank+1)  ← BM25 list
                                                + vec_w/(60+rank+1)   ← Vector list
                                          [config bm25_weight/vector_weight now ACTIVE
                                           as fallback for unmatched cases]
    │
    ▼
Entity Name Boosting
    │
    ▼
PPR (optional)
    │
    ▼
Cross-Encoder Reranking (2-pass)
    │
    ▼
Subgraph Pruning (optional)
    │
    ▼
Context Formatting + LLM Generation
    │
    ▼
{ answer, sources, context, pruning_metadata, query_type }
   [query_type now surfaced in output for evaluation/debugging]
```

---

## Backward Compatibility

- `_merge_results_rrf()` defaults to `bm25_weight=0.5, vector_weight=0.5` — equal weighting, mathematically identical to the old behavior for any direct caller
- When `enable_hybrid_retrieval=False`, classifier is never instantiated and behavior is unchanged
- `query_type` is a new optional key in `run()` output — existing callers that ignore it are unaffected
- Edge cases (empty query → MIXED, `hop_depth=None` → clamped to 0) handled gracefully

---

## Verification Checklist

- [ ] `QueryClassifier.classify("CVE-2021-44228")` → `"keyword"`
- [ ] `QueryClassifier.classify("T1059.001")` → `"keyword"`
- [ ] `QueryClassifier.classify("Mimikatz")` → `"keyword"`
- [ ] `QueryClassifier.classify("how does lateral movement work in ATT&CK?")` → `"semantic"`
- [ ] `QueryClassifier.classify("credential dumping windows")` → `"mixed"`
- [ ] CVE query at hop=2 logs `bm25_w=0.60 vector_w=0.40`
- [ ] Semantic query at hop=2 logs `bm25_w=0.30 vector_w=0.70`
- [ ] `run()` return dict contains `"query_type"` field
- [ ] Pipeline with `enable_hybrid_retrieval=False` still works without errors
