"""
Query Classifier for Adaptive RRF Weighting

Classifies incoming queries into KEYWORD, SEMANTIC, or MIXED types
to drive adaptive BM25/Vector weight selection in hybrid retrieval.

Primary path: pure heuristic, <1ms per query.
Optional LLM path (enable_llm=True): invoked only when heuristic returns MIXED,
using ChatOllama (temperature=0) for deterministic structured output. Falls back
to MIXED on any LLM error so the pipeline is never blocked.
"""

import re
from enum import Enum
from typing import Tuple, Optional

from pydantic import BaseModel, Field


class QueryType(str, Enum):
    KEYWORD  = "keyword"
    SEMANTIC = "semantic"
    MIXED    = "mixed"


class _ClassifyResult(BaseModel):
    query_type: str = Field(
        description='Exactly one of: "keyword", "semantic", "mixed".'
    )


# Compiled regex for cybersecurity identifiers found in the UCKG ontology
_ID_PATTERN = re.compile(
    r'\b('
    r'CVE-\d{4}-\d{4,7}'        # CVE-YYYY-NNNNN
    r'|CWE-\d+'                  # CWE-79
    r'|CAPEC-\d+'                # CAPEC-66
    r'|T\d{4}(\.\d{3})?'         # T1059 or T1059.001 (ATT&CK technique/sub-technique)
    r'|S\d{4}'                   # S0154 (ATT&CK software)
    r'|G\d{4}'                   # G0016 (ATT&CK group)
    r'|MA\d{4}'                  # MA0001 (ATT&CK mitigation)
    r'|C\d{4}'                   # C0043 (ATT&CK campaign)
    r')\b',
    re.IGNORECASE,
)

_QUESTION_WORDS = frozenset({
    "how", "why", "what", "which", "where", "when",
    "explain", "describe", "compare", "summarize", "list",
    "discuss", "analyse", "analyze",
})

# Adaptive weight lookup: (QueryType, hop_depth) -> (bm25_weight, vector_weight)
# hop_depth is clamped to [0, 2] before lookup.
#
# Rationale:
#   KEYWORD queries benefit from BM25 (exact ID/name match); lean BM25 heavily.
#   SEMANTIC queries benefit from vector embeddings; lean vector heavily.
#   At higher hop depths, graph expansion already provides structural context,
#   so BM25 advantage for KEYWORD queries is modestly reduced.
_WEIGHT_TABLE: dict = {
    (QueryType.KEYWORD,  0): (0.70, 0.30),
    (QueryType.KEYWORD,  1): (0.65, 0.35),
    (QueryType.KEYWORD,  2): (0.60, 0.40),
    (QueryType.MIXED,    0): (0.40, 0.60),
    (QueryType.MIXED,    1): (0.40, 0.60),
    (QueryType.MIXED,    2): (0.45, 0.55),
    (QueryType.SEMANTIC, 0): (0.20, 0.80),
    (QueryType.SEMANTIC, 1): (0.25, 0.75),
    (QueryType.SEMANTIC, 2): (0.30, 0.70),
}

_SHORT_QUERY_THRESHOLD = 5   # tokens; <= this is "short"
_SEMANTIC_LENGTH_THRESHOLD = 8  # tokens; > this is "long"


class QueryClassifier:
    """
    Heuristic query classifier for hybrid retrieval weight selection,
    with an optional LLM refinement pass for ambiguous queries.

    Classification rules (heuristic, checked in priority order):
      1. Any known cybersecurity ID pattern (CVE, CWE, ATT&CK IDs, etc.) -> KEYWORD
      2. Short query (<=5 tokens) with at least one capitalised non-question-word -> KEYWORD
      3. Long query (>8 tokens) containing a question/explanation word -> SEMANTIC
      4. Everything else -> MIXED

    When enable_llm=True, rule 4 (MIXED fallback) triggers an LLM call via
    ChatOllama(temperature=0) to refine the classification. On any LLM error,
    MIXED is returned unchanged so the pipeline is never blocked.
    """

    def __init__(self, enable_llm: bool = False, llm_model: str = "llama3:8b"):
        self._enable_llm = enable_llm
        self._llm_model = llm_model
        self._llm_chain = None  # built lazily on first MIXED query

    # ------------------------------------------------------------------
    # LLM path (lazy-initialised)
    # ------------------------------------------------------------------

    def _build_chain(self) -> None:
        """Build the LangChain ChatOllama chain once and cache it."""
        from langchain_ollama import ChatOllama
        from langchain_core.prompts import PromptTemplate
        from langchain_core.output_parsers import PydanticOutputParser

        parser = PydanticOutputParser(pydantic_object=_ClassifyResult)
        prompt = PromptTemplate(
            template=(
                "You are a query classifier for a cybersecurity knowledge graph QA system.\n\n"
                "Classify the user query into exactly one category:\n"
                "- keyword: contains specific IDs, names, or technical terms "
                "(e.g. CVE IDs, tool names, threat group names, software names)\n"
                "- semantic: asks for explanations, comparisons, or general concepts\n"
                "- mixed: combines specific entities with explanatory intent\n\n"
                "{format_instructions}\n\n"
                "Query: {query}\n"
            ),
            input_variables=["query"],
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )
        llm = ChatOllama(model=self._llm_model, temperature=0)
        self._llm_chain = prompt | llm | parser

    def _llm_classify(self, query: str, fallback: QueryType) -> QueryType:
        """Call LLM to refine classification; return fallback on any error."""
        try:
            if self._llm_chain is None:
                self._build_chain()
            result: _ClassifyResult = self._llm_chain.invoke({"query": query})
            val = result.query_type.strip().lower()
            return QueryType(val) if val in QueryType._value2member_map_ else fallback
        except Exception:
            return fallback

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def classify(self, query: str) -> QueryType:
        tokens = query.strip().split()
        n = len(tokens)

        # Rule 1: explicit cybersecurity ID present
        if _ID_PATTERN.search(query):
            return QueryType.KEYWORD

        # Rule 2: short query with capitalised entity-like term
        if n <= _SHORT_QUERY_THRESHOLD:
            if any(
                t[0].isupper() and t.lower() not in _QUESTION_WORDS
                for t in tokens
                if t  # guard against empty token
            ):
                return QueryType.KEYWORD

        # Rule 3: long natural-language question
        if n > _SEMANTIC_LENGTH_THRESHOLD:
            lowered = {t.lower().rstrip("?.,") for t in tokens}
            if lowered & _QUESTION_WORDS:
                return QueryType.SEMANTIC

        # Rule 4: ambiguous — optionally refine with LLM
        if self._enable_llm:
            return self._llm_classify(query, QueryType.MIXED)
        return QueryType.MIXED

    def get_weights(
        self,
        query: str,
        hop_depth: int,
        fallback_bm25: float = 0.4,
        fallback_vector: float = 0.6,
    ) -> Tuple["QueryType", float, float]:
        """
        Classify query and return (query_type, bm25_weight, vector_weight).

        Returns a 3-tuple so callers can log the query type without a second
        classify() call.

        Args:
            query: The user query string.
            hop_depth: Graph traversal depth (0, 1, or 2).
            fallback_bm25: Used when no table entry exists (from GraphRAGConfig).
            fallback_vector: Used when no table entry exists (from GraphRAGConfig).
        """
        qt = self.classify(query)
        depth_key = max(0, min(2, hop_depth))
        bm25_w, vec_w = _WEIGHT_TABLE.get((qt, depth_key), (fallback_bm25, fallback_vector))
        return qt, bm25_w, vec_w
