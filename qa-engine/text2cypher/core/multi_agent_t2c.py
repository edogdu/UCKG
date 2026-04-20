"""
Multi-Agent Text2Cypher Pipeline (LangGraph)

Inspired by:
  "Multi-Agent GraphRAG: A Text-to-Cypher Framework for Labeled Property Graphs"
  (Gusarov et al., 2025, arXiv:2511.08274)

Architecture — 7 cooperating agents + 1 executor:
  1. Query Generator      – uses Enhanced T2CSS (semantic slices + dynamic few-shots)
  2. Graph DB Executor     – runs Cypher against Neo4j
  3. Query Evaluator       – LLM critic grades: Accept / Incorrect / Error-or-Empty
  4. Named Entity Extractor– LLM extracts node labels, properties, relationships from Cypher
  5. Verification Module   – checks entities against the live graph, suggests fixes
  6. Instructions Generator– synthesises correction instructions from verification results
  7. Feedback Aggregator   – merges evaluator + verification feedback into one strategy
  8. Interpreter           – produces a natural-language answer from accepted results

Self-correction loop (Algorithm 1 from the paper):
  generate → execute → evaluate
    ├─ Accept        → interpret → END
    ├─ Incorrect     → aggregate(evaluator feedback) → regenerate
    └─ Error/Empty   → extract entities → verify → generate instructions
                       → aggregate(evaluator + verification) → regenerate
  (up to max_iterations)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class MultiAgentState(TypedDict, total=False):
    # --- Inputs ---
    question: str

    # --- Schema context (from Enhanced T2CSS) ---
    schema_text: str
    semantic_slice: List[str]
    bilingual_slice: List[str]
    few_shot_text: str
    intent: str
    rules: List[str]
    scaffold: str

    # --- Generation loop ---
    prompt: str
    cypher: str
    iteration: int
    max_iterations: int

    # --- Execution ---
    execution_result: Optional[List[Dict[str, Any]]]
    execution_error: Optional[str]

    # --- Evaluation ---
    eval_grade: str          # "accept" | "incorrect" | "error_or_empty"
    eval_feedback: str

    # --- Entity verification ---
    extracted_entities: Dict[str, Any]
    verification_results: Dict[str, Any]
    correction_instructions: str

    # --- Feedback aggregation ---
    aggregated_feedback: str

    # --- Final output ---
    answer: str
    status: str              # "success" | "max_iterations" | "error"
    message: str

    # --- Trace (for inspection / evaluation) ---
    trace: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Agent prompt templates
# ---------------------------------------------------------------------------

EVALUATOR_SYSTEM = """\
You are a Cypher query evaluator for a cybersecurity knowledge graph (Neo4j).

Given:
- The user's QUESTION
- The generated CYPHER query
- The EXECUTION OUTCOME (result rows, error message, or empty)

Classify the query into exactly one grade and provide structured feedback.

Grades:
  ACCEPT        – query is error-free AND the returned results fully and logically
                  answer the user's question.
  INCORRECT     – query executes without error and returns data, but is semantically
                  misaligned, logically flawed, or incomplete.
  ERROR_OR_EMPTY – query either fails with a runtime error or returns no results.

Output format (JSON only, no markdown fences):
{
  "grade": "ACCEPT" | "INCORRECT" | "ERROR_OR_EMPTY",
  "feedback": "<concise explanation of issues and suggested fixes>"
}
"""

EVALUATOR_USER = """\
QUESTION: {question}

CYPHER:
{cypher}

EXECUTION OUTCOME:
{outcome}

Evaluate the query and return JSON with grade and feedback."""


ENTITY_EXTRACTOR_SYSTEM = """\
You are a Cypher query entity extractor for a Neo4j cybersecurity knowledge graph.

Given a Cypher query, extract all schema elements that could be hallucinated or incorrect:
- Node labels used
- Node property name-value pairs used in WHERE/match conditions
- Relationship types (as pairwise patterns like (:Label)-[:TYPE]->(:Label))

Output format (JSON only, no markdown fences):
{
  "node_labels": ["Label1", "Label2"],
  "node_property_values": [
    {"label": "Label1", "property": "propName", "value": "propValue"}
  ],
  "pairwise_relationships": [
    "(:Label1)-[:REL_TYPE]->(:Label2)"
  ]
}
"""

ENTITY_EXTRACTOR_USER = """\
CYPHER:
{cypher}

Extract all schema entities as JSON."""


INSTRUCTIONS_SYSTEM = """\
You are a correction instructions generator for Cypher queries against a Neo4j cybersecurity knowledge graph.

Given verification results showing which entities are valid and which are hallucinated, generate concise, actionable instructions for rewriting the query.

For each invalid entity, suggest the best replacement from the provided candidates.

Output only the correction instructions as plain text, numbered."""

INSTRUCTIONS_USER = """\
VERIFICATION RESULTS:
{verification_json}

Generate numbered correction instructions."""


AGGREGATOR_SYSTEM = """\
You are a feedback aggregator for a multi-agent Cypher query generation system.

Merge the evaluator feedback and (optionally) entity verification instructions into a single, prioritised correction strategy.

Be concise. Output the unified correction strategy as plain text."""

AGGREGATOR_USER = """\
USER QUESTION: {question}

EVALUATOR FEEDBACK:
{eval_feedback}

VERIFICATION INSTRUCTIONS:
{verification_instructions}

Generate a unified correction strategy."""


INTERPRETER_SYSTEM = """\
You are a cybersecurity knowledge graph assistant.
Given the user's question and the database query results, generate a concise, accurate, domain-relevant natural language answer.
If the results are empty or unclear, state that honestly."""

INTERPRETER_USER = """\
QUESTION: {question}

QUERY RESULTS:
{results}

Provide a concise natural-language answer."""


# ---------------------------------------------------------------------------
# Verification helpers (database-grounded, no LLM needed)
# ---------------------------------------------------------------------------

def _levenshtein_ratio(s1: str, s2: str) -> float:
    """Normalised Levenshtein similarity (0-100). Uses rapidfuzz if available."""
    try:
        from rapidfuzz import fuzz
        return fuzz.ratio(s1, s2)
    except ImportError:
        # Pure-python fallback (simple ratio)
        s1l, s2l = s1.lower(), s2.lower()
        if s1l == s2l:
            return 100.0
        len1, len2 = len(s1l), len(s2l)
        max_len = max(len1, len2)
        if max_len == 0:
            return 100.0
        # Simple character overlap ratio
        common = sum(1 for a, b in zip(s1l, s2l) if a == b)
        return (common / max_len) * 100.0


def verify_node_label(session, label: str) -> Dict[str, Any]:
    """Check if a node label exists in the graph."""
    rec = session.run(f"MATCH (n:`{label}`) RETURN 1 LIMIT 1").single()
    if rec is not None:
        return {"label": label, "exists": True, "suggestions": []}

    # Label doesn't exist — find similar labels
    all_labels_result = session.run("CALL db.labels()")
    all_labels = [r["label"] for r in all_labels_result]

    scored = [
        {"label": l, "score": _levenshtein_ratio(label, l)}
        for l in all_labels
    ]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return {
        "label": label,
        "exists": False,
        "suggestions": scored[:5],
    }


def verify_property_value(session, label: str, prop: str, value: str) -> Dict[str, Any]:
    """Check if a property value exists for a given label."""
    rec = session.run(
        f"MATCH (n:`{label}`) WHERE toLower(toString(n.`{prop}`)) = toLower($v) "
        f"RETURN n.`{prop}` AS val LIMIT 1",
        {"v": value},
    ).single()
    if rec is not None:
        return {"label": label, "property": prop, "value": value, "exists": True, "suggestions": []}

    # Value doesn't exist — find similar values
    candidates_result = session.run(
        f"MATCH (n:`{label}`) WHERE n.`{prop}` IS NOT NULL "
        f"RETURN DISTINCT toString(n.`{prop}`) AS val LIMIT 200"
    )
    all_values = [r["val"] for r in candidates_result if r["val"] is not None]

    scored = [
        {"value": v, "score": _levenshtein_ratio(value, v)}
        for v in all_values
    ]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return {
        "label": label,
        "property": prop,
        "value": value,
        "exists": False,
        "suggestions": scored[:5],
    }


def verify_relationship_pattern(session, pattern: str) -> Dict[str, Any]:
    """Check if a relationship pattern exists. Pattern: (:Label)-[:TYPE]->(:Label)"""
    m = re.search(
        r"\(:?\s*([A-Za-z0-9_]+)\s*\)\s*-\s*\[:?\s*([A-Z_]+)\s*\]\s*->\s*\(:?\s*([A-Za-z0-9_]+)\s*\)",
        pattern,
    )
    if not m:
        return {"pattern": pattern, "exists": False, "error": "Could not parse pattern", "suggestions": []}

    src, rel_type, tgt = m.group(1), m.group(2), m.group(3)
    rec = session.run(
        f"MATCH (:`{src}`)-[:`{rel_type}`]->(:`{tgt}`) RETURN 1 LIMIT 1"
    ).single()
    if rec is not None:
        return {"pattern": pattern, "exists": True, "suggestions": []}

    # Check which part is wrong
    rel_exists = session.run(f"MATCH ()-[r:`{rel_type}`]-() RETURN 1 LIMIT 1").single()
    suggestions = []
    if rel_exists is None:
        all_rels = [r["relationshipType"] for r in session.run("CALL db.relationshipTypes()")]
        suggestions = [
            {"type": rt, "score": _levenshtein_ratio(rel_type, rt)}
            for rt in all_rels
        ]
        suggestions.sort(key=lambda x: x["score"], reverse=True)
        suggestions = suggestions[:5]

    return {"pattern": pattern, "exists": False, "suggestions": suggestions}


# ---------------------------------------------------------------------------
# LLM calling helper
# ---------------------------------------------------------------------------

def _llm_call(llm, system: str, user: str, max_tokens: int = 500) -> str:
    """Invoke the LLM with a system+user prompt pair.

    Uses a direct Ollama API call with relaxed settings (higher token limit,
    no premature stop sequences) since agent tasks (evaluation, extraction)
    produce longer JSON/text outputs than Cypher generation.

    Falls back to llm.invoke() if the direct call fails.
    """
    prompt = f"SYSTEM:\n{system}\n\nUSER:\n{user}\n\nASSISTANT:\n"
    try:
        import httpx
        base_url = getattr(llm, "base_url", os.getenv("OLLAMA_URL", "http://localhost:11434"))
        model = getattr(llm, "model", os.getenv("OLLAMA_MODEL", "llama3"))
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.1,
            "num_predict": max_tokens,
            "stop": ["USER:", "SYSTEM:"],
        }
        resp = httpx.post(f"{base_url}/api/generate", json=payload, timeout=90)
        resp.raise_for_status()
        return resp.json()["response"].strip()
    except Exception:
        return llm.invoke(prompt).strip()


def _parse_json_response(text: str) -> Dict[str, Any]:
    """Best-effort extraction of JSON from LLM output."""
    # Strip markdown fences
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = re.sub(r"```", "", cleaned).strip()
    # Try direct parse
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Try to find first { ... } block
    m = re.search(r"\{[\s\S]*\}", cleaned)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return {}


# ---------------------------------------------------------------------------
# Cypher extraction (reuse existing utility)
# ---------------------------------------------------------------------------

try:
    from core.text2cypher import extract_cypher
except ImportError:
    try:
        from text2cypher import extract_cypher
    except ImportError:
        def extract_cypher(text: str) -> str:
            text = re.sub(r"```(?:cypher)?\s*\n?", "", text)
            text = re.sub(r"```", "", text).strip()
            return text


# ---------------------------------------------------------------------------
# Multi-Agent Pipeline
# ---------------------------------------------------------------------------

class MultiAgentText2Cypher:
    """
    Multi-agent LangGraph pipeline for text-to-Cypher generation.

    Combines the Enhanced T2CSS pipeline (semantic schema slices, intent
    classification, dynamic rules, dynamic few-shots) with the paper's
    iterative self-correction loop:

        generate → execute → evaluate → [verify] → [aggregate feedback] → regenerate

    Parameters
    ----------
    neo4j_driver : neo4j.Driver
        Active Neo4j driver for query execution and verification.
    llm : OllamaLLM
        LLM instance (invoke(prompt) → str).
    enhanced_pipeline : EnhancedT2CSSPipeline, optional
        Pre-initialised Enhanced T2CSS pipeline. If None, one will be
        created with default settings.
    max_iterations : int
        Maximum self-correction iterations (paper uses 4).
    verbose : bool
        Print agent trace to stdout.
    """

    def __init__(
        self,
        neo4j_driver,
        llm,
        enhanced_pipeline=None,
        max_iterations: int = 4,
        verbose: bool = True,
    ):
        self.driver = neo4j_driver
        self.llm = llm
        self.max_iterations = max_iterations
        self.verbose = verbose

        # Lazily import Enhanced T2CSS
        if enhanced_pipeline is not None:
            self.pipeline = enhanced_pipeline
        else:
            self.pipeline = self._init_default_pipeline()

        self.graph = self._build_graph()

    # ------------------------------------------------------------------
    # Pipeline initialisation
    # ------------------------------------------------------------------

    def _init_default_pipeline(self):
        try:
            from core.t2css_enhanced import EnhancedT2CSSPipeline
        except ImportError:
            from t2css_enhanced import EnhancedT2CSSPipeline
        return EnhancedT2CSSPipeline(
            top_k=12,
            fewshot_k=3,
            auto_load_fewshot=True,
        )

    # ------------------------------------------------------------------
    # Agent implementations
    # ------------------------------------------------------------------

    def _agent_retrieve_schema(self, state: MultiAgentState) -> dict:
        """Agent 0: Retrieve semantic schema slice & few-shots via Enhanced T2CSS."""
        try:
            from core.t2css_enhanced import (
                classify_intent,
                clause_scaffold,
                normalize_ids,
                render_schema_line,
                retrieve_semantic_slice,
            )
            from core.dynamic_rules import GLOBAL_RULES, select_rules_for_intent
        except ImportError:
            from t2css_enhanced import (
                classify_intent,
                clause_scaffold,
                normalize_ids,
                render_schema_line,
                retrieve_semantic_slice,
            )
            from dynamic_rules import GLOBAL_RULES, select_rules_for_intent

        question = normalize_ids(state["question"])
        intent = classify_intent(question)
        rules, features = select_rules_for_intent(intent, question)
        scaffold = clause_scaffold(intent)

        semantic_slice = retrieve_semantic_slice(
            self.pipeline.embedder,
            question,
            self.pipeline.corpus_lines,
            self.pipeline.corpus_embeddings,
            intent,
            k=self.pipeline.top_k,
        )
        bilingual = [
            render_schema_line(line, self.pipeline.label_map, self.pipeline.rel_map)
            for line in semantic_slice
        ]

        few_shot_text = ""
        if self.pipeline.fewshot_store:
            examples = self.pipeline.fewshot_store.get_top_k(question, k=self.pipeline.fewshot_k)
            few_shot_text = self.pipeline.fewshot_store.format_examples(examples)

        self._trace(state, "retrieve_schema", {
            "intent": intent,
            "features": features.active_features() if hasattr(features, "active_features") else [],
            "slice_size": len(semantic_slice),
            "fewshot_count": few_shot_text.count("EXAMPLE NL:") if few_shot_text else 0,
        })

        return {
            "question": question,
            "intent": intent,
            "rules": rules,
            "scaffold": scaffold,
            "semantic_slice": semantic_slice,
            "bilingual_slice": bilingual,
            "few_shot_text": few_shot_text,
        }

    def _agent_generate_query(self, state: MultiAgentState) -> dict:
        """Agent 1 — Query Generator: assemble prompt and call LLM."""
        try:
            from core.t2css_enhanced import assemble_prompt
        except ImportError:
            from t2css_enhanced import assemble_prompt

        feedback = state.get("aggregated_feedback", "")
        iteration = state.get("iteration", 0)

        if iteration > 0 and feedback:
            question_augmented = (
                f"{state['question']}\n\n"
                f"CORRECTION FEEDBACK (from previous attempt):\n{feedback}\n\n"
                f"Previous Cypher (do NOT repeat it verbatim — fix the issues above):\n"
                f"{state.get('cypher', '')}"
            )
        else:
            question_augmented = state["question"]

        prompt = assemble_prompt(
            question=question_augmented,
            sem_bilingual=state.get("bilingual_slice", []),
            rules=state.get("rules", []),
            scaffold=state.get("scaffold", ""),
            fewshot_text=state.get("few_shot_text", ""),
        )

        raw = self.llm.invoke(prompt)
        cypher = extract_cypher(raw)

        self._trace(state, "generate_query", {
            "iteration": iteration,
            "cypher": cypher,
            "had_feedback": bool(feedback),
        })

        return {"prompt": prompt, "cypher": cypher}

    def _agent_execute_query(self, state: MultiAgentState) -> dict:
        """Agent 2 — Graph DB Executor: two-phase (EXPLAIN then RUN).

        Phase 1 – EXPLAIN: sends the query plan to Neo4j *without* executing.
                  This catches syntax errors, unknown labels/relationship types,
                  and invalid property references at near-zero cost.
        Phase 2 – RUN:     only reached when EXPLAIN succeeds. Executes the
                  query and returns result rows.

        Separating the phases lets the evaluator distinguish between
        *structural* errors (bad Cypher) and *semantic* issues (correct
        Cypher that returns empty/wrong results), which drives different
        correction paths in the self-correction loop.
        """
        cypher = state.get("cypher", "")
        if not cypher.strip():
            self._trace(state, "execute_query", {
                "phase": "skip", "error": "Empty Cypher query",
            })
            return {
                "execution_result": None,
                "execution_error": "Empty Cypher query",
            }

        # --- Phase 0: Write-clause guard ---
        WRITE_CLAUSES = {"CREATE", "MERGE", "DELETE", "DETACH DELETE", "SET",
                         "REMOVE", "FOREACH", "LOAD CSV", "CALL dbms"}
        upper_q = cypher.upper()
        write_hits = [wc for wc in WRITE_CLAUSES if wc in upper_q]
        if write_hits:
            err = f"Blocked write clause(s): {', '.join(write_hits)}"
            self._trace(state, "execute_query", {"phase": "write_guard", "error": err})
            return {"execution_result": None, "execution_error": err}

        # --- Phase 1: EXPLAIN (plan-only, no execution) ---
        try:
            with self.driver.session() as session:
                session.run(f"EXPLAIN {cypher}").consume()
        except Exception as e:
            explain_error = str(e)
            self._trace(state, "execute_query", {
                "phase": "EXPLAIN",
                "error": explain_error,
            })
            return {
                "execution_result": None,
                "execution_error": f"EXPLAIN failed: {explain_error}",
            }

        # --- Phase 2: RUN (EXPLAIN passed → safe to execute) ---
        try:
            with self.driver.session() as session:
                result = session.run(cypher)
                rows = [dict(record) for record in result]
            self._trace(state, "execute_query", {
                "phase": "RUN",
                "row_count": len(rows),
                "error": None,
            })
            return {"execution_result": rows, "execution_error": None}
        except Exception as e:
            self._trace(state, "execute_query", {
                "phase": "RUN",
                "row_count": 0,
                "error": str(e),
            })
            return {"execution_result": None, "execution_error": str(e)}

    def _agent_evaluate_query(self, state: MultiAgentState) -> dict:
        """Agent 3 — Query Evaluator: LLM-based critic."""
        exec_result = state.get("execution_result")
        exec_error = state.get("execution_error")

        if exec_error:
            outcome = f"ERROR: {exec_error}"
        elif exec_result is None or len(exec_result) == 0:
            outcome = "EMPTY: query returned no results."
        else:
            # Truncate for prompt size
            preview = json.dumps(exec_result[:10], default=str, indent=2)
            outcome = f"RESULTS ({len(exec_result)} rows, first 10 shown):\n{preview}"

        user_msg = EVALUATOR_USER.format(
            question=state["question"],
            cypher=state.get("cypher", ""),
            outcome=outcome,
        )

        raw = _llm_call(self.llm, EVALUATOR_SYSTEM, user_msg, max_tokens=400)
        parsed = _parse_json_response(raw)

        grade = parsed.get("grade", "ERROR_OR_EMPTY").upper().replace(" ", "_")
        if grade not in {"ACCEPT", "INCORRECT", "ERROR_OR_EMPTY"}:
            # Heuristic fallback
            if exec_error or (exec_result is not None and len(exec_result) == 0):
                grade = "ERROR_OR_EMPTY"
            elif exec_result and len(exec_result) > 0:
                grade = "ACCEPT"
            else:
                grade = "ERROR_OR_EMPTY"

        feedback = parsed.get("feedback", raw)

        self._trace(state, "evaluate_query", {"grade": grade, "feedback": feedback})

        return {"eval_grade": grade.lower(), "eval_feedback": feedback}

    def _agent_extract_entities(self, state: MultiAgentState) -> dict:
        """Agent 4 — Named Entity Extractor."""
        user_msg = ENTITY_EXTRACTOR_USER.format(cypher=state.get("cypher", ""))
        raw = _llm_call(self.llm, ENTITY_EXTRACTOR_SYSTEM, user_msg, max_tokens=500)
        entities = _parse_json_response(raw)

        if not entities:
            # Regex fallback
            cypher = state.get("cypher", "")
            labels = list(set(re.findall(r"\(\w*:([A-Za-z0-9_]+)\)", cypher)))
            rel_types = list(set(re.findall(r"\[:([A-Z_]+)\]", cypher)))
            entities = {
                "node_labels": labels,
                "node_property_values": [],
                "pairwise_relationships": [f"()-[:{rt}]->()" for rt in rel_types],
            }

        self._trace(state, "extract_entities", entities)
        return {"extracted_entities": entities}

    def _agent_verify_entities(self, state: MultiAgentState) -> dict:
        """Agent 5 — Verification Module: check entities against the live graph."""
        entities = state.get("extracted_entities", {})
        results: Dict[str, Any] = {
            "label_checks": [],
            "property_checks": [],
            "relationship_checks": [],
            "has_issues": False,
        }

        with self.driver.session() as session:
            for label in entities.get("node_labels", []):
                check = verify_node_label(session, label)
                results["label_checks"].append(check)
                if not check["exists"]:
                    results["has_issues"] = True

            for pv in entities.get("node_property_values", []):
                label = pv.get("label", "")
                prop = pv.get("property", "")
                value = pv.get("value", "")
                if label and prop and value:
                    check = verify_property_value(session, label, prop, value)
                    results["property_checks"].append(check)
                    if not check["exists"]:
                        results["has_issues"] = True

            for pattern in entities.get("pairwise_relationships", []):
                check = verify_relationship_pattern(session, pattern)
                results["relationship_checks"].append(check)
                if not check["exists"]:
                    results["has_issues"] = True

        self._trace(state, "verify_entities", {"has_issues": results["has_issues"]})
        return {"verification_results": results}

    def _agent_generate_instructions(self, state: MultiAgentState) -> dict:
        """Agent 6 — Instructions Generator."""
        verification = state.get("verification_results", {})

        if not verification.get("has_issues", False):
            self._trace(state, "generate_instructions", {"instructions": "No corrections needed."})
            return {"correction_instructions": "No entity corrections needed."}

        verification_json = json.dumps(verification, default=str, indent=2)
        user_msg = INSTRUCTIONS_USER.format(verification_json=verification_json)
        instructions = _llm_call(self.llm, INSTRUCTIONS_SYSTEM, user_msg, max_tokens=400)

        self._trace(state, "generate_instructions", {"instructions": instructions[:200]})
        return {"correction_instructions": instructions}

    def _agent_aggregate_feedback(self, state: MultiAgentState) -> dict:
        """Agent 7 — Feedback Aggregator."""
        eval_feedback = state.get("eval_feedback", "")
        correction_instructions = state.get("correction_instructions", "")

        if not correction_instructions or correction_instructions == "No entity corrections needed.":
            # Only evaluator feedback (Incorrect path)
            aggregated = eval_feedback
        else:
            user_msg = AGGREGATOR_USER.format(
                question=state["question"],
                eval_feedback=eval_feedback,
                verification_instructions=correction_instructions,
            )
            aggregated = _llm_call(self.llm, AGGREGATOR_SYSTEM, user_msg, max_tokens=500)

        self._trace(state, "aggregate_feedback", {"aggregated": aggregated[:200]})
        return {"aggregated_feedback": aggregated}

    def _agent_interpret(self, state: MultiAgentState) -> dict:
        """Agent 8 — Interpreter: produce natural-language answer."""
        results = state.get("execution_result", [])
        preview = json.dumps(results[:20], default=str, indent=2) if results else "No results."

        user_msg = INTERPRETER_USER.format(
            question=state["question"],
            results=preview,
        )
        answer = _llm_call(self.llm, INTERPRETER_SYSTEM, user_msg, max_tokens=500)

        self._trace(state, "interpret", {"answer": answer[:200]})
        return {
            "answer": answer,
            "status": "success",
            "message": f"Accepted after {state.get('iteration', 0) + 1} iteration(s).",
        }

    # ------------------------------------------------------------------
    # LangGraph wiring
    # ------------------------------------------------------------------

    def _build_graph(self):
        try:
            from langgraph.graph import END, StateGraph
        except ImportError:
            logger.warning(
                "langgraph not installed — MultiAgentText2Cypher.invoke() will use "
                "a plain-Python fallback loop instead of a compiled graph."
            )
            return None

        g = StateGraph(MultiAgentState)

        # --- Nodes ---
        g.add_node("retrieve_schema", self._agent_retrieve_schema)
        g.add_node("generate_query", self._agent_generate_query)
        g.add_node("execute_query", self._agent_execute_query)
        g.add_node("evaluate_query", self._agent_evaluate_query)
        g.add_node("extract_entities", self._agent_extract_entities)
        g.add_node("verify_entities", self._agent_verify_entities)
        g.add_node("generate_instructions", self._agent_generate_instructions)
        g.add_node("aggregate_feedback", self._agent_aggregate_feedback)
        g.add_node("inc_iteration", lambda s: {"iteration": s.get("iteration", 0) + 1})
        g.add_node("interpret", self._agent_interpret)
        g.add_node("finalize_max_iter", lambda s: {
            "status": "max_iterations",
            "message": f"Could not produce an accepted query after {s.get('max_iterations', 4)} iterations.",
            "answer": f"I was unable to fully answer your question after {s.get('max_iterations', 4)} attempts. "
                       f"The best query I generated was: {s.get('cypher', 'N/A')}",
        })

        # --- Entry ---
        g.set_entry_point("retrieve_schema")
        g.add_edge("retrieve_schema", "generate_query")
        g.add_edge("generate_query", "execute_query")
        g.add_edge("execute_query", "evaluate_query")

        # --- After evaluation: route by grade ---
        def route_after_eval(state: MultiAgentState) -> str:
            grade = state.get("eval_grade", "error_or_empty")
            if grade == "accept":
                return "interpret"
            iteration = state.get("iteration", 0)
            max_iter = state.get("max_iterations", 4)
            if iteration + 1 >= max_iter:
                return "finalize_max_iter"
            if grade == "incorrect":
                return "aggregate_feedback_direct"
            # error_or_empty → full verification path
            return "extract_entities"

        g.add_conditional_edges(
            "evaluate_query",
            route_after_eval,
            {
                "interpret": "interpret",
                "finalize_max_iter": "finalize_max_iter",
                "aggregate_feedback_direct": "aggregate_feedback",
                "extract_entities": "extract_entities",
            },
        )

        # Verification path
        g.add_edge("extract_entities", "verify_entities")
        g.add_edge("verify_entities", "generate_instructions")
        g.add_edge("generate_instructions", "aggregate_feedback")

        # After aggregation → increment and regenerate
        g.add_edge("aggregate_feedback", "inc_iteration")
        g.add_edge("inc_iteration", "generate_query")

        # Terminal nodes
        g.add_edge("interpret", END)
        g.add_edge("finalize_max_iter", END)

        return g.compile()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def invoke(self, question: str) -> Dict[str, Any]:
        """
        Run the full multi-agent pipeline for a question.

        Returns dict with keys:
            cypher, answer, status, message, execution_result, trace, iterations
        """
        initial_state: MultiAgentState = {
            "question": question,
            "iteration": 0,
            "max_iterations": self.max_iterations,
            "trace": [],
        }

        if self.graph is not None:
            final = self.graph.invoke(initial_state)
        else:
            final = self._fallback_loop(initial_state)

        return {
            "cypher": final.get("cypher"),
            "answer": final.get("answer", ""),
            "execution_result": final.get("execution_result", []),
            "status": final.get("status", "error"),
            "message": final.get("message", ""),
            "iterations": final.get("iteration", 0) + 1,
            "eval_grade": final.get("eval_grade", ""),
            "trace": final.get("trace", []),
        }

    # ------------------------------------------------------------------
    # Fallback loop (when LangGraph is not installed)
    # ------------------------------------------------------------------

    def _fallback_loop(self, state: MultiAgentState) -> MultiAgentState:
        """Plain-Python execution of Algorithm 1 (no LangGraph dependency)."""
        # Step 0: retrieve schema context
        state.update(self._agent_retrieve_schema(state))

        for iteration in range(state.get("max_iterations", 4)):
            state["iteration"] = iteration

            # Step 1: generate query
            state.update(self._agent_generate_query(state))

            # Step 2: execute query
            state.update(self._agent_execute_query(state))

            # Step 3: evaluate query
            state.update(self._agent_evaluate_query(state))

            grade = state.get("eval_grade", "error_or_empty")

            if grade == "accept":
                state.update(self._agent_interpret(state))
                return state

            if grade == "incorrect":
                # Direct feedback from evaluator
                state["correction_instructions"] = ""
                state.update(self._agent_aggregate_feedback(state))
            else:
                # Error/empty → full verification path
                state.update(self._agent_extract_entities(state))
                state.update(self._agent_verify_entities(state))
                state.update(self._agent_generate_instructions(state))
                state.update(self._agent_aggregate_feedback(state))

        # Exhausted iterations
        state["status"] = "max_iterations"
        state["message"] = f"Could not produce an accepted query after {state.get('max_iterations', 4)} iterations."
        state["answer"] = (
            f"I was unable to fully answer your question after {state.get('max_iterations', 4)} attempts. "
            f"The best query I generated was: {state.get('cypher', 'N/A')}"
        )
        return state

    # ------------------------------------------------------------------
    # Trace helper
    # ------------------------------------------------------------------

    def _trace(self, state: MultiAgentState, agent_name: str, data: Dict[str, Any]):
        entry = {"agent": agent_name, "timestamp": time.time(), **data}
        trace = state.get("trace")
        if trace is None:
            state["trace"] = [entry]
        else:
            trace.append(entry)
        if self.verbose:
            compact = {k: (v[:120] + "..." if isinstance(v, str) and len(v) > 120 else v)
                       for k, v in data.items()}
            print(f"  [{agent_name}] {compact}")


# ---------------------------------------------------------------------------
# Factory + convenience
# ---------------------------------------------------------------------------

def create_multi_agent_t2c(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    llm,
    semantic_schema_path: str = None,
    max_iterations: int = 4,
    top_k: int = 12,
    fewshot_k: int = 3,
    verbose: bool = True,
) -> MultiAgentText2Cypher:
    """
    Factory function to create a fully wired MultiAgentText2Cypher instance.

    Parameters match the existing ``create_enhanced_text2cypher`` API style.
    """
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    try:
        from core.t2css_enhanced import EnhancedT2CSSPipeline
    except ImportError:
        from t2css_enhanced import EnhancedT2CSSPipeline

    pipeline = EnhancedT2CSSPipeline(
        semantic_schema_path=semantic_schema_path,
        top_k=top_k,
        fewshot_k=fewshot_k,
        auto_load_fewshot=True,
    )

    return MultiAgentText2Cypher(
        neo4j_driver=driver,
        llm=llm,
        enhanced_pipeline=pipeline,
        max_iterations=max_iterations,
        verbose=verbose,
    )


# ---------------------------------------------------------------------------
# Quick CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    from llm.ollama_llm import OllamaLLM

    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")

    llm = OllamaLLM()
    agent = create_multi_agent_t2c(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, llm, verbose=True)

    questions = [
        "Find all CVEs with critical severity",
        "How many campaigns use the T1059 technique?",
        "Which groups are associated with Cobalt Strike software?",
    ]

    for q in questions:
        print(f"\n{'='*80}")
        print(f"QUESTION: {q}")
        print("=" * 80)
        result = agent.invoke(q)
        print(f"\n  Status:     {result['status']}")
        print(f"  Iterations: {result['iterations']}")
        print(f"  Cypher:     {result['cypher']}")
        print(f"  Answer:     {result['answer'][:200]}")
        print(f"  Rows:       {len(result.get('execution_result') or [])}")
