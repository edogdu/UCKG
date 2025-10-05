# validator.py
# Ontology-aware validator for mapped triples.
# Works with the connection.py ontology and the `mapped` view
# produced by normalize_and_map_malont(...).

from __future__ import annotations
from typing import Dict, Any, Tuple, List
from collections import Counter
from .base import OntologyConfig, is_combo_allowed

# -----------------------------------------------------------------------------
# Light predicate normalization
#  - fixes case/spacing/underscores
#  - adds namespaces if missing (when an exact match exists)
#  - keeps this light; semantic mapping belongs in malont_adapter
# -----------------------------------------------------------------------------

_NAMESPACES: Tuple[str, ...] = ("action", "core", "identity", "observable", "tool", "location")

def _normalize_predicate(p: str, onto: OntologyConfig) -> str:
    if not isinstance(p, str):
        return ""
    raw = p
    p = p.strip().lower()

    # collapse spaces around colon; unify underscores; normalize long dashes
    p = p.replace(" : ", ":").replace(" :", ":").replace(": ", ":")
    p = p.replace(" ", "_").replace("__", "_").replace("–", "-").replace("—", "-")

    # if missing namespace, try adding a known one that exists in ontology
    if ":" not in p:
        for ns in _NAMESPACES:
            cand = f"{ns}:{p}"
            if cand in onto.PREDICATES:
                return cand

    # if namespaced but local uses hyphens, try underscore form
    if ":" in p:
        ns, local = p.split(":", 1)
        cand = f"{ns}:{local.replace('-', '_')}"
        if cand in onto.PREDICATES:
            return cand

    return raw

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def validate_mapped_triple(
    mapped: Dict[str, Any],
    onto: OntologyConfig,
    lenient_accept: bool = True,
) -> str:
    """
    Validate a single mapped triple against an ontology.

    Returns:
      "strict"                     -> fully valid per ontology
      "lenient:<reason>"           -> acceptable but outside strict rules
      "reject"                     -> malformed or clearly invalid
    """
    if not isinstance(mapped, dict):
        return "reject"

    s = mapped.get("subject")
    o = mapped.get("object")
    p_in = mapped.get("predicate")

    if not (isinstance(s, dict) and isinstance(o, dict) and isinstance(p_in, str)):
        return "reject"

    st = s.get("type")
    ot = o.get("type")
    p = _normalize_predicate(p_in, onto)

    if not (isinstance(st, str) and isinstance(ot, str) and isinstance(p, str) and st and ot and p):
        return "reject"

    # Predicate must exist in ontology
    if p not in onto.PREDICATES:
        return "lenient:unknown-predicate" if lenient_accept else "reject"

    # Relation predicates (subject_type, predicate, object_type)
    if p in onto.RELATION_PREDICATES:
        if is_combo_allowed(onto, st, p, ot):
            return "strict"
        return "lenient:relation-not-in-allowed" if lenient_accept else "reject"

    # Attribute predicates (subject_type, predicate, literal_type)
    if p in onto.ATTRIBUTE_PREDICATES:
        if is_combo_allowed(onto, st, p, ot):
            return "strict"
        return "lenient:attribute-not-in-allowed" if lenient_accept else "reject"

    # Should not occur if ontology is consistent
    return "lenient:unknown-predicate-class" if lenient_accept else "reject"


def validate_triple_record(
    triple_record: Dict[str, Any],
    onto: OntologyConfig,
    lenient_accept: bool = True,
    target_field: str = "mapped",
) -> str:
    """
    Validate a full triple record (the one you keep in JSON)
    by looking up triple_record[target_field] and calling validate_mapped_triple.

    triple_record example:
      {
        "subject": {... MALONT ...},
        "predicate": "uses",
        "object": {... MALONT ...},
        "evidence": {...},
        "mapped": { "subject": {... connection ...}, "predicate": "...", "object": {...} }
      }
    """
    target = triple_record.get(target_field, {})
    outcome = validate_mapped_triple(target, onto, lenient_accept=lenient_accept)
    triple_record["_validity"] = outcome  # convenience
    return outcome


def tally_validity(outcomes: List[str]) -> Dict[str, int]:
    """
    Aggregate counts of strict/lenient/reject for quick metrics.
    """
    counts = {"strict": 0, "lenient": 0, "reject": 0}
    for v in outcomes:
        if v == "strict":
            counts["strict"] += 1
        elif isinstance(v, str) and v.startswith("lenient:"):
            counts["lenient"] += 1
        else:
            counts["reject"] += 1
    return counts


# -----------------------------------------------------------------------------
# Optional: quick debug helper to find top unknown predicates after normalization
# -----------------------------------------------------------------------------

def top_unknown_predicates(records: List[Dict[str, Any]], onto: OntologyConfig, target_field: str = "mapped", k: int = 20):
    """
    Returns a list of (predicate, count) pairs for predicates that are still
    not in onto.PREDICATES after normalization. Useful for expanding adapters.
    """
    ctr = Counter()
    for rec in records:
        mapped = rec.get(target_field) or {}
        p = _normalize_predicate((mapped.get("predicate") or ""), onto)
        if p and p not in onto.PREDICATES:
            ctr[p] += 1
    return ctr.most_common(k)
