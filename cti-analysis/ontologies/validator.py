# validator.py
# Ontology-aware validator for mapped triples.
# Works with the connection.py ontology and the `mapped` view
# produced by normalize_and_map_malont(...).

from __future__ import annotations
from typing import Dict, Any
from .base import OntologyConfig, is_combo_allowed




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
    p = mapped.get("predicate")

    if not (isinstance(s, dict) and isinstance(o, dict) and isinstance(p, str)):
        return "reject"

    st = s.get("type")
    ot = o.get("type")
    p = p.strip() if isinstance(p, str) else None

    if not (isinstance(st, str) and isinstance(ot, str) and isinstance(p, str) and p):
        return "reject"

    # Predicate must exist in ontology
    if p not in onto.PREDICATES:
        return "lenient:unknown-predicate" if lenient_accept else "reject"

    # Attribute predicates (subject, predicate, literal-type)
    if p in onto.ATTRIBUTE_PREDICATES:
       if is_combo_allowed(onto, st, p, ot):
           return "strict"
       return "lenient:relation-not-in-allowed" if lenient_accept else "reject"


    # Should not reach here if ontology is consistent, but guard it
    return "lenient:unknown-predicate-class" if lenient_accept else "reject"


def validate_triple_record(
    triple_record: Dict[str, Any],
    onto: OntologyConfig,
    lenient_accept: bool = True,
    target_field: str = "mapped",
) -> str:
    """
    Validate a full triple record (the one you keep in JSON),
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
    # also write the outcome back for convenience
    triple_record["_validity"] = outcome
    return outcome


def tally_validity(outcomes: list[str]) -> Dict[str, int]:
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
