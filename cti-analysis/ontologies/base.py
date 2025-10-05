# ontologies/base.py
from dataclasses import dataclass, field
from typing import Dict, Iterable, Set, Tuple

TripleCombo = Tuple[str, str, str]  # (subject.type, predicate, object.type)

@dataclass(frozen=True)
class OntologyConfig:
    SUBJECT_TYPES: Set[str]
    PREDICATES: Set[str]
    OBJECT_TYPES: Set[str]
    LITERAL_TYPES: Set[str] = field(default_factory=set)

    # Simple type hierarchy: child -> parent
    PARENT_OF: Dict[str, str] = field(default_factory=dict)

    # Buckets
    ATTRIBUTE_PREDICATES: Set[str] = field(default_factory=set)
    RELATION_PREDICATES: Set[str] = field(default_factory=set)

    # Compatibility matrices
    ALLOWED_RELATION_COMBOS: Set[TripleCombo] = field(default_factory=set)
    ALLOWED_ATTRIBUTE_COMBOS: Set[TripleCombo] = field(default_factory=set)


# ---------------- Helpers ----------------

def supertype_chain(t: str, parent_of: Dict[str, str]) -> Iterable[str]:
    """
    Yield t, then its parents up the simple hierarchy.
    """
    cur = t
    seen = set()
    while cur and cur not in seen:
        yield cur
        seen.add(cur)
        cur = parent_of.get(cur)


def matches(pattern: str, t: str, parent_of: Dict[str, str]) -> bool:
    """
    Wildcard match for 'ns:*' against 'ns:Type' and exact matches otherwise.
    Also treat parent matches as OK (e.g., 'identity:Identity' matches 'identity:Person').
    """
    if not pattern or not t:
        return False
    if pattern.endswith(":*"):
        ns = pattern.split(":")[0]
        return t.startswith(ns + ":")
    return any(p == pattern for p in supertype_chain(t, parent_of))


def is_combo_allowed(cfg: OntologyConfig, subj_type: str, predicate: str, obj_type: str) -> bool:
    """
    Fast vocab checks + matrix match (wildcards + hierarchy-aware).
    """
    # Vocab checks (allow literals for object)
    if subj_type not in cfg.SUBJECT_TYPES and subj_type not in cfg.LITERAL_TYPES:
        return False
    if predicate not in cfg.PREDICATES:
        return False
    if obj_type not in cfg.OBJECT_TYPES and obj_type not in cfg.LITERAL_TYPES:
        return False

    combos = cfg.ALLOWED_ATTRIBUTE_COMBOS if predicate in cfg.ATTRIBUTE_PREDICATES else cfg.ALLOWED_RELATION_COMBOS

    for s_pat, p_pat, o_pat in combos:
        if p_pat != predicate:
            continue
        s_ok = (s_pat == "*") or matches(s_pat, subj_type, cfg.PARENT_OF)
        o_ok = (o_pat == "*") or matches(o_pat, obj_type, cfg.PARENT_OF)
        if s_ok and o_ok:
            return True
    return False


def validate_triple_semantics(cfg: OntologyConfig, triple: dict) -> bool:
    """
    Drop-in semantic validator for a triple:
      - Vocab allow-lists
      - Attribute vs Relation rules
      - Compatibility matrices (wildcards + hierarchy)

    Expects triple with keys:
      subject: {name, type}, predicate, object: {name, type}
    """
    s = triple.get("subject") or {}
    o = triple.get("object") or {}
    p = (triple.get("predicate") or "").strip()

    s_type = (s.get("type") or "").strip()
    o_type = (o.get("type") or "").strip()

    # Vocab checks
    if p not in cfg.PREDICATES:
        return False
    if s_type not in cfg.SUBJECT_TYPES:
        return False
    if o_type not in cfg.OBJECT_TYPES and o_type not in cfg.LITERAL_TYPES:
        return False

    # Attribute vs relation constraints
    if p in cfg.ATTRIBUTE_PREDICATES:
        if o_type not in cfg.LITERAL_TYPES:
            return False
    else:
        if o_type in cfg.LITERAL_TYPES and p not in cfg.ATTRIBUTE_PREDICATES:
            return False

    # Compatibility matrix
    return is_combo_allowed(cfg, s_type, p, o_type)
