# malont_adapter.py
# One-stop adapter: take a raw MALONT-like triple from the LLM,
# normalize types/predicates (regex + aliases), apply safe repairs,
# and map to your connection.py ontology for validation/graph.

from __future__ import annotations
import re
from typing import Dict, Any, Tuple, Optional
from .connection import get_config as get_connection_config, OntologyConfig

# -------------------------
# 1) Normalization helpers
# -------------------------

# Common free-text → MALONT surface predicates (keep MALONT wording)
_PRED_CANON: Dict[str, str] = {
    r"\buses?\b": "uses",
    r"\btargets?\b": "targets",
    r"\bexploit(?:s|ed|ing)?\b": "exploits",
    r"\bcommunicates? with\b": "communicatesWith",
    r"\bbelongs to\b": "belongsTo",
    r"\bhas alias(?:es)?\b": "hasAlias",
    r"\bhas\b": "has",

    # incident/investigation language
    r"\bwas contacted to look into\b": "investigates",
    r"\binvestigat(?:e|ed|ing|ion)\b": "investigates",
    r"\bfocused (?:initially )?on\b": "focusesOn",
    r"\bexhibited\b": "exhibits",
    r"\bcoincides? with\b": "coincidesWith",
}

# Lightweight type canonicalization:
#  - fixes casing/spacing/hyphen/underscore variants
#  - collapses long MALONT names to the canonical surface label
_TYPE_ALIASES: Dict[str, str] = {
    # identities
    "threatactor": "ThreatActor",
    "threat actor": "ThreatActor",
    "organisation": "Organization",

    # actions
    "attackpattern": "AttackPattern",
    "attack-pattern": "AttackPattern",
    "attackpattern_largedescription": "AttackPattern",
    "attackpattern_smalldescription": "AttackPattern",

    # observables
    "ipaddress": "IPAddress",
    "ip address": "IPAddress",
    "domain name": "DomainName",
    "email address": "EmailAddress",
    "file name": "Filename",
    "file path": "Filepath",
}

def _normalize_spaces_case(s: str) -> str:
    # normalize case and remove obvious separators to match _TYPE_ALIASES keys
    s2 = s.strip()
    s2 = re.sub(r"[_\-]+", " ", s2)
    return s2

def canonicalize_type(raw: Any) -> Optional[str]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = _normalize_spaces_case(raw).lower()
    if s in _TYPE_ALIASES:
        return _TYPE_ALIASES[s]
    # Title-case tokens like "attack pattern" → "Attack Pattern" then collapse known MALONT forms
    title = " ".join(tok.capitalize() for tok in s.split())
    # collapse known multi-word MALONT surface labels back to canonical token
    join = title.replace(" ", "")
    # prefer explicit alias mapping if we had it
    if join in {"ThreatActor","Organization","Person","Campaign","AttackPattern","URL","DomainName","IPAddress",
                "EmailAddress","Filepath","Filename","Hash","MD5","SHA-1","SHA-256","Software","Tool","Malware",
                "Infrastructure","Network","System","Vulnerability","Location","Country","Region","DateTime",
                "String","Number"}:
        return join
    return raw.strip()

def canonicalize_predicate(raw: Any) -> Optional[str]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().lower()
    for pat, canon in _PRED_CANON.items():
        if re.search(pat, s):
            return canon
    return raw.strip()  # leave as-is if unknown; mapper may still handle it

# ------------------------------------------------
# 2) MALONT → connection ontology mapping tables
# ------------------------------------------------

_TYPE_MAP: Dict[str, str] = {
    # Identities
    "ThreatActor": "identity:Identity",        # refine later to Person vs Organization if you wish
    "Organization": "identity:Organization",
    "Person": "identity:Person",

    # Actions (higher-level activities)
    "Campaign": "action:Action",
    "AttackPattern": "action:Action",

    # Observables
    "URL": "observable:URL",
    "DomainName": "observable:DomainName",
    "IPAddress": "observable:IPAddress",
    "EmailAddress": "observable:EmailAddress",
    "Filename": "observable:File",
    "Filepath": "observable:File",
    "Hash": "observable:File",
    "MD5": "observable:File",
    "SHA-1": "observable:File",
    "SHA-256": "observable:File",
    "Software": "observable:Tool",
    "Tool": "observable:Tool",
    "Malware": "observable:Tool",
    "Infrastructure": "observable:ObservableObject",
    "Network": "observable:ObservableObject",
    "System": "observable:ObservableObject",
    "Vulnerability": "observable:Vulnerability",

    # Locations
    "Location": "location:Location",
    "Country": "location:Location",
    "Region": "location:Location",

    # Literals
    "DateTime": "core:DateTime",
    "String": "core:Literal",
    "Number": "core:Number",
}

_PRED_MAP: Dict[str, str] = {
    # canonical MALONT verbs
    "uses": "action:instrument",
    "targets": "action:object",
    "exploits": "action:object",
    "communicatesWith": "action:instrument",    # you can add a dedicated net:communicatesWith later
    "belongsTo": "core:createdBy",
    "hasAlias": "core:externalReference",
    "has": "core:hasFacet",

    # normalized free-text
    "investigates": "action:participant",       # Org investigates Action/Incident
    "focusesOn": "action:objective",
    "exhibits": "action:result",
    "coincidesWith": "core:hasFacet",           # often better as Action.startTime
}

# --------------------------------------
# 3) Adapter public API (one-call usage)
# --------------------------------------

def get_connection_ontology() -> OntologyConfig:
    return get_connection_config()

def normalize_and_map_malont(triple: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Input: raw MALONT-ish triple from LLM:
      {"subject":{"name":..., "type":...}, "predicate":..., "object":{...}, "evidence":{...}}
    Returns:
      (clean_malont, mapped_connection)
    """
    # --- normalize MALONT surface ---
    subj = dict(triple.get("subject") or {})
    obj  = dict(triple.get("object") or {})
    pred = triple.get("predicate")

    subj["type"] = canonicalize_type(subj.get("type", ""))
    obj["type"]  = canonicalize_type(obj.get("type", ""))
    pred_clean   = canonicalize_predicate(pred)

    clean_malont = dict(triple)
    clean_malont["subject"] = subj
    clean_malont["object"]  = obj
    clean_malont["predicate"] = pred_clean

    # --- map to connection ontology ---
    s_out = {"name": subj.get("name"), "type": _TYPE_MAP.get(subj.get("type",""), subj.get("type",""))}
    o_out = {"name": obj.get("name"),  "type": _TYPE_MAP.get(obj.get("type",""),  obj.get("type",""))}
    p_out = _PRED_MAP.get(pred_clean or "", pred_clean or "")

    # --- safe structural repairs ---
    # 1) DateTime as subject & Action as object → flip to Action --action:startTime--> DateTime
    if s_out.get("type") == "core:DateTime" and o_out.get("type") == "action:Action":
        s_out, o_out = o_out, s_out
        p_out = "action:startTime"

    # 2) “security incident” often better as Action
    if isinstance(o_out.get("name"), str) and o_out["name"].lower().strip() in {"security incident","incident"}:
        o_out["type"] = "action:Action"

    mapped = {"subject": s_out, "predicate": p_out, "object": o_out}
    return clean_malont, mapped

# --------------------------------------
# 4) Optional: extend at runtime
# --------------------------------------

def add_type_alias(raw_variant: str, canonical_malont: str) -> None:
    """Let you add a new normalization alias without editing code elsewhere."""
    key = _normalize_spaces_case(raw_variant).lower()
    _TYPE_ALIASES[key] = canonical_malont

def add_predicate_rule(pattern: str, malont_predicate: str) -> None:
    """Add a regex → MALONT predicate rule."""
    _PRED_CANON[pattern] = malont_predicate
