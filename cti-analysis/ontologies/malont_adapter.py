from __future__ import annotations
from typing import Dict, Any, Optional, Tuple
import re

# -----------------------------------------------------------------------------
# 0) Basic string normalizers
# -----------------------------------------------------------------------------

def _norm_spaces_case(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())

def _norm_key(s: str) -> str:
    # unify for dictionary keys: remove spaces/underscores/hyphens and lower
    return (
        s.strip().lower()
         .replace(" ", "")
         .replace("_", "")
         .replace("-", "")
    )

# -----------------------------------------------------------------------------
# 1) Canonicalization (LLM → canonical MALONT surface)
#    Use these on the raw LLM outputs *before* mapping to the connection ontology.
# -----------------------------------------------------------------------------

# Soft alias table for types at the MALONT layer
_TYPE_ALIASES: Dict[str, str] = {
    "threatactor": "ThreatActor",
    "actor": "ThreatActor",
    "org": "Organization",
    "organisation": "Organization",
    "company": "Organization",
    "person": "Person",
    "human": "Person",
    "campaign": "Campaign",
    "attackpattern": "AttackPattern",
    "tactic": "AttackPattern",
    "technique": "AttackPattern",
    "url": "URL",
    "domain": "DomainName",
    "domainname": "DomainName",
    "ip": "IPAddress",
    "ipaddress": "IPAddress",
    "email": "EmailAddress",
    "emailaddress": "EmailAddress",
    "filepath": "Filepath",
    "filename": "Filename",
    "hash": "Hash",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "tool": "Tool",
    "malware": "Malware",
    "software": "Software",
    "infrastructure": "Infrastructure",
    "network": "Network",
    "system": "System",
    "vulnerability": "Vulnerability",
    "location": "Location",
    "country": "Country",
    "region": "Region",
    "datetime": "DateTime",
    "string": "String",
    "number": "Number",
}

# Regex-to-canonical MALONT predicate patterns (very permissive)
_PRED_CANON: Dict[str, str] = {
    r"^use[s]?$|leverag|drop|deliver|deploy|install|run|launch|execut": "usesTool",
    r"target|against|aim|victim": "targetsAsset",
    r"exploit": "exploits",
    r"communicat|connect": "communicatesWith",
    r"belong|affiliat|operate[s]? by|run[s]? by": "belongsTo",
    r"alias|aka|also known as|handle": "hasAlias",
    r"focus|objective|goal|intent|purpose|to\s+\w+": "focusesOn",
    r"result|lead[s]? to|cause[s]?": "exhibits",
    r"coincid|correlat|relat": "coincidesWith",
    r"name|label|title": "has",  # often maps to core:name later
    r"ref|reference|link": "has", # later → core:externalReference
    r"time|date": "atTime",
    r"locat|in\s+\w+": "inLocation",
    r"investigat|analyz|research|track": "investigates",
    r"perform|conduct|execute": "usesTool",  # often operationalized as instrument
}

def canonicalize_type(raw: Any) -> Optional[str]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = _norm_spaces_case(raw).lower()
    if s in _TYPE_ALIASES:
        return _TYPE_ALIASES[s]

    title = " ".join(tok.capitalize() for tok in s.split())  # "attack pattern" → "Attack Pattern"
    join = title.replace(" ", "")
    # prefer explicit MALONT tokens if we recognize them
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
    return raw.strip()  # leave as-is; mapper may still handle it

# -----------------------------------------------------------------------------
# 2) Mapping: canonical MALONT → connection ontology
#    Fill these with your actual ontology terms.
# -----------------------------------------------------------------------------

# Types: MALONT → connection
TYPE_MAP: Dict[str, str] = {
    # identities
    "ThreatActor": "identity:Organization",
    "Organization": "identity:Organization",
    "Person": "identity:Person",

    # actions/attack concepts
    "Campaign": "action:Action",
    "AttackPattern": "tool:Tool",   # or a dedicated class if you have one
    "Software": "tool:Tool",
    "Tool": "tool:Tool",
    "Malware": "tool:Tool",

    # observables
    "URL": "observable:URL",
    "DomainName": "observable:DomainName",
    "IPAddress": "observable:IPAddress",
    "EmailAddress": "observable:EmailAddress",
    "Filepath": "observable:File",
    "Filename": "observable:File",
    "Hash": "observable:File",
    "MD5": "observable:File",
    "SHA-1": "observable:File",
    "SHA-256": "observable:File",

    # infra/locations
    "Infrastructure": "location:Location",
    "Network": "location:Location",
    "System": "location:Location",
    "Location": "location:Location",
    "Country": "location:Location",
    "Region": "location:Location",

    # literals
    "DateTime": "core:DateTime",
    "String": "core:String",
    "Number": "core:Number",

    "Application": "tool:Tool",                   # scripts/utilities are software
    "Command": "action:Action",                   # “Delete command … deletes …” is an action
    "AttackPattern_SmallDescription": "tool:Tool",# you can refine later if you add a dedicated class
    "MalwareAnalysis": "core:Literal",            # treat analysis labels/snippets as literal text
    "Filename": "observable:File",  
}

def map_malont_type(malont_type: Optional[str]) -> Optional[str]:
    if not malont_type:
        return None
    return TYPE_MAP.get(malont_type, malont_type)

# Predicates: MALONT → connection (semantic)
def _pm(key: str) -> str:
    return _norm_key(key)

PRED_MAP: Dict[str, str] = {
    # canonical MALONT-style keys (normalized with _norm_key)
    _pm("usesTool"): "action:instrument",
    _pm("targetsAsset"): "action:object",
    _pm("exploits"): "action:object",
    _pm("communicatesWith"): "action:instrument",
    _pm("belongsTo"): "core:createdBy",
    _pm("hasAlias"): "core:externalReference",
    _pm("has"): "core:hasFacet",
    _pm("investigates"): "action:participant",
    _pm("focusesOn"): "action:objective",
    _pm("exhibits"): "action:result",
    _pm("coincidesWith"): "core:hasFacet",
    _pm("atTime"): "action:startTime",
    _pm("inLocation"): "action:location",

    # common CTI verbs seen in the wild (fall through to the same mapping)
    _pm("uses"): "action:instrument",
    _pm("leverages"): "action:instrument",
    _pm("delivers"): "action:instrument",
    _pm("drops"): "action:instrument",
    _pm("downloads"): "action:instrument",
    _pm("installs"): "action:instrument",
    _pm("runs"): "action:instrument",
    _pm("launches"): "action:instrument",
    _pm("deploys"): "action:instrument",
    _pm("connects"): "action:instrument",
    _pm("connectsTo"): "action:instrument",
    _pm("communicates"): "action:instrument",
    _pm("hosts"): "action:object",
    _pm("hostsOn"): "action:location",
    _pm("associatedWith"): "core:hasFacet",
    _pm("relatedTo"): "core:hasFacet",
    _pm("controls"): "action:object",
    _pm("controlsServer"): "action:object",
    _pm("observedIn"): "action:location",
    _pm("performs"): "action:performer",

    _pm("deletes"):    "action:object",   # deletes <files> → object is observable:File
    _pm("contains"):   "core:hasFacet",
}

def map_malont_predicate(pred: Optional[str]) -> Optional[str]:
    if not pred:
        return None
    k = _norm_key(pred)
    return PRED_MAP.get(k, pred)


def map_malont_predicate_with_context(pred: Optional[str],
                                      mapped_subject_type: Optional[str],
                                      mapped_object_type: Optional[str]) -> Optional[str]:
    base = map_malont_predicate(pred)
    if base is None:
        return None

    # If object is a literal, prefer attributes over relations where possible
    if mapped_object_type and mapped_object_type.startswith("core:"):
        if base in ("core:hasFacet", "core:description"):
            return "core:description"   # attribute; allowed for any subject with core:Literal
        if base.startswith("action:"):
            # action:* with literal object will likely fail; fall back to description
            return "core:description"

    # If the verb is about targeting/connecting/deleting, it’s an action on an observable
    if base == "action:object":
        # ensure subject will be an action (validator expects that combo)
        return "action:object"

    return base


def _force_action_subject_if_needed(subj_type: Optional[str], predicate: Optional[str]) -> Optional[str]:
    if isinstance(predicate, str) and predicate.startswith("action:"):
        if subj_type != "action:Action":
            return "action:Action"
    return subj_type


# -----------------------------------------------------------------------------
# 3) High-level adapter: normalize MALONT → map to connection
#    Call this from your extractor to produce the "mapped" view.
# -----------------------------------------------------------------------------

def normalize_and_map_malont(triple: Dict[str, Any]) -> Dict[str, Any]:
    """
    Input triple is the raw LLM/MALONT-style triple:
      { "subject": {"name":..., "type":...}, "predicate": "...", "object": {"name":..., "type": ...}, ... }

    Returns a dict with both the original and a 'mapped' connection-ontology view.
    """
    subj = triple.get("subject", {}) or {}
    obj  = triple.get("object", {}) or {}

    # 1) Canonicalize MALONT types and predicate
    s_type_canon = canonicalize_type(subj.get("type"))
    o_type_canon = canonicalize_type(obj.get("type"))
    p_canon      = canonicalize_predicate(triple.get("predicate"))

    # 2) Map to connection ontology
    s_type_conn = map_malont_type(s_type_canon)
    o_type_conn = map_malont_type(o_type_canon)
    # 3) Context-aware predicate mapping (uses mapped types)
    p_conn = map_malont_predicate_with_context(p_canon, s_type_conn, o_type_conn)
    # 4) Ensure subject is action for action:* predicates
    s_type_conn = _force_action_subject_if_needed(s_type_conn, p_conn)

    mapped = {
        "subject": {"name": subj.get("name"), "type": s_type_conn},
        "predicate": p_conn,
        "object": {"name": obj.get("name"), "type": o_type_conn},
    }

    # Preserve originals and add mapped
    out = dict(triple)
    out["mapped"] = mapped
    return out
