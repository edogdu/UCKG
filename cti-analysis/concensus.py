# consensus.py
import re
from collections import defaultdict
from difflib import SequenceMatcher

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def _key(t):
    s = t.get("subject", {}) or {}
    o = t.get("object", {}) or {}
    p = (t.get("predicate") or "").strip()
    return (_norm(s.get("name","")), (s.get("type") or "").strip(),
            p,
            _norm(o.get("name","")), (o.get("type") or "").strip())

def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, _norm(a), _norm(b)).ratio()

def _quote_overlap(a: str, b: str) -> bool:
    aW = set(_norm(a).lower().split()); bW = set(_norm(b).lower().split())
    if not aW or not bW: return False
    return len(aW & bW) >= max(3, min(len(aW), len(bW)) // 2)

def consensus_filter(candidate_lists,
                     allowed_types, allowed_preds,
                     m=2, tau_name=0.90):
    """Keep only triples that reach quorum m across multiple prompt outputs."""
    # whitelist + flat
    all_triples = []
    for triples in (candidate_lists or []):
        for t in (triples or []):
            s, o, p = t.get("subject") or {}, t.get("object") or {}, t.get("predicate") or ""
            if s.get("type") in allowed_types and o.get("type") in allowed_types and p in allowed_preds:
                all_triples.append(t)

    if not all_triples:
        return []

    buckets = defaultdict(list)
    for t in all_triples:
        buckets[_key(t)].append(t)

    keys = list(buckets.keys())
    visited = set()
    accepted = []

    for i, ki in enumerate(keys):
        if ki in visited:
            continue
        group = list(buckets[ki])

        # try to merge near-duplicates with same predicate/types
        si,ti,pi,oi,ui = ki
        for j, kj in enumerate(keys):
            if j <= i or kj in visited: 
                continue
            sj,tj,pj,oj,uj = kj
            if pi != pj or ti != tj or ui != uj:
                continue
            if _sim(si, sj) >= tau_name and _sim(oi, oj) >= tau_name:
                qi = (group[0].get("evidence") or {}).get("quote","")
                qj = (buckets[kj][0].get("evidence") or {}).get("quote","")
                if _quote_overlap(qi, qj):
                    group += buckets[kj]
                    visited.add(kj)

        if len(group) >= m:
            rep = max(group, key=lambda t: len((t.get("evidence") or {}).get("quote","")))
            accepted.append(rep)

        visited.add(ki)

    return accepted
