from __future__ import annotations
import json
import re
import os
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, asdict

BASE_DIR = Path(__file__).parent.resolve()

# -----------------------------
# CONFIG
# -----------------------------
WORKDIR       = BASE_DIR / "output" / "CTI-HAL"
MANIFEST_PATH = WORKDIR / Path("manifest.json")
ANALYSIS_OUT  = WORKDIR / Path("analysis")
# Second candidate analysis folder under datasets (for cleaning)
DATASET_ANALYSIS = BASE_DIR / "datasets" / "CTI-HAL" / "analysis"
# List of analysis paths to clean
ANALYSIS_PATHS_TO_CLEAN = [ANALYSIS_OUT, DATASET_ANALYSIS]
MAPPINGS_CSV  = BASE_DIR / Path("CTI_HAL_mappings.csv")
# If true, delete CTI-HAL/analysis before running (can override via env SIM_CLEAN_ANALYSIS=1)
CLEAN_ANALYSIS = os.getenv("SIM_CLEAN_ANALYSIS", "1") == "1"

# Hit@k configuration (comma-separated env var or default)
_HIT_KS_ENV = os.getenv("SIM_HIT_KS", "1,3,5")
HIT_KS: Tuple[int, ...] = tuple(sorted({int(x) for x in _HIT_KS_ENV.split(',') if x.strip().isdigit()})) or (1, 3, 5)


LIKELY_ENTITY_KEYS = {
    # flat lists of strings
    "entities", "entity_names", "tools", "groups", "malware", "software",
    # lists of dicts with 'name' fields
    "annotations", "entity_mentions", "extractions", "labels", "items",
    # MITRE-y things
    "techniques", "tactics", "subtechniques", "mitre_ids"
}


RESULT_SOURCE_KEYS = {"source", "cti_entity", "entity", "node", "name"}

# ATT&CK ID regex patterns for techniques, tactics, software
ATTACK_ID_PATTERNS = {
    "technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE),
    "tactic": re.compile(r"\bTA0\d{3}\b", re.IGNORECASE),
    "software": re.compile(r"\bS\d{4}\b", re.IGNORECASE),
}
def extract_attack_ids_from_results(sim_dir: Path) -> Set[str]:
    ids: Set[str] = set()
    per_node = sim_dir / "similarity_per_node.json"
    if not per_node.exists():
        log(f"[warn] No similarity_per_node.json in {sim_dir}")
        return ids

    obj = _read_json(per_node)

    # First preference: use clean_id already present on ATT&CK targets (emitted by similarity_scoring)
    def collect_clean_ids(v: Any):
        if isinstance(v, dict):
            # a node with top_k
            if "top_k" in v and isinstance(v["top_k"], list):
                for hit in v["top_k"]:
                    if not isinstance(hit, dict):
                        continue
                    target = hit.get("target") or {}
                    if not isinstance(target, dict):
                        continue
                    labels = set(target.get("labels") or [])
                    if not (ATTACK_LABELS & labels):
                        continue
                    cid = target.get("clean_id")
                    if isinstance(cid, str) and cid.strip():
                        ids.add(cid.strip().upper())
            for vv in v.values():
                collect_clean_ids(vv)
        elif isinstance(v, list):
            for it in v:
                collect_clean_ids(it)

    collect_clean_ids(obj)

    if ids:
        return ids

    # Fallback: scan strings for IDs if clean_id wasn't available
    def scan_value(v: Any):
        if isinstance(v, str):
            s = v.upper()
            for rx in ATTACK_ID_PATTERNS.values():
                for m in rx.findall(s):
                    ids.add(m.upper())
        elif isinstance(v, dict):
            for vv in v.values():
                scan_value(vv)
        elif isinstance(v, list):
            for it in v:
                scan_value(it)

    if isinstance(obj, dict):
        for k, v in obj.items():
            scan_value(k)
            scan_value(v)
    elif isinstance(obj, list):
        for entry in obj:
            scan_value(entry)

    return ids

@dataclass
class PdfRun:
    pdf: Path
    group: str
    similarity_dir: Path
    ann_L_dir: Path
    ann_S_dir: Path
    chunk_json: Optional[Path] = None

@dataclass
class PdfScores:
    pdf: str
    group: str
    matched: int
    missed: int
    spurious: int
    precision: float
    recall: float
    f1: float
    n_gt: int
    n_found: int
    matched_list: List[str]
    missed_list: List[str]
    spurious_list: List[str]
    # hit@k metrics (generic)
    queries: int
    hit_rates: Dict[int, float]      # e.g., {1: 0.42, 3: 0.57}
    hit_counts: Dict[int, int]       # e.g., {1: 12, 3: 18}
def compute_hits_multi(sim_dir: Path, gt_ids: Set[str], ks: Tuple[int, ...] = HIT_KS) -> Tuple[int, Dict[int, int]]:
    """Single-pass computation of hit@k for k in ks.
    Returns (queries, hits_by_k) where hits_by_k[k] is the number of queries with at least one GT ID in top-k.
    Only counts targets whose labels intersect ATTACK_LABELS, using target.clean_id.
    """
    per_node = sim_dir / "similarity_per_node.json"
    if not per_node.exists():
        return (0, {k: 0 for k in ks})
    obj = _read_json(per_node)

    max_k = max(ks) if ks else 5
    hits_by_k = {k: 0 for k in ks}
    queries = 0

    def process_entry(entry: Any) -> None:
        nonlocal queries
        if not isinstance(entry, dict):
            return
        topk = entry.get("top_k")
        if not isinstance(topk, list) or not topk:
            return
        seq: List[str] = []
        for hit in topk[:max_k]:
            if not isinstance(hit, dict):
                continue
            target = hit.get("target") or {}
            if not isinstance(target, dict):
                continue
            labels = set(target.get("labels") or [])
            if not (ATTACK_LABELS & labels):
                continue
            cid = target.get("clean_id")
            if isinstance(cid, str) and cid.strip():
                seq.append(cid.strip().upper())
        if not seq:
            return
        queries += 1
        # Compute hits for each k
        sset = set(seq)  # used if len(seq) < k
        for k in ks:
            top_set = set(seq[:k]) if len(seq) >= k else sset
            if top_set & gt_ids:
                hits_by_k[k] += 1

    if isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, dict) and "top_k" in v:
                process_entry(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict) and "top_k" in it:
                        process_entry(it)
    elif isinstance(obj, list):
        for entry in obj:
            if isinstance(entry, dict) and "top_k" in entry:
                process_entry(entry)

    return (queries, hits_by_k)

# -----------------------------
# Helpers
# -----------------------------

def log(msg: str) -> None:
    print(msg, flush=True)


def _read_json(p: Path) -> Any:
    """Read JSON with robust decoding. Tries utf-8, utf-8-sig, latin-1, then utf-8 ignore.
    As a last resort, attempts to strip leading/trailing junk around the first '{' and last '}'
    and parse that slice.
    """
    # First, try common encodings cleanly
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return json.loads(p.read_text(encoding=enc))
        except UnicodeDecodeError:
            continue
        except json.JSONDecodeError:
            # If decoding worked but JSON failed, try next strategy
            pass
    # Next, decode with utf-8 ignoring bad bytes (may lose some characters inside strings)
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    # Last resort: read bytes, slice between the first '{' and last '}' and parse
    try:
        raw = p.read_bytes()
        text = raw.decode("utf-8", errors="ignore")
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = text[start:end+1]
            return json.loads(snippet)
    except Exception:
        pass
    # Give a clear error with file path
    raise ValueError(f"Failed to read JSON from {p} with multiple decoding strategies")


def _write_json(obj: Any, p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

ATTACK_LABELS = {"UcoexMITREATTACK", "UcoexTACTICS", "UcoexSOFTWARE"}



# --- Path normalization helpers ---
def _to_path(x: Any) -> Path:
    """Normalize to a Path, tolerating Windows-style backslashes in JSON."""
    return Path(str(x).replace("\\", "/")).resolve() if isinstance(x, (str, Path)) else Path(str(x))


def _basename_any(p: Any) -> str:
    """Return the final filename component for paths that may contain '/' or '\\'."""
    s = str(p)
    # split on both separators
    s = s.split('/')[-1]
    s = s.split('\\')[-1]
    return s


def _read_mappings_csv(path: Path) -> Dict[str, Dict[str, str]]:
    """Return mapping from document filename (lowercased) -> {identifier, group, title}.
    Expects columns: Title, Document, Identifier, Group (Group optional).
    """
    import csv
    mapping: Dict[str, Dict[str, str]] = {}
    if not path.exists():
        return mapping
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            doc = (row.get("Document") or "").strip()
            ident = (row.get("Identifier") or "").strip()
            group = (row.get("Group") or "").strip()
            title = (row.get("Title") or "").strip()
            if not doc or not ident:
                continue
            mapping[doc.lower()] = {"identifier": ident, "group": group, "title": title}
            # also allow stem-only match
            if doc.lower().endswith(".pdf"):
                mapping[doc.lower()[:-4]] = {"identifier": ident, "group": group, "title": title}
    return mapping


def _parse_readme_mapping(readme_path: Path) -> Dict[str, str]:
    """Parse a Markdown table that maps PDF filenames to annotation JSON base names.
    Returns a dict where keys are lowercased PDF filenames (with or without .pdf) and
    values are lowercased JSON basenames (with or without .json).
    The function looks for the first table whose header contains both 'pdf' and 'annot' tokens.
    """
    mapping: Dict[str, str] = {}
    if not readme_path.exists():
        return mapping
    text = readme_path.read_text(encoding="utf-8", errors="ignore")
    lines = [ln.strip() for ln in text.splitlines()]

    # Find table header line
    header_idx = -1
    for i, ln in enumerate(lines):
        if ln.startswith("|") and "|" in ln:
            hdr = [h.strip().lower() for h in ln.strip("|").split("|")]
            if any("pdf" in h or "report" in h for h in hdr) and any("annot" in h for h in hdr):
                header_idx = i
                break
    if header_idx == -1:
        return mapping

    # Determine column indexes
    header = [h.strip().lower() for h in lines[header_idx].strip("|").split("|")]
    try:
        pdf_col = next(i for i, h in enumerate(header) if ("pdf" in h or "report" in h))
        ann_col = next(i for i, h in enumerate(header) if "annot" in h)
    except StopIteration:
        return mapping

    # Walk rows until a non-table line
    for ln in lines[header_idx+1:]:
        if not ln.startswith("|"):
            break
        # skip separator rows like |---|
        if set(ln.replace("|", "").strip()) <= set("-: "):
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) <= max(pdf_col, ann_col):
            continue
        pdf_cell = cells[pdf_col].strip()
        ann_cell = cells[ann_col].strip()
        if not pdf_cell or not ann_cell:
            continue
        # Clean extensions and lowercase
        pdf_key = pdf_cell.lower()
        ann_val = ann_cell.lower()
        mapping[pdf_key] = ann_val
        # also store stem-only variants for convenience
        if pdf_key.endswith(".pdf"):
            mapping[pdf_key[:-4]] = ann_val
        if ann_val.endswith(".json"):
            mapping[pdf_key] = ann_val[:-5]
            if pdf_key.endswith(".pdf"):
                mapping[pdf_key[:-4]] = ann_val[:-5]
    return mapping


def read_manifest(manifest_path: Path) -> List[PdfRun]:
    obj = _read_json(manifest_path)
    runs_obj = obj.get("runs", []) if isinstance(obj, dict) else obj
    runs: List[PdfRun] = []
    for r in runs_obj:
        runs.append(PdfRun(
            pdf=_to_path(r["pdf"]),
            group=r.get("group", "unknown"),
            similarity_dir=_to_path(r["similarity_dir"]),
            ann_L_dir=_to_path(r["annotations"]["annotator_L"]),
            ann_S_dir=_to_path(r["annotations"]["annotator_S"]),
            chunk_json=_to_path(r["chunk_json"]) if r.get("chunk_json") else None,
        ))
    return runs


def find_annotation_files(pdf_run: PdfRun) -> Tuple[Optional[Path], Optional[Path]]:
    base = _basename_any(pdf_run.pdf)
    doc_key = base.lower()
    # compute stem manually to handle names with multiple dots consistently
    doc_stem = doc_key[:-4] if doc_key.endswith('.pdf') else Path(base).stem.lower()

    csv_map = _read_mappings_csv(MAPPINGS_CSV)
    ident: Optional[str] = None
    if doc_key in csv_map:
        ident = csv_map[doc_key]["identifier"].strip()
    elif doc_stem in csv_map:
        ident = csv_map[doc_stem]["identifier"].strip()

    if not ident:
        log(f"[warn] No CSV mapping found for {pdf_run.pdf.name}")
        return None, None

    base_name = ident if not ident.lower().endswith(".json") else ident[:-5]

    # APT29 is dual-annotated (Annotator L and Annotator S). Others are single-annotated.
    is_apt29 = (pdf_run.group or "").strip().upper() == "APT29"

    if is_apt29:
        # Use explicit L and S subfolders as provided by the manifest
        L = (pdf_run.ann_L_dir / f"{base_name}.json")
        S = (pdf_run.ann_S_dir / f"{base_name}.json")
        L_best = L if L.exists() else None
        S_best = S if S.exists() else None
        if not L_best and not S_best:
            log(
                f"[warn] APT29 annotation files not found for '{ident}' as {base_name}.json in:\n"
                f"  L={pdf_run.ann_L_dir}\n  S={pdf_run.ann_S_dir}"
            )
        return L_best, S_best

    # Non-APT29: only a single annotation exists. Look directly in the group annotation folder(s).
    # We will search a small set of candidate directories, preferring those that exist.
    candidates = []
    for d in [pdf_run.ann_L_dir, pdf_run.ann_S_dir, pdf_run.ann_L_dir.parent, pdf_run.ann_S_dir.parent]:
        try:
            if d and d.exists() and d.is_dir():
                candidates.append(d)
        except Exception:
            continue

    # Deduplicate while preserving order
    seen = set()
    unique_dirs = []
    for d in candidates:
        if str(d) not in seen:
            unique_dirs.append(d)
            seen.add(str(d))

    found_path: Optional[Path] = None
    for d in unique_dirs:
        p = d / f"{base_name}.json"
        if p.exists():
            found_path = p
            break

    if not found_path:
        log(
            f"[warn] Annotation file not found for '{ident}' as {base_name}.json in any of:\n  " +\
            "\n  ".join(str(d) for d in unique_dirs) if unique_dirs else f"[warn] No candidate annotation dirs available for group {pdf_run.group}"
        )
        return None, None

    # Return a single annotator file for non-APT29; the caller will handle None filtering
    return found_path, None


def extract_entities_from_annotation(json_path: Path) -> Set[str]:
    """Attempt to extract cybersecurity entity names from a variety of common schemas."""
    try:
        obj = _read_json(json_path)
    except Exception:
        return set()

    names: Set[str] = set()

    def maybe_add(val: Any):
        if isinstance(val, str) and val.strip():
            names.add(val.strip())

    def walk(x: Any):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in LIKELY_ENTITY_KEYS:
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, str):
                                maybe_add(item)
                            elif isinstance(item, dict):
                                # common shapes: {name: "X"}, {label: "Y"}
                                for kk in ("name", "label", "entity", "text"):
                                    if isinstance(item.get(kk), str):
                                        maybe_add(item[kk])
                    elif isinstance(v, dict):
                        for kk in ("name", "label", "entity", "text"):
                            if isinstance(v.get(kk), str):
                                maybe_add(v[kk])
                    elif isinstance(v, str):
                        maybe_add(v)
                # always walk deeper to discover nested shapes
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)
        # primitives ignored

    walk(obj)

    # final normalization
    normalized = {re.sub(r"\s+", " ", n).strip() for n in names}
    return {n for n in normalized if n}


def extract_attack_entities(json_path: Path) -> Dict[str, Set[str]]:
    """Extract ATT&CK entities: technique IDs (T####[.###]), tactic IDs (TA000x),
    and software/tool IDs (S####), plus their names if present.
    The MICROSOFT.json example shows fields like 'technique', and metadata with
    'tactic', 'tactic_name', 'technique_name', 'sub_technique', 'sub_technique_name', 'tool', 'tool_name'.
    """
    try:
        obj = _read_json(json_path)
    except Exception:
        return {"techniques": set(), "tactics": set(), "software": set(), "names": set()}

    techs: Set[str] = set()
    tacts: Set[str] = set()
    soft: Set[str] = set()
    names: Set[str] = set()

    def add_name(x: Any):
        if isinstance(x, str) and x.strip():
            names.add(x.strip())

    def walk(x: Any):
        if isinstance(x, dict):
            # direct technique id
            t = x.get("technique")
            if isinstance(t, str) and t.strip():
                techs.add(t.strip())
            md = x.get("metadata")
            if isinstance(md, dict):
                # tactic ids and names
                tac_ids = md.get("tactic")
                tac_names = md.get("tactic_name")
                if isinstance(tac_ids, list):
                    for ti in tac_ids:
                        if isinstance(ti, str) and ti.strip():
                            tacts.add(ti.strip())
                if isinstance(tac_names, list):
                    for tn in tac_names:
                        add_name(tn)
                # technique names
                add_name(md.get("technique_name"))
                add_name(md.get("sub_technique_name"))
                # sub-technique id
                sti = md.get("sub_technique")
                if isinstance(sti, str) and sti.strip():
                    techs.add(sti.strip())
                # software/tool ids and names
                tools = md.get("tool")
                tool_names = md.get("tool_name")
                if isinstance(tools, list):
                    for sid in tools:
                        if isinstance(sid, str) and sid.strip():
                            soft.add(sid.strip())
                elif isinstance(tools, str) and tools.strip():
                    soft.add(tools.strip())
                if isinstance(tool_names, list):
                    for nm in tool_names:
                        add_name(nm)
                elif isinstance(tool_names, str):
                    add_name(tool_names)
            # generic names
            for k in ("name", "label", "entity", "text"):
                add_name(x.get(k))
            # walk deeper
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)

    walk(obj)

    # Normalize
    def norm_ids(s: Set[str]) -> Set[str]:
        out = set()
        for v in s:
            vv = v.strip().upper()
            out.add(vv)
        return out

    return {
        "techniques": norm_ids(techs),
        "tactics": norm_ids(tacts),
        "software": norm_ids(soft),
        "names": {re.sub(r"\s+", " ", n).strip() for n in names if n and n.strip()}
    }


def extract_cti_entities_from_results(sim_dir: Path) -> Set[str]:
    """Pull the CTIEntity names that our pipeline produced for this PDF.
    We prefer similarity_per_node.json (per-source entries), falling back to chunk data if needed."""
    names: Set[str] = set()
    per_node = sim_dir / "similarity_per_node.json"
    if per_node.exists():
        obj = _read_json(per_node)
        # Support both list and dict schemas
        if isinstance(obj, dict):
            # could be { entity_name: {neighbors:[...]}, ... }
            for k, v in obj.items():
                if isinstance(k, str):
                    names.add(k)
                if isinstance(v, dict):
                    for kk in RESULT_SOURCE_KEYS:
                        if isinstance(v.get(kk), str):
                            names.add(v[kk])
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            for kk in RESULT_SOURCE_KEYS:
                                if isinstance(item.get(kk), str):
                                    names.add(item[kk])
        elif isinstance(obj, list):
            # could be [ {source:"X", neighbors:[...]}, ... ]
            for entry in obj:
                if not isinstance(entry, dict):
                    continue
                for kk in RESULT_SOURCE_KEYS:
                    if isinstance(entry.get(kk), str):
                        names.add(entry[kk])
                # sometimes nested under 'source': {'name': 'X'}
                src = entry.get("source")
                if isinstance(src, dict) and isinstance(src.get("name"), str):
                    names.add(src["name"])
    else:
        log(f"[warn] No similarity_per_node.json in {sim_dir}")

    # normalize
    names = {re.sub(r"\s+", " ", n).strip() for n in names}
    return {n for n in names if n}


def score_single(pdf_run: PdfRun, ann_paths: List[Path]) -> PdfScores:
    # Ground-truth: ATT&CK IDs from annotations (union of annotators)
    gt_ids: Set[str] = set()
    for ap in ann_paths:
        atk = extract_attack_entities(ap)
        gt_ids |= atk["techniques"] | atk["tactics"] | atk["software"]

    # Our results: ATT&CK IDs parsed from similarity output
    found_ids = extract_attack_ids_from_results(pdf_run.similarity_dir)

    matched_ids = sorted(found_ids & gt_ids)
    missed_ids  = sorted(gt_ids - found_ids)
    spurious_ids = sorted(found_ids - gt_ids)

    n_matched = len(matched_ids)
    n_gt = len(gt_ids)
    n_found = len(found_ids)

    precision = (n_matched / n_found) if n_found else 0.0
    recall = (n_matched / n_gt) if n_gt else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # Efficient multi-k hits in a single pass
    queries, hits_by_k = compute_hits_multi(pdf_run.similarity_dir, gt_ids, HIT_KS)
    hit_rates = {k: (hits_by_k.get(k, 0) / queries) if queries else 0.0 for k in HIT_KS}

    return PdfScores(
        pdf=str(pdf_run.pdf),
        group=pdf_run.group,
        matched=n_matched,
        missed=len(missed_ids),
        spurious=len(spurious_ids),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        n_gt=n_gt,
        n_found=n_found,
        matched_list=matched_ids,
        missed_list=missed_ids,
        spurious_list=spurious_ids,
        queries=queries,
        hit_rates={k: round(v, 4) for k, v in hit_rates.items()},
        hit_counts={k: int(hits_by_k.get(k, 0)) for k in HIT_KS},
    )


def analyze() -> None:
    # Optionally wipe previous analysis outputs for a clean run (both output/ and datasets/ locations)
    if CLEAN_ANALYSIS:
        for ap in ANALYSIS_PATHS_TO_CLEAN:
            try:
                if ap.exists() and ap.is_dir():
                    log(f"[Analysis] CLEAN_ANALYSIS=1; removing: {ap}")
                    shutil.rmtree(ap, ignore_errors=True)
            except Exception as e:
                log(f"[warn] Failed to remove {ap}: {e}")
    ANALYSIS_OUT.mkdir(parents=True, exist_ok=True)
    log(f"[Analysis] Writing fresh analysis to: {ANALYSIS_OUT}")

    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"manifest not found: {MANIFEST_PATH}")

    runs = read_manifest(MANIFEST_PATH)
    per_pdf: List[PdfScores] = []

    for r in runs:
        # locate L/S jsons for this PDF
        L_json, S_json = find_annotation_files(r)
        ann_list = [p for p in [L_json, S_json] if p is not None]
        if not ann_list:
            log(f"[warn] No annotations found for { _basename_any(r.pdf) } (missing mapping or files)")
            continue

        log(f"[Analysis] {r.pdf.name}: L={L_json.name if L_json else '—'}, S={S_json.name if S_json else '—'}")
        scores = score_single(r, ann_list)
        per_pdf.append(scores)

        # Build unioned ground-truth IDs for transparency
        gt_ids_union: Set[str] = set()
        for ap in ann_list:
            atk = extract_attack_entities(ap)
            gt_ids_union |= atk["techniques"] | atk["tactics"] | atk["software"]

        out_payload = {
            "pdf": scores.pdf,
            "group": scores.group,
            "annotation_files": [str(p) for p in ann_list],
            "ground_truth_attack_ids": sorted(list(gt_ids_union)),
            "matched_ids": scores.matched_list,
            "missed_ids": scores.missed_list,
            "spurious_ids": scores.spurious_list,
            "precision": scores.precision,
            "recall": scores.recall,
            "f1": scores.f1,
            "n_gt": scores.n_gt,
            "n_found": scores.n_found,
            "queries": scores.queries,
            "hit_at_k": scores.hit_rates,     # rates per k
            "hit_counts": scores.hit_counts,  # counts per k
        }
        out_dir = ANALYSIS_OUT / r.group / r.pdf.stem
        _write_json(out_payload, out_dir / "entity_scoring.json")

    # Group-level and overall summaries (dynamic over HIT_KS)
    group_totals: Dict[str, Dict[str, Any]] = {}
    overall = {"pdfs": 0, "queries": 0, "matched": 0, "missed": 0, "spurious": 0, "n_gt": 0, "n_found": 0}
    for k in HIT_KS:
        overall[f"hit{k}_count"] = 0

    for s in per_pdf:
        g = s.group or "unknown"
        if g not in group_totals:
            gt = {"pdfs": 0, "queries": 0, "matched": 0, "missed": 0, "spurious": 0, "n_gt": 0, "n_found": 0}
            for k in HIT_KS:
                gt[f"hit{k}_count"] = 0
            group_totals[g] = gt
        else:
            gt = group_totals[g]
        gt["pdfs"] += 1
        gt["queries"] += s.queries
        for k in HIT_KS:
            gt[f"hit{k}_count"] += s.hit_counts.get(k, 0)
        # other totals
        gt["matched"] += s.matched
        gt["missed"] += s.missed
        gt["spurious"] += s.spurious
        gt["n_gt"] += s.n_gt
        gt["n_found"] += s.n_found

        overall["pdfs"] += 1
        overall["queries"] += s.queries
        for k in HIT_KS:
            overall[f"hit{k}_count"] += s.hit_counts.get(k, 0)
        overall["matched"] += s.matched
        overall["missed"] += s.missed
        overall["spurious"] += s.spurious
        overall["n_gt"] += s.n_gt
        overall["n_found"] += s.n_found

    def finalize_counts_dynamic(d: Dict[str, Any]) -> Dict[str, Any]:
        q = d.get("queries", 0) or 0
        for k in HIT_KS:
            key = f"hit{k}"
            cnt_key = f"hit{k}_count"
            d[key] = round((d.get(cnt_key, 0) / q), 4) if q else 0.0
        return d

    overall = finalize_counts_dynamic(overall)
    for g in list(group_totals.keys()):
        group_totals[g] = finalize_counts_dynamic(group_totals[g])

    _write_json(group_totals, ANALYSIS_OUT / "group_summary.json")
    _write_json(overall, ANALYSIS_OUT / "overall_summary.json")

    # aggregate leaderboard across PDFs
    leaderboard = sorted(per_pdf, key=lambda s: (s.f1, s.recall, s.precision), reverse=True)
    _write_json([asdict(s) for s in leaderboard], ANALYSIS_OUT / "leaderboard.json")

    # quick TSV for eyeballing (dynamic hit@k columns)
    hit_cols = "\t".join([f"hit@{k}" for k in HIT_KS])
    tsv_lines = [f"pdf\tgroup\tmatched\tmissed\tspurious\tgt\tfound\tprecision\trecall\tf1\tqueries\t{hit_cols}"]
    for s in leaderboard:
        hit_vals = "\t".join(str(s.hit_rates.get(k, 0.0)) for k in HIT_KS)
        tsv_lines.append(
            f"{Path(s.pdf).name}\t{s.group}\t{s.matched}\t{s.missed}\t{s.spurious}\t{s.n_gt}\t{s.n_found}\t{s.precision}\t{s.recall}\t{s.f1}\t{s.queries}\t{hit_vals}"
        )
    (ANALYSIS_OUT / "summary.tsv").write_text("\n".join(tsv_lines), encoding="utf-8")

    log(f"[Analysis] Wrote {len(per_pdf)} per-PDF reports + leaderboard + TSV to {ANALYSIS_OUT}")


if __name__ == "__main__":
    analyze()
