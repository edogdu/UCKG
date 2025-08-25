from pathlib import Path
import json
import time
import traceback
import sys

BASE_DIR = Path(__file__).parent.resolve()

# CONFIG (edit these)
MODEL_NAME        = "gemma2:9b"
EMBED_MODEL_NAME  = "nomic-embed-text"
OLLAMA_BASE_URL   = "http://localhost:11434"
NEO4J_URI         = "bolt://localhost:7687"
NEO4J_USER        = "neo4j"
NEO4J_PASS        = "abcd90909090"
WORKDIR           = BASE_DIR / "output"  # where chunk_data_*.json lands

CTI_HAL_REPO_URL  = "https://github.com/dessertlab/CTI-HAL.git"
CTI_HAL_LOCAL_DIR = BASE_DIR / "datasets" / "CTI-HAL"  # where to clone the repo
PROGRESS_PATH     = WORKDIR / "CTI-HAL" / "progress.json"

def _clean_state():
    # remove progress file
    try:
        if PROGRESS_PATH.exists():
            PROGRESS_PATH.unlink()
            log(f"[Clean] Removed progress file: {PROGRESS_PATH}")
    except Exception as e:
        log(f"[Clean] Warning: could not remove progress file: {e}")

    # rotate manifest if present
    man_path = WORKDIR / "CTI-HAL" / "manifest.json"
    try:
        if man_path.exists():
            ts = time.strftime("%Y%m%d-%H%M%S")
            backup = man_path.with_name(f"manifest.{ts}.bak.json")
            man_path.rename(backup)
            log(f"[Clean] Rotated manifest to: {backup}")
    except Exception as e:
        log(f"[Clean] Warning: could not rotate manifest: {e}")

def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def _save_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_progress(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"completed": [], "failed": []}
    return {"completed": [], "failed": []}


def _save_progress(obj: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


import subprocess
import os

def clear_cti_entities(neo4j_uri: str, neo4j_user: str, neo4j_pass: str) -> None:
    # Deletes all CTIEntity nodes and any attached relationships
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    try:
        with driver.session() as session:
            session.run("MATCH (n:CTIEntity) DETACH DELETE n")
    finally:
        driver.close()
    log("[DB] Cleared :CTIEntity nodes")

def ensure_repo(repo_url: str, dest: Path) -> None:
    dest_parent = dest.parent
    dest_parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        log(f"[Dataset] Cloning {repo_url} -> {dest}")
        subprocess.check_call(["git", "clone", "--depth", "1", repo_url, str(dest)])
    else:
        # Try to pull latest, but don't fail the pipeline if it errors
        try:
            log(f"[Dataset] Pulling latest in {dest}")
            subprocess.check_call(["git", "-C", str(dest), "pull", "--ff-only"]) 
        except subprocess.CalledProcessError as e:
            log(f"[Dataset] Warning: git pull failed ({e}); continuing with existing checkout")


def enumerate_cti_hal(repo_root: Path):
    """Yield tuples of (pdf_path, group_name, annotator_L_dir, annotator_S_dir).
    - PDFs live under Reports/<group>/**/*.pdf
    - Annotations live under Data/<group>/(annotator L|annotator S)/
    """
    reports_dir = repo_root / "Reports"
    data_dir    = repo_root / "Data"
    candidates = sorted(reports_dir.glob("**/*.pdf"), key=lambda p: str(p).lower())
    for pdf in candidates:
        # group is the immediate subdir under Reports
        try:
            group = pdf.relative_to(reports_dir).parts[0]
        except Exception:
            group = "unknown"
        ann_L = data_dir / group / "annotator L"
        ann_S = data_dir / group / "annotator S"
        yield pdf, group, ann_L, ann_S

def stage_extraction(input_path: Path, model: str, ollama_base_url: str, out_dir: Path) -> Path:
    from extraction import CyberTripleExtractor  # local module

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = input_path.stem.replace(" ", "_")
    chunk_json = out_dir / f"chunk_data_{stem}_{model.replace(':','_')}.json"

    log(f"[Extraction] model={model}, file={input_path}")
    extractor = CyberTripleExtractor(str(input_path), model_name=model, ollama_base_url=ollama_base_url)
    raw_chunk_results = extractor.run()
    extractor.build_dict(raw_chunk_results)

    if hasattr(extractor, "save_to_json"):
        extractor.save_to_json(str(chunk_json))  # preferred path if available
    else:
        # fallback: try common attribute name; otherwise just dump raw
        chunk_data = getattr(extractor, "chunk_data", raw_chunk_results)
        _save_json(chunk_data, chunk_json)

    log(f"[Extraction] wrote {chunk_json}")
    return chunk_json

def stage_insertion(chunk_json_path: Path, neo4j_uri: str, neo4j_user: str, neo4j_pass: str) -> None:
    import insertion  # local module

    chunk_obj = _load_json(chunk_json_path)
    chunk_data = chunk_obj.get("data", chunk_obj)

    log("[Insertion] inserting triples into Neo4j…")
    insertion.store_in_neo4j(chunk_data, uri=neo4j_uri, user=neo4j_user, password=neo4j_pass)
    log("[Insertion] complete")

def stage_clear_cti_entities() -> None:
    clear_cti_entities(NEO4J_URI, NEO4J_USER, NEO4J_PASS)

def stage_embed_cti_entities(chunk_json_path: Path, model: str, ollama_base_url: str,
                             neo4j_uri: str, neo4j_user: str, neo4j_pass: str) -> None:
    import insertion  # local module

    chunk_obj = _load_json(chunk_json_path)
    chunk_data = chunk_obj.get("data", chunk_obj)
    log("[Embedding] embedding CTIEntity nodes...")
    insertion.embed_cti_entities_from_chunk(
        chunk_data,
        uri=neo4j_uri,
        user=neo4j_user,
        password=neo4j_pass,
        model=model,
        ollama_url=f"{ollama_base_url.rstrip('/')}/api/embeddings",
    )
    log("[Embedding] CTIEntity nodes embedded")

# Similarity 
def stage_similarity(sim_output_dir: Path) -> None:
    # set per-run output dir for similarity_scoring
    os.environ["SIM_OUTPUT_DIR"] = str(sim_output_dir)
    from similarity_scoring import run_similarity  # local module (reads SIM_OUTPUT_DIR at import/run time)
    log(f"[Similarity] running vector top-k scoring via Neo4j index… -> {sim_output_dir}")
    run_similarity(sim_output_dir)
    log("[Similarity] results saved under similarity_scoring outputs/")

def stage_analysis() -> None:
    try:
        import extraction_analysis  # local module
    except Exception:
        log("[Analysis] results_analysis.py not found; skipping")
        return

    for fn in ("main", "run", "analyze", "entrypoint"):
        if hasattr(extraction_analysis, fn):
            log(f"[Analysis] results_analysis.{fn}()")
            getattr(extraction_analysis, fn)()
            log("[Analysis] complete")
            return
    log("[Analysis] no callable entrypoint found; skipping")

def process_single_pdf(pdf: Path, group: str, ann_L: Path, ann_S: Path) -> dict:
    out_dir = WORKDIR / "CTI-HAL" / group / pdf.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    started_ts = time.strftime("%Y-%m-%d %H:%M:%S")

    # Ensure per-file isolation: start with no CTIEntity nodes
    stage_clear_cti_entities()

    # Extract -> chunk json in out_dir
    chunk_json = stage_extraction(pdf, MODEL_NAME, OLLAMA_BASE_URL, out_dir)

    # Insert into Neo4j
    stage_insertion(chunk_json, NEO4J_URI, NEO4J_USER, NEO4J_PASS)

    # Embed CTIEntity nodes after insertion
    stage_embed_cti_entities(chunk_json, EMBED_MODEL_NAME, OLLAMA_BASE_URL, NEO4J_URI, NEO4J_USER, NEO4J_PASS)

    # Similarity: per-PDF results go to out_dir/vec_results
    sim_dir = out_dir / "vec_results"
    stage_similarity(sim_dir)

    return {
        "pdf": str(pdf),
        "group": group,
        "chunk_json": str(chunk_json),
        "similarity_dir": str(sim_dir),
        "annotations": {
            "annotator_L": str(ann_L),
            "annotator_S": str(ann_S),
        },
        "started": started_ts,
    }

def main() -> int:
    try:
        if "--clean" in sys.argv:
            log("[Clean] Starting clean run: resetting progress and manifest…")
            _clean_state()

        repo_dir = Path(CTI_HAL_LOCAL_DIR)
        ensure_repo(CTI_HAL_REPO_URL, repo_dir)

        progress = _load_progress(PROGRESS_PATH)
        completed_set = set(progress.get("completed", []))
        failed_entries = progress.get("failed", [])

        manifest = {"repo": str(repo_dir), "runs": []}
        count = 0

        for pdf, group, ann_L, ann_S in enumerate_cti_hal(repo_dir):
            if not pdf.exists():
                continue
            rel_pdf = str(pdf.relative_to(repo_dir))  # resume key
            if rel_pdf in completed_set:
                log(f"[Skip] Already completed: {rel_pdf}")
                continue

            log(f"[Pipeline] Processing PDF: {rel_pdf}")
            try:
                entry = process_single_pdf(pdf, group, ann_L, ann_S)
                manifest["runs"].append(entry)
                count += 1

                # mark completed and persist progress after EACH file
                completed_set.add(rel_pdf)
                progress["completed"] = sorted(list(completed_set))
                _save_progress(progress, PROGRESS_PATH)

            except KeyboardInterrupt:
                log("[Stop] Interrupted by user. Saving progress…")
                progress["completed"] = sorted(list(completed_set))
                _save_progress(progress, PROGRESS_PATH)
                break
            except Exception as e:
                log(f"[Error] Failed on {rel_pdf}: {e}")
                traceback.print_exc()
                failed_entries.append({"pdf": rel_pdf, "error": str(e)})
                progress["failed"] = failed_entries
                _save_progress(progress, PROGRESS_PATH)
                # continue to next file

        # Write manifest for this run (append-only semantics: we keep all entries we processed now)
        man_path = WORKDIR / "CTI-HAL" / "manifest.json"
        existing = {}
        if man_path.exists():
            try:
                existing = json.loads(man_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        # merge: keep prior runs plus new ones
        prior_runs = existing.get("runs", [])
        manifest_all = {"repo": str(repo_dir), "runs": prior_runs + manifest["runs"]}
        _save_json(manifest_all, man_path)

        log(f"Completed {count} new PDFs in this session. Manifest: {man_path}")
        log(f"Progress file: {PROGRESS_PATH}")
        return 0

    except Exception as e:
        log("Pipeline failed: " + str(e))
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Optional flag: `python main.py --clean` to reset progress & rotate manifest
    raise SystemExit(main())