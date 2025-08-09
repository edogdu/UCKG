#!/usr/bin/env python3
# evaluate_fuzzy.py — run this from the extracted_triples folder

import os
import re
import glob
import json
import unicodedata
import string
import textwrap
from difflib import SequenceMatcher

import pandas as pd  # pip install pandas openpyxl

# =========================
# Tunable knobs
# =========================
PAGE_SLACK = 1          # allow same page or ±1
CONTAIN_THRESH = 0.80   # token containment threshold
FUZZY_HIGH = 0.90       # first fuzzy pass (stricter)
FUZZY_LOW  = 0.85       # second fuzzy pass (looser, last resort)
TOPK_FOR_UNMATCHED = 3  # how many nearest candidates to show for each unmatched gold
MAX_CONTEXT_CHARS = 220 # truncate contexts in Excel to keep them readable
SHOW_TOP_MATCHES = 12   # how many matched rows to print per file in terminal (0 = none)
SHOW_TOP_NEARMISS = 8   # how many near-misses to print per file in terminal (0 = none)
CTX_COL_WIDTH = 60      # terminal context width
# =========================

# -------- Text utils --------
PUNCT = "".join(ch for ch in string.punctuation if ch not in "-_/")
PUNCT_RE = re.compile("[" + re.escape(PUNCT) + "]")
MULTISPACE_RE = re.compile(r"\s+")

def norm_text(s: str) -> str:
    s = (s or "").replace("\u00AD","")            # soft hyphen
    s = unicodedata.normalize("NFKC", s)
    s = s.replace("-\n", "").replace("-\r\n", "") # de-hyphenate line breaks
    s = s.replace("\n", " ").replace("\r", " ")
    s = s.lower().strip()
    s = PUNCT_RE.sub(" ", s)                      # drop most punctuation
    s = MULTISPACE_RE.sub(" ", s)                 # collapse spaces
    return s

def tokens(s: str):
    return [t for t in s.split() if t]

def jaccard(a: str, b: str) -> float:
    A, B = set(tokens(a)), set(tokens(b))
    if not A and not B: return 1.0
    if not A or not B:  return 0.0
    return len(A & B) / len(A | B)

def sim_char(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def hybrid_sim(a: str, b: str, alpha: float = 0.6) -> float:
    # blend character similarity and token Jaccard
    return alpha * sim_char(a, b) + (1 - alpha) * jaccard(a, b)

def containment(a: str, b: str) -> float:
    # fraction of gold tokens present in pred
    A, B = set(tokens(a)), set(tokens(b))
    return (len(A & B) / len(A)) if A else 0.0

def shorten(s: str, width: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return textwrap.shorten(s, width=width, placeholder="…")

def clean_for_excel(s: str, limit: int = MAX_CONTEXT_CHARS) -> str:
    if s is None: return ""
    s = MULTISPACE_RE.sub(" ", s).strip()
    return (s if len(s) <= limit else s[:limit-1] + "…")

def safe_name(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r'[<>:"/\\|?*]+', "_", base)

# -------- Loaders --------
def load_gold(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    items = []
    for row in data:
        items.append({
            "ctx":  norm_text(row.get("context", "")),
            "page": (row.get("metadata", {}) or {}).get("page_number"),
            "id":   (row.get("metadata", {}) or {}).get("id"),
            "raw":  row
        })
    return items

def load_pred(path: str):
    with open(path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    items = []
    for row in meta.get("data", []):
        items.append({
            "ctx":  norm_text(row.get("context", "")),
            "page": (row.get("metadata", {}) or {}).get("page_number"),
            "id":   (row.get("metadata", {}) or {}).get("id"),
            "raw":  row
        })
    return items

# -------- Matching --------
def page_ok(gpage, ppage, slack=PAGE_SLACK):
    if gpage is None or ppage is None:
        return True
    try:
        return abs(int(gpage) - int(ppage)) <= slack
    except Exception:
        return True

def align_exact_contain_fuzzy(golds, preds,
                              contain_thresh=CONTAIN_THRESH,
                              fuzzy_high=FUZZY_HIGH,
                              fuzzy_low=FUZZY_LOW,
                              page_slack=PAGE_SLACK):
    """
    Returns:
      matches: list of (gi, pi, score)
      unmatched_gold: list of gi
      unmatched_pred: list of pi
      match_methods: dict keyed by (gi,pi) -> "exact"|"containment"|"fuzzy_high"|"fuzzy_low"
    """
    # exact index by normalized context
    p_index = {}
    for i, p in enumerate(preds):
        p_index.setdefault(p["ctx"], []).append(i)

    used_pred = set()
    matches = []
    unmatched_gold = []
    match_methods = {}

    # 1) exact match
    for gi, g in enumerate(golds):
        cand = p_index.get(g["ctx"], [])
        chosen = None
        for pi in cand:
            if pi not in used_pred:
                chosen = pi
                break
        if chosen is not None:
            used_pred.add(chosen)
            matches.append((gi, chosen, 1.0))
            match_methods[(gi, chosen)] = "exact"
        else:
            unmatched_gold.append(gi)

    def candidate_pred_indices(gi, remaining):
        gpage = golds[gi].get("page")
        return [pi for pi in remaining if page_ok(gpage, preds[pi].get("page"), page_slack)]

    # 2) containment pass (order-robust)
    remaining_pred = [i for i in range(len(preds)) if i not in used_pred]
    for gi in list(unmatched_gold):
        gctx = golds[gi]["ctx"]
        best = (-1.0, None, None)  # (containment, pi, (char_sim,jaccard))
        for pi in candidate_pred_indices(gi, remaining_pred):
            pctx = preds[pi]["ctx"]
            c = containment(gctx, pctx)
            if c > best[0]:
                best = (c, pi, (sim_char(gctx, pctx), jaccard(gctx, pctx)))
        if best[0] >= contain_thresh:
            c, pi, (cs, jc) = best
            matches.append((gi, pi, float(c)))
            match_methods[(gi, pi)] = "containment"
            used_pred.add(pi)
            remaining_pred.remove(pi)
            unmatched_gold.remove(gi)

    # 3) hybrid fuzzy (strict)
    remaining_pred = [i for i in range(len(preds)) if i not in used_pred]
    for gi in list(unmatched_gold):
        gctx = golds[gi]["ctx"]; glen = len(gctx)
        best = (-1.0, None, None)  # (score, pi, (char_sim,jaccard,contain))
        for pi in candidate_pred_indices(gi, remaining_pred):
            pctx = preds[pi]["ctx"]
            if glen and abs(len(pctx) - glen) > int(0.25 * glen):
                continue
            cs = sim_char(gctx, pctx)
            jc = jaccard(gctx, pctx)
            ct = containment(gctx, pctx)
            s  = 0.6*cs + 0.4*jc
            if s > best[0]:
                best = (s, pi, (cs, jc, ct))
        if best[0] >= fuzzy_high and best[1] is not None:
            s, pi, (cs, jc, ct) = best
            matches.append((gi, pi, float(s)))
            match_methods[(gi, pi)] = "fuzzy_high"
            used_pred.add(pi)
            remaining_pred.remove(pi)
            unmatched_gold.remove(gi)

    # 4) hybrid fuzzy (looser, last resort)
    remaining_pred = [i for i in range(len(preds)) if i not in used_pred]
    for gi in list(unmatched_gold):
        gctx = golds[gi]["ctx"]; glen = len(gctx)
        best = (-1.0, None, None)
        for pi in candidate_pred_indices(gi, remaining_pred):
            pctx = preds[pi]["ctx"]
            if glen and abs(len(pctx) - glen) > int(0.35 * glen):
                continue
            cs = sim_char(gctx, pctx)
            jc = jaccard(gctx, pctx)
            ct = containment(gctx, pctx)
            s  = 0.55*cs + 0.45*jc
            if s > best[0]:
                best = (s, pi, (cs, jc, ct))
        if best[0] >= fuzzy_low and best[1] is not None:
            s, pi, (cs, jc, ct) = best
            matches.append((gi, pi, float(s)))
            match_methods[(gi, pi)] = "fuzzy_low"
            used_pred.add(pi)
            remaining_pred.remove(pi)
            unmatched_gold.remove(gi)

    unmatched_pred = [i for i in range(len(preds)) if i not in used_pred]
    return matches, unmatched_gold, unmatched_pred, match_methods

# -------- Terminal pretty printing --------
def print_divider():
    print("-" * (10 + 7 + 2*CTX_COL_WIDTH))

def print_matches_table(matches, golds, preds, match_methods, limit=SHOW_TOP_MATCHES):
    if limit == 0 or not matches:
        return
    method_rank = {"exact": 0, "containment": 1, "fuzzy_high": 2, "fuzzy_low": 3}
    matches_sorted = sorted(
        matches,
        key=lambda m: (-(m[2]), method_rank.get(match_methods.get((m[0], m[1]), "fuzzy_low"), 99))
    )[:limit]

    print_divider()
    header = f"{'#':>3}  {'Sim':>6}  {'Gold Context':<{CTX_COL_WIDTH}}  {'Pred Context':<{CTX_COL_WIDTH}}"
    print(header)
    print_divider()
    for idx, (gi, pi, sc) in enumerate(matches_sorted, start=1):
        gtxt = shorten(golds[gi]["raw"].get("context",""), CTX_COL_WIDTH)
        ptxt = shorten(preds[pi]["raw"].get("context",""), CTX_COL_WIDTH)
        print(f"{idx:>3}  {sc:6.3f}  {gtxt:<{CTX_COL_WIDTH}}  {ptxt:<{CTX_COL_WIDTH}}")
    print_divider()

def print_nearmisses_table(golds, preds, unmatched_gold, limit=SHOW_TOP_NEARMISS):
    if limit == 0 or not unmatched_gold:
        return
    rows = []
    for gi in unmatched_gold:
        gctx = golds[gi]["ctx"]; gpage = golds[gi].get("page")
        best = (-1.0, None)
        for pi, p in enumerate(preds):
            if not page_ok(gpage, p.get("page"), PAGE_SLACK):
                continue
            s = hybrid_sim(gctx, p["ctx"], alpha=0.6)
            if s > best[0]:
                best = (s, pi)
        rows.append((best[0], gi, best[1]))
    rows.sort(reverse=True, key=lambda r: r[0])
    rows = rows[:limit]
    if not rows:
        return

    print("\nClosest non-matches (gold vs best candidate):")
    print_divider()
    header = f"{'#':>3}  {'Best':>6}  {'Gold Context':<{CTX_COL_WIDTH}}  {'Best Candidate (Pred)':<{CTX_COL_WIDTH}}"
    print(header)
    print_divider()
    for idx, (score, gi, pi) in enumerate(rows, start=1):
        gtxt = shorten(golds[gi]["raw"].get("context",""), CTX_COL_WIDTH)
        ptxt = shorten(preds[pi]["raw"].get("context",""), CTX_COL_WIDTH) if pi is not None else ""
        print(f"{idx:>3}  {score:6.3f}  {gtxt:<{CTX_COL_WIDTH}}  {ptxt:<{CTX_COL_WIDTH}}")
    print_divider()

# -------- Excel writers (pretty, human-friendly) ----------
def _percent(x):
    try:
        return round(float(x) * 100.0, 1)
    except Exception:
        return ""

def _build_match_rows(matches, golds, preds, match_methods, max_ctx=MAX_CONTEXT_CHARS):
    rows = []
    for idx, (gi, pi, sc) in enumerate(matches, start=1):
        gold_ctx_raw = golds[gi]["raw"].get("context","")
        pred_ctx_raw = preds[pi]["raw"].get("context","")
        gctx_n = norm_text(gold_ctx_raw)
        pctx_n = norm_text(pred_ctx_raw)
        char_sim = sim_char(gctx_n, pctx_n)
        token_sim = jaccard(gctx_n, pctx_n)
        contain_score = containment(gctx_n, pctx_n)
        rows.append({
            "Match #": idx,
            "Method": match_methods.get((gi, pi), "fuzzy"),
            "Similarity (%)": _percent(sc),
            "Char Similarity (%)": _percent(char_sim),
            "Token Similarity (%)": _percent(token_sim),
            "Containment (%)": _percent(contain_score),
            "Gold Page": golds[gi].get("page"),
            "Pred Page": preds[pi].get("page"),
            "Gold ID": golds[gi].get("id"),
            "Pred ID": preds[pi].get("id"),
            "Gold Context": clean_for_excel(gold_ctx_raw, max_ctx),
            "Pred Context": clean_for_excel(pred_ctx_raw, max_ctx),
            "_Gold Context (full)": gold_ctx_raw,
            "_Pred Context (full)": pred_ctx_raw,
        })
    return rows

def _build_unmatched_rows_with_candidates(golds, preds, unmatched_gold, k=TOPK_FOR_UNMATCHED, max_ctx=MAX_CONTEXT_CHARS):
    rows = []
    for gi in unmatched_gold:
        gctx_n = golds[gi]["ctx"]; gpage = golds[gi].get("page")
        scored = []
        for pi, p in enumerate(preds):
            if not page_ok(gpage, p.get("page"), PAGE_SLACK):
                continue
            pctx_n = p["ctx"]
            cs = sim_char(gctx_n, pctx_n)
            jc = jaccard(gctx_n, pctx_n)
            ct = containment(gctx_n, pctx_n)
            s  = 0.6*cs + 0.4*jc
            scored.append((s, cs, jc, ct, pi))
        scored.sort(reverse=True, key=lambda x: x[0])

        gold_row = {
            "Gold Index": gi,
            "Gold Page": golds[gi].get("page"),
            "Gold ID": golds[gi].get("id"),
            "Gold Context": clean_for_excel(golds[gi]["raw"].get("context",""), max_ctx),
        }
        top = scored[:k] if scored else []
        if not top:
            rows.append({**gold_row,
                         "Cand #": "", "Pred Index": "", "Pred Page": "", "Pred ID": "",
                         "Similarity (%)": "", "Char Sim (%)": "", "Token Sim (%)": "", "Containment (%)": "",
                         "Pred Context": ""})
        else:
            for rank, (s, cs, jc, ct, pi) in enumerate(top, start=1):
                rows.append({**gold_row,
                             "Cand #": rank,
                             "Pred Index": pi,
                             "Pred Page": preds[pi].get("page"),
                             "Pred ID": preds[pi].get("id"),
                             "Similarity (%)": _percent(s),
                             "Char Sim (%)": _percent(cs),
                             "Token Sim (%)": _percent(jc),
                             "Containment (%)": _percent(ct),
                             "Pred Context": clean_for_excel(preds[pi]["raw"].get("context",""), max_ctx)})
    return rows

def write_xlsx(out_path, matches_rows, unmatched_rows):
    df_matches = pd.DataFrame(matches_rows)
    df_unmatched = pd.DataFrame(unmatched_rows)

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        df_matches.to_excel(writer, sheet_name="Matches", index=False)
        df_unmatched.to_excel(writer, sheet_name="Unmatched (Top-3)", index=False)

        # Format (bold headers, widths, wrap contexts)
        wb = writer.book

        def _format_sheet(ws, context_cols):
            # bold header
            for cell in ws[1]:
                cell.font = cell.font.copy(bold=True)
            # widths for non-context cols
            widths = {
                "A": 8,  "B": 14,
                "C": 16, "D": 16, "E": 16, "F": 16,
                "G": 10, "H": 10, "I": 10, "J": 10,
            }
            for col, w in widths.items():
                ws.column_dimensions[col].width = w
            # make context columns wide + wrapped
            for col_idx in context_cols:
                col_letter = ws.cell(row=1, column=col_idx).column_letter
                ws.column_dimensions[col_letter].width = 80
                for row in ws.iter_rows(min_row=2, min_col=col_idx, max_col=col_idx):
                    for cell in row:
                        cell.alignment = cell.alignment.copy(wrap_text=True, vertical="top")

        # Matches sheet
        ws_m = writer.sheets["Matches"]
        # Hide full context columns by default if present
        try:
            idx_full_g = df_matches.columns.get_loc("_Gold Context (full)") + 1
            idx_full_p = df_matches.columns.get_loc("_Pred Context (full)") + 1
            ws_m.column_dimensions[ws_m.cell(row=1, column=idx_full_g).column_letter].hidden = True
            ws_m.column_dimensions[ws_m.cell(row=1, column=idx_full_p).column_letter].hidden = True
        except Exception:
            pass
        # Visible context columns
        ctx_cols = []
        for name in ["Gold Context", "Pred Context"]:
            if name in df_matches.columns:
                ctx_cols.append(df_matches.columns.get_loc(name) + 1)
        _format_sheet(ws_m, ctx_cols)

        # Unmatched sheet
        ws_u = writer.sheets["Unmatched (Top-3)"]
        ctx_cols_u = []
        for name in ["Gold Context", "Pred Context"]:
            if name in df_unmatched.columns:
                ctx_cols_u.append(df_unmatched.columns.get_loc(name) + 1)
        _format_sheet(ws_u, ctx_cols_u)

# -------- Main (auto-run from extracted_triples) --------
if __name__ == "__main__":
    current_dir = os.path.abspath(os.getcwd())
    gold_file = os.path.join(os.path.dirname(current_dir), "MICROSOFT.json")
    pred_files = sorted(glob.glob(os.path.join(current_dir, "chunk_data_*.json")))
    out_dir = os.path.join(current_dir, "matched_csv")  # folder for the Excel files

    if not os.path.exists(gold_file):
        print(f"[ERROR] Gold file not found: {gold_file}")
        raise SystemExit(1)
    if not pred_files:
        print(f"[ERROR] No chunk_data_*.json found in {current_dir}")
        raise SystemExit(1)

    print("=== evaluate_fuzzy (context-only, multi-pass, page-aware) ===")
    print(f"Gold file : {gold_file}")
    print(f"Pred dir  : {current_dir}")
    print(f"Found     : {len(pred_files)} prediction file(s)")
    print(f"Params    : PAGE_SLACK={PAGE_SLACK}  CONTAIN={CONTAIN_THRESH}  FUZZY_HIGH={FUZZY_HIGH}  FUZZY_LOW={FUZZY_LOW}")
    print()
    os.makedirs(out_dir, exist_ok=True)

    golds = load_gold(gold_file)

    for pred_path in pred_files:
        preds = load_pred(pred_path)
        matches, um_g, um_p, match_methods = align_exact_contain_fuzzy(
            golds, preds,
            contain_thresh=CONTAIN_THRESH,
            fuzzy_high=FUZZY_HIGH,
            fuzzy_low=FUZZY_LOW,
            page_slack=PAGE_SLACK
        )
        avg_sim = (sum(sc for _,_,sc in matches) / len(matches)) if matches else 0.0

        base = safe_name(pred_path)

        # Terminal summary
        print(f"File: {pred_path}")
        print(f"  Gold sentences  : {len(golds)}")
        print(f"  Pred sentences  : {len(preds)}")
        print(f"  Matched pairs   : {len(matches)}")
        print(f"  Unmatched gold  : {len(um_g)}")
        print(f"  Unmatched pred  : {len(um_p)}")
        print(f"  Avg similarity  : {avg_sim:.3f}")
        print()

        # Terminal tables (optional)
        if SHOW_TOP_MATCHES:
            # sort by score desc for display
            method_rank = {"exact": 0, "containment": 1, "fuzzy_high": 2, "fuzzy_low": 3}
            display_matches = sorted(
                matches,
                key=lambda m: (-(m[2]), method_rank.get(match_methods.get((m[0], m[1]), "fuzzy_low"), 99))
            )[:SHOW_TOP_MATCHES]
            print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
            print(f"{'#':>3}  {'Sim':>6}  {'Gold Context':<{CTX_COL_WIDTH}}  {'Pred Context':<{CTX_COL_WIDTH}}")
            print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
            for idx, (gi, pi, sc) in enumerate(display_matches, start=1):
                gtxt = shorten(golds[gi]["raw"].get("context",""), CTX_COL_WIDTH)
                ptxt = shorten(preds[pi]["raw"].get("context",""), CTX_COL_WIDTH)
                print(f"{idx:>3}  {sc:6.3f}  {gtxt:<{CTX_COL_WIDTH}}  {ptxt:<{CTX_COL_WIDTH}}")
            print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
            print()

        if SHOW_TOP_NEARMISS and um_g:
            # compute best candidate per unmatched gold and sort
            rows = []
            for gi in um_g:
                gctx = golds[gi]["ctx"]; gpage = golds[gi].get("page")
                best = (-1.0, None)
                for pi, p in enumerate(preds):
                    if not page_ok(gpage, p.get("page"), PAGE_SLACK):
                        continue
                    s = hybrid_sim(gctx, p["ctx"], alpha=0.6)
                    if s > best[0]:
                        best = (s, pi)
                rows.append((best[0], gi, best[1]))
            rows.sort(reverse=True, key=lambda r: r[0])
            rows = rows[:SHOW_TOP_NEARMISS]

            if rows:
                print("Closest non-matches (gold vs best candidate):")
                print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
                print(f"{'#':>3}  {'Best':>6}  {'Gold Context':<{CTX_COL_WIDTH}}  {'Best Candidate (Pred)':<{CTX_COL_WIDTH}}")
                print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
                for idx, (score, gi, pi) in enumerate(rows, start=1):
                    gtxt = shorten(golds[gi]["raw"].get("context",""), CTX_COL_WIDTH)
                    ptxt = shorten(preds[pi]["raw"].get("context",""), CTX_COL_WIDTH) if pi is not None else ""
                    print(f"{idx:>3}  {score:6.3f}  {gtxt:<{CTX_COL_WIDTH}}  {ptxt:<{CTX_COL_WIDTH}}")
                print("-" * (10 + 7 + 2*CTX_COL_WIDTH))
                print()

        # Excel report (only)
        match_rows = _build_match_rows(matches, golds, preds, match_methods, max_ctx=MAX_CONTEXT_CHARS)
        unmatched_rows = _build_unmatched_rows_with_candidates(golds, preds, um_g, k=TOPK_FOR_UNMATCHED, max_ctx=MAX_CONTEXT_CHARS)
        out_xlsx = os.path.join(out_dir, f"evaluation_{base}.xlsx")
        write_xlsx(out_xlsx, match_rows, unmatched_rows)
        print(f"  Wrote Excel → {out_xlsx}\n")