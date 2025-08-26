#!/usr/bin/env python3
from __future__ import annotations
import os, json
from pathlib import Path
from typing import Dict, Any, Tuple, List
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).parent.resolve()
WORKDIR = BASE_DIR / "output" / "CTI-HAL"
ANALYSIS_OUT = WORKDIR / "analysis"
FIG_DIR = ANALYSIS_OUT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

# Hit@k configuration aligned with similarity_analysis.py
_HIT_KS_ENV = os.getenv("SIM_HIT_KS", "1,3,5")
HIT_KS: Tuple[int, ...] = tuple(sorted({int(x) for x in _HIT_KS_ENV.split(',') if x.strip().isdigit()})) or (1, 3, 5)

# Helper: support group summaries keyed by int or str("k")
def _k(bucket: Dict[str, Any], k: int) -> Dict[str, Any]:
    return bucket.get(k) or bucket.get(str(k)) or {}


def _load_json(p: Path) -> Any:
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_summaries():
    group = _load_json(ANALYSIS_OUT / "group_summary.json")
    overall = _load_json(ANALYSIS_OUT / "overall_summary.json")
    leaderboard = _load_json(ANALYSIS_OUT / "leaderboard.json")
    return group, overall, leaderboard


def bar_group_metric(group: Dict[str, Any], metric_key: str, title: str, fname: str) -> None:
    groups = sorted(group.keys())
    for k in HIT_KS:
        vals = [_k(group[g], k).get(metric_key, 0.0) for g in groups]
        plt.figure()
        plt.title(f"{title} (k={k})")
        plt.ylabel(metric_key)
        plt.xlabel("Group")
        plt.xticks(rotation=45, ha="right")
        plt.bar(groups, vals)
        plt.tight_layout()
        plt.savefig(FIG_DIR / f"{fname}_k{k}.png")
        plt.close()


def bar_group_precision_spurious(group: Dict[str, Any], fname_prefix: str) -> None:
    groups = sorted(group.keys())
    for k in HIT_KS:
        prec = [_k(group[g], k).get("precision", 0.0) for g in groups]
        spur = [_k(group[g], k).get("spurious", 0.0) for g in groups]
        x = range(len(groups))
        width = 0.35
        plt.figure()
        plt.title(f"Precision vs Spurious @k={k} by Group")
        plt.xlabel("Group")
        plt.xticks(ticks=list(x), labels=groups, rotation=45, ha="right")
        plt.ylabel("ratio")
        plt.bar([xi - width/2 for xi in x], prec, width)
        plt.bar([xi + width/2 for xi in x], spur, width)
        plt.legend(["precision", "spurious"])  # fixed typo
        plt.tight_layout()
        plt.savefig(FIG_DIR / f"{fname_prefix}_k{k}.png")
        plt.close()


def scatter_precision_recall(leaderboard: List[Dict[str, Any]], fname: str, label_top_n: int = 8) -> None:
    xs, ys, sizes = [], [], []
    for row in leaderboard:
        xs.append(row["precision"])
        ys.append(row["recall"])
        sizes.append(max(10.0, float(row.get("queries", 0)) ** 0.5 * 15.0))
    plt.figure()
    plt.title("Per-PDF Precision vs Recall (size ~ sqrt(queries))")
    plt.xlabel("precision")
    plt.ylabel("recall")
    plt.scatter(xs, ys, s=sizes)
    plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIG_DIR / f"{fname}.png")
    plt.close()


def hist_f1(leaderboard: List[Dict[str, Any]], fname: str, bins: int = 20) -> None:
    vals = [r["f1"] for r in leaderboard]
    plt.figure()
    plt.title("F1 Distribution (all PDFs)")
    plt.xlabel("F1")
    plt.ylabel("count")
    plt.hist(vals, bins=bins)
    plt.tight_layout()
    plt.savefig(FIG_DIR / f"{fname}.png")
    plt.close()


def coverage_at_k(group: Dict[str, Any], leaderboard: List[Dict[str, Any]], fname_prefix: str) -> None:
    """
    Approximate coverage using per-PDF ids_at_k union sizes.
    For each group and k: union of matched_ids@k size / union of GT for that group's PDFs.
    """
    per_group_gt: Dict[str, set] = {}
    per_group_matched_k: Dict[str, Dict[int, set]] = {}
    for row in leaderboard:
        g = row["group"]
        report_path = (ANALYSIS_OUT / g / Path(row["pdf"]).stem / "entity_scoring.json")
        if not report_path.exists():
            continue
        obj = _load_json(report_path)
        gt_ids = set(obj.get("ground_truth_attack_ids", []))
        per_group_gt.setdefault(g, set()).update(gt_ids)
        ids_at_k = obj.get("ids_at_k", {})
        for k in HIT_KS:
            mk = set(ids_at_k.get(str(k), {}).get("matched_ids", []))
            per_group_matched_k.setdefault(g, {}).setdefault(k, set()).update(mk)

    groups = sorted(per_group_gt.keys())
    for k in HIT_KS:
        cov = []
        for g in groups:
            gt = per_group_gt.get(g, set())
            mk = per_group_matched_k.get(g, {}).get(k, set())
            ratio = (len(mk) / len(gt)) if gt else 0.0
            cov.append(ratio)
        plt.figure()
        plt.title(f"Coverage@{k} (union matched IDs / union GT) by Group")
        plt.xlabel("Group")
        plt.ylabel("coverage")
        plt.xticks(rotation=45, ha="right")
        plt.bar(groups, cov)
        plt.tight_layout()
        plt.savefig(FIG_DIR / f"{fname_prefix}_k{k}.png")
        plt.close()


def queries_per_group(leaderboard: List[Dict[str, Any]], fname: str) -> None:
    by_group: Dict[str, int] = {}
    for r in leaderboard:
        by_group[r["group"]] = by_group.get(r["group"], 0) + int(r.get("queries", 0))
    groups = sorted(by_group.keys())
    vals = [by_group[g] for g in groups]
    plt.figure()
    plt.title("Eligible Queries by Group")
    plt.xlabel("Group")
    plt.ylabel("queries")
    plt.xticks(rotation=45, ha="right")
    plt.bar(groups, vals)
    plt.tight_layout()
    plt.savefig(FIG_DIR / f"{fname}.png")
    plt.close()


def main() -> None:
    group, overall, leaderboard = _read_summaries()
    bar_group_metric(group, "hit", "Hit Rate by Group", "hit_rate_by_group")
    bar_group_precision_spurious(group, "prec_vs_spur_by_group")
    scatter_precision_recall(leaderboard, "scatter_precision_recall")
    hist_f1(leaderboard, "hist_f1")
    coverage_at_k(group, leaderboard, "coverage_by_group")
    queries_per_group(leaderboard, "queries_per_group")
    print(f"[Charts] Wrote figures to: {FIG_DIR}")


if __name__ == "__main__":
    main()