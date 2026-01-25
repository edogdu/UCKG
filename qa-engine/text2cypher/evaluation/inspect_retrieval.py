"""
Inspect Enhanced T2CSS semantic schema retrieval (cosine similarity) on a dataset.

This script:
  - samples N questions per Category from a CSV dataset
  - embeds each question with Ollama embeddings
  - computes cosine similarity against the Enhanced T2CSS corpus embeddings
  - prints the top-K retrieved schema lines (rendered for the prompt) + scores
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

# Import pipeline internals (same file used by runtime)
from text2cypher.core.t2css_enhanced import (
    load_semantic_schema,
    build_maps,
    build_embedding_corpus,
    render_schema_line,
)
from text2cypher.core.embeddings import OllamaEmbeddings, batch_cosine_similarity


def read_dataset_rows(csv_path: Path) -> List[Dict[str, str]]:
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def group_questions_by_category(rows: List[Dict[str, str]]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = defaultdict(list)
    for r in rows:
        cat = (r.get("Category") or "").strip()
        q = (r.get("NaturalLanguageQuestion") or "").strip()
        if not cat or not q:
            continue
        grouped[cat].append(q)
    return dict(grouped)


def sample_per_category(
    grouped: Dict[str, List[str]],
    per_category: int,
    seed: int,
    categories: List[str] | None = None,
) -> List[Tuple[str, str]]:
    rng = random.Random(seed)
    out: List[Tuple[str, str]] = []

    cats = categories if categories else sorted(grouped.keys())
    for cat in cats:
        qs = grouped.get(cat, [])
        if not qs:
            continue
        n = min(per_category, len(qs))
        samples = rng.sample(qs, n) if len(qs) >= n else list(qs)
        out.extend([(cat, q) for q in samples])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dataset",
        type=str,
        default=str(
            Path(__file__).parent.parent / "dataset" / "technical_dataset_COMPLETION_clean.csv"
        ),
        help="Path to CSV dataset with Category and NaturalLanguageQuestion columns",
    )
    ap.add_argument("--per-category", type=int, default=2)
    ap.add_argument("--topk", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--ollama-url", type=str, default=None, help="Override OLLAMA_URL")
    ap.add_argument("--embed-model", type=str, default="nomic-embed-text")
    ap.add_argument(
        "--categories",
        type=str,
        default="",
        help="Comma-separated category names to restrict (default: all categories found)",
    )
    args = ap.parse_args()

    dataset_path = Path(args.dataset).expanduser().resolve()
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    rows = read_dataset_rows(dataset_path)
    grouped = group_questions_by_category(rows)
    if not grouped:
        raise RuntimeError("No (Category, NaturalLanguageQuestion) rows found in dataset")

    categories = [c.strip() for c in args.categories.split(",") if c.strip()] or None

    # Build the exact corpus that EnhancedT2CSS uses for retrieval
    sem = load_semantic_schema(None)
    label_map, rel_map = build_maps(sem)
    corpus_lines = build_embedding_corpus(sem)

    embedder = OllamaEmbeddings(model=args.embed_model, base_url=args.ollama_url)
    corpus_emb = embedder.encode(corpus_lines, normalize_embeddings=True)

    print("=" * 100)
    print("Enhanced T2CSS Retrieval Inspection")
    print(f"- dataset: {dataset_path}")
    print(f"- categories: {categories if categories else 'ALL'}")
    print(f"- per_category: {args.per_category}")
    print(f"- topk: {args.topk}")
    print(f"- embed_model: {args.embed_model}")
    print(f"- ollama_url: {embedder.base_url}")
    print(f"- corpus_size: {len(corpus_lines)} lines")
    print("=" * 100)

    samples = sample_per_category(grouped, args.per_category, args.seed, categories=categories)

    for idx, (cat, q) in enumerate(samples, 1):
        q_emb = embedder.encode(q, normalize_embeddings=True)
        sims = batch_cosine_similarity(q_emb, corpus_emb)
        top_idx = np.argsort(sims)[::-1][: args.topk]

        print("\n" + "-" * 100)
        print(f"[{idx}/{len(samples)}] Category: {cat}")
        print(f"Question: {q}")
        print("-" * 100)
        for rank, i in enumerate(top_idx, 1):
            raw = corpus_lines[int(i)]
            rendered = render_schema_line(raw, label_map, rel_map)
            print(f"{rank:02d}. {float(sims[int(i)]):.4f}  {rendered}")
            # Uncomment for debugging:
            # print(f"     RAW: {raw}")


if __name__ == "__main__":
    main()

