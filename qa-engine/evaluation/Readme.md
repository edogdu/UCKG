# Multi-Evaluation Toolkit

Evaluate summaries against their sources with **ROUGE**, **BLEU**, **BERTScore**, and optional **QAFactEval** factual checks. Batch mode flattens the metrics into CSV/JSON so downstream tooling (like the metric chart notebook) can pick them up immediately.

## Install

```bash
cd qa-engine/evaluation
pip install -r requirements.txt
```

## Quick Start

```bash
# 1. Inspect dataset coverage
python multi-eval.py --list-ids

# 2. Inspect a single sample (default dataset)
python multi-eval.py --id 1

# 3. Evaluate every sample and save metrics
python multi-eval.py --all-ids --save-csv new_result.csv
# (optional) Also emit JSON
python multi-eval.py --all-ids --save-json results.json

# 4. Manually score ad-hoc text files
python multi-eval.py --source-file source.txt --summary-file summary.txt
```

## Usage Patterns

### 1. Explore datasets

```bash
python multi-eval.py --list-ids
python multi-eval.py --list-ids --dataset path/to/dataset.json
```

You will see overall dataset metadata, available IDs, and ID ranges.

### 2. Evaluate dataset samples (recommended)

```bash
# Default dataset in this directory
python multi-eval.py --id 1

# Custom dataset path
python multi-eval.py --id 42 --dataset path/to/evaluation_dataset.json
```

This prints the question metadata plus all metric scores for the requested sample.

### 3. Batch mode for dashboards/analysis

```bash
python multi-eval.py --all-ids --save-csv new_result.csv
python multi-eval.py --all-ids --save-json results.json  # optional
```

Batch mode runs through the entire dataset with a progress bar and writes flattened metrics. The resulting `new_result.csv` is what `metric_chart.ipynb` expects by default.

### 4. Manual (non-dataset) evaluation

```bash
python multi-eval.py --source-text "..." --summary-text "..."
python multi-eval.py --source-file source.txt --summary-file summary.txt
```

## Arguments

### Standard Mode
- `--source-text`: Source text as string
- `--summary-text`: Summary text as string
- `--source-file`: Path to source text file
- `--summary-file`: Path to summary text file

### Dataset Mode
- `--id`: Sample ID from evaluation dataset
- `--dataset`: Path to evaluation dataset JSON file (default `evaluation_dataset.json`)
- `--list-ids`: List all available sample IDs
- `--all-ids`: Evaluate every sample in the dataset
- `--save-csv`: Path to save CSV results in `--all-ids` mode
- `--save-json`: Path to save JSON results in `--all-ids` mode

## Outputs

### Single Sample Evaluation (--id or manual mode)

The tool prints:

1. **Sample Metadata** (dataset mode only):
   - Question ID
   - Question Type
   - Hop Count
   - First Node
   - Question preview (first 200 characters)

2. **Metric Scores**:
   - **ROUGE F1**: R1, R2, RLsum (precision, recall, F1)
   - **BLEU**: BLEU-1, BLEU-2, BLEU-3, BLEU-4 scores
   - **BERTScore**: Precision, Recall, F1 (rescaled)
   - **BERTScore (precision-only)**: Precision metric only
   - **QAFactEval**: Factual consistency score (if available)

### Batch Evaluation (--all-ids)

When evaluating all samples:
- **Progress Bar**: Hacker-green progress bar showing evaluation progress with percentage
- **CSV Export**: Saves results to CSV with columns:
  - `id`, `rouge1_f1`, `rouge2_f1`, `rougeLsum_f1`
  - `bleu1`, `bleu2`, `bleu3`, `bleu4`
  - `bertscore_p`, `bertscore_r`, `bertscore_f1`, `bertscore_precision_only`
  - `qafacteval_score`, `qafacteval_available`
- **JSON Export**: Saves results as JSON array with full metric data

## Example Output

### Single Sample Evaluation

```
Loading dataset: evaluation_dataset.json

============================================================
SAMPLE METADATA
============================================================
Question ID: 1
Question Type: simple
Hop Count: 1
First Node: UcoexObservedExample

Question:
  What vulnerability identifier relates to race conditions...

Evaluating summary (main metrics only)...

============================================================
MAIN METRICS
============================================================
ROUGE F1 -> R1: 0.245  R2: 0.123  RLsum: 0.198
BLEU -> 1: 0.341  2: 0.189  3: 0.123  4: 0.089
BERTScore -> P: 0.892  R: 0.756  F1: 0.818
BERTScore (precision-only): 0.892
QAFactEval: available
```

### Batch Evaluation

```
Loading dataset: evaluation_dataset.json

Evaluating 1000 samples...

Evaluating: 100%|████████████████| 1000/1000 [05:23<00:00, 3.10sample/s]

Saved CSV: results.csv
```

## Metric Chart Notebook

Once `new_result.csv` exists you can produce metric breakdown visuals without touching the Python script.

1. Make sure `new_result.csv` (or another CSV produced by `--all-ids`) lives beside the notebook.  
   ```bash
   python multi-eval.py --all-ids --save-csv new_result.csv
   ```
2. Install the visualization extras if they are not already present:
   ```bash
   pip install pandas matplotlib seaborn numpy
   ```
3. Launch Jupyter (or VS Code / Cursor notebook support) and open `metric_chart.ipynb`.
4. The first cell defines `RESULT_CSV`—point it to another file if needed, then run the notebook sequentially. It will:
   - Load and validate the CSV
   - Tag samples into Types 0/1/2 (IDs 1–50/51–100/101–150 by default)
   - Compute mean ROUGE/BLEU/BERTScore per type
   - Render horizontal bar charts plus a combined comparison chart

The notebook saves no artifacts today, but you can adapt the plotting cells to export PNGs if required.

## Features

### Metrics Supported

1. **ROUGE** (Recall-Oriented Understudy for Gisting Evaluation)
   - ROUGE-1: Unigram overlap
   - ROUGE-2: Bigram overlap
   - ROUGE-Lsum: Longest common subsequence

2. **BLEU** (Bilingual Evaluation Understudy)
   - BLEU-1 through BLEU-4 with sentence-level smoothing

3. **BERTScore**
   - Precision, Recall, and F1 scores
   - Uses `microsoft/deberta-xlarge-mnli` model
   - Rescaled with baseline for interpretability

4. **QAFactEval** (Optional)
   - QA-based factual consistency evaluation
   - Requires additional installation

### Progress Bar

- **Hacker-green colored progress bar** for batch evaluations
- Shows percentage completion and processing speed
- Works with or without `tqdm` library (fallback implementation included)

## Requirements

### Core Dependencies
- `nltk>=3.7` (with `punkt_tab` tokenizer)
- `rouge-score>=0.1.2`
- `bert-score>=0.3.11`

### Optional Dependencies
- `pandas>=1.5.0` (for CSV/JSON export)
- `tqdm>=4.64.0` (for enhanced progress bar)
- `qafacteval>=0.1.0` (for factual consistency evaluation)
- Visualization stack (`matplotlib`, `seaborn`, `numpy`) for `metric_chart.ipynb`

## Notes

- NLTK automatically downloads `punkt_tab` tokenizer on first run (required for BLEU)
- BERTScore downloads the `microsoft/deberta-xlarge-mnli` model on first run (~1.5GB)
- QAFactEval downloads additional models (~2GB) if enabled
- Batch evaluation results are saved to CSV/JSON without printing large tables to console
- Progress bar uses ANSI color codes for terminal compatibility (works on Windows, Linux, macOS)
- Visualization now lives solely in `metric_chart.ipynb`, keeping the CLI script fast and dependency-light