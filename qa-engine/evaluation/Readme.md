# Multi-Evaluation Tool

A comprehensive evaluation tool that assesses summaries against source text using multiple metrics: **ROUGE**, **BLEU**, **BERTScore**, and **QAFactEval**.

## Installation

```bash
cd qa-engine/evaluation
pip install -r requirements.txt
```

## Quick Start

```bash
# List available sample IDs in the dataset
python multi-eval.py --list-ids

# Evaluate a specific sample by ID
python multi-eval.py --id 1

# Evaluate ALL samples and save to CSV (with progress bar)
python multi-eval.py --all-ids --save-csv results.csv

# Evaluate ALL samples and save to JSON
python multi-eval.py --all-ids --save-json results.json

# Manual evaluation with text files
python multi-eval.py --source-file source.txt --summary-file summary.txt
```

## Usage

### Method 1: Explore Dataset

List all available samples in the dataset:

```bash
# List IDs from default dataset
python multi-eval.py --list-ids

# List IDs from custom dataset
python multi-eval.py --list-ids --dataset path/to/dataset.json
```

This displays:
- Total number of questions
- Generation date and pipeline info
- All available sample IDs
- ID range (min-max)

### Method 2: Evaluate from Dataset (Recommended)  

Evaluate a specific sample from the evaluation dataset by ID:

```bash
# Use default dataset (evaluation_dataset.json in same directory)
python multi-eval.py --id 1

# Specify custom dataset path
python multi-eval.py --id 5 --dataset path/to/evaluation_dataset.json

# Disable plots
python multi-eval.py --id 1 --no-plots

# Custom title for plots
python multi-eval.py --id 1 --title "Evaluation Results"
```

This mode automatically extracts:
- **Question**: The question being asked
- **Summary**: The source/reference text (from `summary` field)
- **Response**: The generated response (from `response` field)
- **Metadata**: ID, question type, hop count, node information, etc.

### Method 3: Manual Text/Files

```bash
# Using text arguments
python multi-eval.py --source-text "..." --summary-text "..."

# Using files
python multi-eval.py --source-file source.txt --summary-file summary.txt

# Disable plots
python multi-eval.py --source-file source.txt --summary-file summary.txt --no-plots
```

## Arguments

### Standard Mode
- `--source-text`: Source text as string
- `--summary-text`: Summary text as string
- `--source-file`: Path to source text file
- `--summary-file`: Path to summary text file
- `--no-plots`: Disable visualization plots
- `--title`: Custom title for plots (default: "Evaluation")

### Dataset Mode
- `--id`: Sample ID from evaluation dataset (enables dataset mode)
- `--dataset`: Path to evaluation dataset JSON file (default: `evaluation_dataset.json`)
- `--list-ids`: List all available sample IDs in the dataset
- `--all-ids`: Evaluate all samples in the dataset (with progress bar)
- `--save-csv`: Path to save CSV results when using `--all-ids`
- `--save-json`: Path to save JSON results when using `--all-ids`

## Output

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
- `matplotlib>=3.6.0` and `seaborn>=0.12.0` (for plots, currently disabled)
- `qafacteval>=0.1.0` (for factual consistency evaluation)

## Notes

- NLTK automatically downloads `punkt_tab` tokenizer on first run (required for BLEU)
- BERTScore downloads the `microsoft/deberta-xlarge-mnli` model on first run (~1.5GB)
- QAFactEval downloads additional models (~2GB) if enabled
- Batch evaluation results are saved to CSV/JSON without printing large tables to console
- Progress bar uses ANSI color codes for terminal compatibility (works on Windows, Linux, macOS)