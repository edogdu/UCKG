# Multi-Evaluation Tool

This tool evaluates summaries against source text using multiple metrics: ROUGE, BLEU, BERTScore, and QAFactEval.

## Installation

```bash
cd qa-engine/evaluation
pip install -r requirements.txt
```

## Quick Start

```bash
# List available sample IDs in the dataset
python multi-eval.py --list-ids

# Evaluate sample ID 1
python multi-eval.py --id 1

# Disable plots for faster evaluation
python multi-eval.py --id 1 --no-plots
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
- **Context**: The source/reference text (from `context` field)
- **Response**: The generated summary (from `response` field)
- **Metadata**: ID, mode, difficulty, hop_count, node types, etc.

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

## Output

The tool prints:
1. **Sample Metadata** (dataset mode only):
   - Question ID, Mode, Difficulty
   - Hop Count, Number of Sources
   - Node Types
   - Question preview

2. **Metric Scores**:
   - ROUGE F1 (R1, R2, RLsum)
   - BLEU scores (1-4 grams)
   - BERTScore (Precision, Recall, F1)
   - BERTScore (precision-only)
   - QAFactEval (if available)

3. **Visualizations** (optional):
   - Bar charts for ROUGE, BLEU, and BERTScore metrics

## Example Output

```
Loading dataset: evaluation_dataset.json

============================================================
SAMPLE METADATA
============================================================
Question ID: 1
Mode: graphrag
Difficulty: 1
Source File: first 1 hop.json
Hop Count: 1
Number of Sources: 2
Node Types: UcoexObservedExample

Question:
  What vulnerability identifier relates to race conditions...

============================================================
MAIN METRICS
============================================================
ROUGE F1 -> R1: 0.245  R2: 0.123  RLsum: 0.198
BLEU -> 1: 0.341  2: 0.189  3: 0.123  4: 0.089
BERTScore -> P: 0.892  R: 0.756  F1: 0.818
BERTScore (precision-only): 0.892
QAFactEval: available
```

## Notes

- BERTScore uses `microsoft/deberta-xlarge-mnli` model (downloads on first run)
- QAFactEval requires additional installation and downloads heavy models
- NLTK downloads required data automatically on first run
- Plots are non-blocking and can be saved to file if display is unavailable