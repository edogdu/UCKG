#!/bin/bash
set -e

# Get the directory where this script is located (pipelines/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Root of fine-tuning folder
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
# Working dir for output
WORKING_DIR="$(pwd)"

echo "=== Step 1: Extract Raw Data (Neo4j -> JSONL) ==="
python3 "$SCRIPT_DIR/extract_uckg_raw.py" --output "$SCRIPT_DIR/raw_data.jsonl" --limit 1000

echo "=== Step 2: Filter Properties (Keep only Name, Desc, Example) ==="
python3 "$SCRIPT_DIR/filter_uckg_data.py" --input "$SCRIPT_DIR/raw_data.jsonl" --output "$SCRIPT_DIR/filtered_data.jsonl"

echo "=== Step 3: Clean Data (Parse JSON strings, Final Cleanup) ==="
python3 "$SCRIPT_DIR/clean_uckg_data.py" --input "$SCRIPT_DIR/filtered_data.jsonl" --output "$SCRIPT_DIR/clean_data.jsonl"

echo "=== Step 4: Load to GraphGen (JSONL -> KuzuDB) ==="
PYTHONPATH="$PROJECT_ROOT" python3 "$SCRIPT_DIR/load_rich_atomic.py" --input "$SCRIPT_DIR/clean_data.jsonl" --dir "$PROJECT_ROOT/cache"

echo "=== ETL Pipeline Complete! ==="
echo "Graph data is staged in $PROJECT_ROOT/cache/graph_kuzu and ready for generation."
