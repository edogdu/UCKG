#!/bin/bash

# Check evaluation progress

echo "================================"
echo "Enhanced T2CSS Evaluation Progress"
echo "================================"
echo ""

LOG_FILE="evaluation/evaluation_run.log"

if [ -f "$LOG_FILE" ]; then
    echo "📊 Recent output:"
    echo "----------------"
    tail -20 "$LOG_FILE"
    echo ""
    echo "----------------"
    echo ""
    
    # Count progress if tqdm is in output
    if grep -q "Evaluating:" "$LOG_FILE"; then
        echo "✅ Evaluation is running..."
        echo ""
        LAST_LINE=$(grep "Evaluating:" "$LOG_FILE" | tail -1)
        echo "Last progress: $LAST_LINE"
    fi
    
    # Check if complete
    if grep -q "EVALUATION COMPLETE" "$LOG_FILE"; then
        echo ""
        echo "🎉 Evaluation is COMPLETE!"
        echo ""
        echo "📁 Results files:"
        ls -lh evaluation/results_t2css_enhanced.csv 2>/dev/null
        ls -lh evaluation/report_t2css_enhanced.md 2>/dev/null
    fi
else
    echo "❌ Log file not found. Evaluation may not have started yet."
fi

echo ""
echo "To view full log:"
echo "  tail -f $LOG_FILE"
echo ""
echo "To check if process is running:"
echo "  ps aux | grep evaluate_t2css_only"
