#!/bin/bash
# Monitor evaluation progress

LOG_FILE="evaluation_run_clean.log"

echo "=========================================="
echo "Text-to-Cypher Evaluation Progress Monitor"
echo "=========================================="
echo ""

# Check if process is running
PID=$(pgrep -f "evaluate_models.py")
if [ -z "$PID" ]; then
    echo "⚠️  Evaluation process not running"
else
    echo "✅ Evaluation running (PID: $PID)"
fi

echo ""
echo "Progress:"
echo "----------"

# Get latest progress from log
if [ -f "$LOG_FILE" ]; then
    PROGRESS=$(grep -a "Evaluating" "$LOG_FILE" | tail -1)
    if [ ! -z "$PROGRESS" ]; then
        echo "$PROGRESS"
        
        # Extract numbers for calculation
        CURRENT=$(echo "$PROGRESS" | grep -oE '[0-9]+it' | grep -oE '[0-9]+')
        if [ ! -z "$CURRENT" ]; then
            TOTAL=388
            PERCENT=$((CURRENT * 100 / TOTAL))
            REMAINING=$((TOTAL - CURRENT))
            
            # Extract time per iteration
            TIME_PER_IT=$(echo "$PROGRESS" | grep -oE '[0-9]+\.[0-9]+s/it' | grep -oE '[0-9]+\.[0-9]+')
            if [ ! -z "$TIME_PER_IT" ]; then
                ETA_SECONDS=$(echo "$REMAINING * $TIME_PER_IT" | bc)
                ETA_MINUTES=$(echo "$ETA_SECONDS / 60" | bc)
                
                echo ""
                echo "📊 Statistics:"
                echo "   Completed: $CURRENT / $TOTAL ($PERCENT%)"
                echo "   Remaining: $REMAINING questions"
                echo "   Speed: ${TIME_PER_IT}s per question"
                echo "   ETA: ~${ETA_MINUTES} minutes"
            fi
        fi
    else
        echo "No progress data yet..."
    fi
    
    echo ""
    echo "Recent activity (last 5 lines):"
    echo "--------------------------------"
    tail -5 "$LOG_FILE"
else
    echo "Log file not found: $LOG_FILE"
fi

echo ""
echo "=========================================="
echo "To monitor live: tail -f $LOG_FILE"
echo "To check again: ./monitor_progress.sh"
echo "=========================================="

