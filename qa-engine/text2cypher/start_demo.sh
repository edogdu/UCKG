#!/bin/bash

echo "🚀 Starting Text2Cypher V4 Demo..."
echo "=================================="

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        echo "✅ Port $1 is already in use"
        return 0
    else
        echo "❌ Port $1 is not in use"
        return 1
    fi
}

# Start Backend Server
echo "📡 Starting Backend Server (Port 8001)..."
cd backend
if check_port 8001; then
    echo "Backend already running on port 8001"
else
    echo "Starting backend server..."
    python3 main.py &
    BACKEND_PID=$!
    echo "Backend started with PID: $BACKEND_PID"
    sleep 3
fi

# Start Frontend Server
echo "🎨 Starting Frontend Server (Port 3000)..."
cd ../frontend
if check_port 3000; then
    echo "Frontend already running on port 3000"
else
    echo "Starting frontend server..."
    npm start &
    FRONTEND_PID=$!
    echo "Frontend started with PID: $FRONTEND_PID"
    sleep 5
fi

echo ""
echo "🎉 Text2Cypher V4 Demo is starting up!"
echo "======================================"
echo "Backend API:  http://localhost:8001"
echo "Frontend UI:  http://localhost:3000"
echo "API Docs:     http://localhost:8001/docs"
echo ""
echo "Press Ctrl+C to stop both servers"
echo ""

# Wait for user to stop
wait