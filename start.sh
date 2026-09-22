#!/usr/bin/env bash

# Resolve script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=========================================="
echo " Starting ProofStrike Security Platform   "
echo "=========================================="

# 1. Start Backend in backend directory
echo "Starting Backend API on http://127.0.0.1:8000..."
(
  cd "$DIR/backend" || exit 1
  export PYTHONPATH="$DIR/backend"
  ./venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
) &
BACKEND_PID=$!

# Trap signals to cleanup background backend process
cleanup() {
  echo ""
  echo "Shutting down ProofStrike..."
  kill $BACKEND_PID 2>/dev/null
  exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Wait a second for backend to bind port 8000
sleep 2

# 2. Start Frontend
echo "Starting Frontend UI on http://localhost:5173..."
cd "$DIR/frontend" || exit 1
npm run dev
