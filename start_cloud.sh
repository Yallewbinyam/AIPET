#!/bin/bash
# =============================================================
# AIPET Cloud — Production Startup Script
# =============================================================
# What this script does:
#   1. Activates the Python virtual environment
#   2. Sets production environment variables
#   3. Starts Gunicorn with the correct config
#   4. Logs output to /tmp/aipet_cloud.log
#
# Usage:
#   ./start_cloud.sh          start the server
#   ./stop_cloud.sh           stop the server
# =============================================================

set -e
export DATABASE_URL="postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"

PROJECT_DIR="/home/binyam/AIPET"
VENV="$PROJECT_DIR/venv/bin"
LOG="/tmp/aipet_cloud.log"
PID="/tmp/aipet_cloud.pid"

echo "============================================================"
echo "  AIPET Cloud — Starting Production Server"
echo "============================================================"

# Check virtual environment exists
if [ ! -f "$VENV/python3" ]; then
    echo "ERROR: Virtual environment not found at $VENV"
    echo "Run: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
source "$VENV/activate"

# Set environment
export FLASK_ENV=production
export PYTHONPATH="$PROJECT_DIR"

# Change to project directory
cd "$PROJECT_DIR"

# Stop any existing instance
if [ -f "$PID" ]; then
    echo "[*] Stopping existing instance..."
    kill $(cat "$PID") 2>/dev/null || true
    rm -f "$PID"
    sleep 2
fi

echo "[*] Starting Gunicorn..."
nohup "$VENV/gunicorn" \
    --config dashboard/backend/gunicorn_config.py \
    --pid "$PID" \
    "dashboard.backend.app_cloud:app" \
    > "$LOG" 2>&1 &

sleep 3

# Verify server started
if curl -s http://localhost:5001/api/health > /dev/null 2>&1; then
    echo "[+] AIPET Cloud started successfully"
    echo "[+] API:  http://localhost:5001"
    echo "[+] Log:  $LOG"
    echo "[+] PID:  $(cat $PID 2>/dev/null || echo unknown)"
else
    echo "[-] ERROR: Server failed to start"
    echo "[-] Check log: $LOG"
    exit 1
fi

echo "============================================================"
