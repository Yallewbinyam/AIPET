#!/bin/bash
# =============================================================
# AIPET Cloud — Stop Script
# =============================================================
PID="/tmp/aipet_cloud.pid"

if [ -f "$PID" ]; then
    echo "[*] Stopping AIPET Cloud..."
    kill $(cat "$PID") 2>/dev/null
    rm -f "$PID"
    echo "[+] AIPET Cloud stopped"
else
    echo "[*] No running instance found"
    pkill -f "gunicorn.*app_cloud" 2>/dev/null || true
    echo "[+] Done"
fi
