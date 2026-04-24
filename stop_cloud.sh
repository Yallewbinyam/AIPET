#!/bin/bash
# =============================================================
# AIPET Cloud — Stop Script
# =============================================================
# Stops Gunicorn, Celery worker, and Celery Beat gracefully.
# =============================================================

PROJECT_DIR="/home/binyam/AIPET"

GUNICORN_PID="$PROJECT_DIR/pids/gunicorn.pid"
WORKER_PID="$PROJECT_DIR/pids/celery_worker.pid"
BEAT_PID="$PROJECT_DIR/pids/celery_beat.pid"

# Legacy path (pre-D3 start_cloud.sh used /tmp/)
LEGACY_PID="/tmp/aipet_cloud.pid"

echo "[*] Stopping AIPET Cloud..."

_stop_pid() {
    local label="$1" pid_file="$2"
    if [ -f "$pid_file" ]; then
        PID=$(cat "$pid_file")
        if kill "$PID" 2>/dev/null; then
            echo "[+] $label stopped (pid $PID)"
        else
            echo "[~] $label pid $PID was already gone"
        fi
        rm -f "$pid_file"
    else
        echo "[~] No $label PID file found"
    fi
}

_stop_pid "Gunicorn"      "$GUNICORN_PID"
_stop_pid "Gunicorn"      "$LEGACY_PID"        # clean up legacy if present
_stop_pid "Celery worker" "$WORKER_PID"
_stop_pid "Celery Beat"   "$BEAT_PID"

# Belt-and-suspenders: kill any survivors
pkill -f "gunicorn.*app_cloud" 2>/dev/null && echo "[+] Gunicorn (pkill)" || true
pkill -f "celery.*aipet"       2>/dev/null && echo "[+] Celery (pkill)"   || true

# Remove Beat schedule file so next start is clean
rm -f "$PROJECT_DIR/celerybeat-schedule"

echo "[+] Done"
