#!/bin/bash
# =============================================================
# AIPET Cloud — Production Startup Script
# =============================================================
# Starts three processes:
#   1. Gunicorn (Flask web server)
#   2. Celery worker  (background tasks: scans, NVD sync, ML retrain)
#   3. Celery Beat    (periodic task scheduler)
#
# Dev vs production model
# -----------------------
# On PRODUCTION hosts: Celery worker and Beat are managed by systemd
# via deploy/systemd/aipet-celery-worker.service and
# deploy/systemd/aipet-celery-beat.service (see deploy/systemd/INSTALL.md).
# When those services are active, this script detects them and skips
# the nohup launch — systemd owns those processes.
#
# On DEV (this script's primary mode): the systemd services are not
# installed, so Celery is launched as nohup background processes with
# PID files under pids/ and logs under logs/.
#
# Usage:
#   ./start_cloud.sh          start all services
#   ./stop_cloud.sh           stop all services
# =============================================================

set -e
export DATABASE_URL="postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
export REDIS_URL="redis://localhost:6379/0"

PROJECT_DIR="/home/byall/AIPET"
VENV="$PROJECT_DIR/venv/bin"

mkdir -p "$PROJECT_DIR/logs" "$PROJECT_DIR/pids"

GUNICORN_LOG="$PROJECT_DIR/logs/gunicorn.log"
GUNICORN_PID="$PROJECT_DIR/pids/gunicorn.pid"

WORKER_LOG="$PROJECT_DIR/logs/celery_worker.log"
WORKER_PID="$PROJECT_DIR/pids/celery_worker.pid"

BEAT_LOG="$PROJECT_DIR/logs/celery_beat.log"
BEAT_PID="$PROJECT_DIR/pids/celery_beat.pid"

echo "============================================================"
echo "  AIPET Cloud — Starting All Services"
echo "============================================================"

# Check virtual environment
if [ ! -f "$VENV/python3" ]; then
    echo "ERROR: Virtual environment not found at $VENV"
    echo "Run: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

source "$VENV/activate"
export FLASK_ENV=production
export PYTHONPATH="$PROJECT_DIR"
cd "$PROJECT_DIR"

# ── Stop any existing instances ────────────────────────────────────────────
for PID_FILE in "$GUNICORN_PID" "$WORKER_PID" "$BEAT_PID"; do
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
done
# Belt-and-suspenders: also kill by name in case PID files are stale
pkill -f "gunicorn.*app_cloud" 2>/dev/null || true
pkill -f "celery.*aipet" 2>/dev/null || true
sleep 2

# ── Check Redis is reachable before launching Celery ──────────────────────
echo "[*] Checking Redis..."
if ! redis-cli ping > /dev/null 2>&1; then
    echo "ERROR: Redis is not reachable (redis-cli ping failed)."
    echo "       Start Redis before launching AIPET Cloud."
    echo "       Gunicorn will still start; Celery processes will NOT."
    SKIP_CELERY=1
else
    echo "[+] Redis OK"
    SKIP_CELERY=0
fi

# ── 1. Start Gunicorn ─────────────────────────────────────────────────────
echo "[*] Starting Gunicorn..."
nohup "$VENV/gunicorn" \
    --config dashboard/backend/gunicorn_config.py \
    --pid "$GUNICORN_PID" \
    "dashboard.backend.app_cloud:app" \
    > "$GUNICORN_LOG" 2>&1 &

sleep 3

if curl -s http://localhost:5001/api/health > /dev/null 2>&1; then
    echo "[+] Gunicorn started (pid $(cat "$GUNICORN_PID" 2>/dev/null || echo '?'))"
else
    echo "[-] ERROR: Gunicorn failed to start — check $GUNICORN_LOG"
    exit 1
fi

# ── 2 & 3. Start Celery processes ─────────────────────────────────────────
if [ "$SKIP_CELERY" -eq 1 ]; then
    echo "[!] Skipping Celery (Redis unavailable)"
else
    # ── Detect if systemd is managing Celery (production mode) ───────────────
    WORKER_SYSTEMD=0
    BEAT_SYSTEMD=0
    if systemctl is-active --quiet aipet-celery-worker.service 2>/dev/null; then
        echo "[+] Celery worker managed by systemd (aipet-celery-worker.service) — skipping nohup launch"
        WORKER_SYSTEMD=1
    fi
    if systemctl is-active --quiet aipet-celery-beat.service 2>/dev/null; then
        echo "[+] Celery Beat managed by systemd (aipet-celery-beat.service) — skipping nohup launch"
        BEAT_SYSTEMD=1
    fi

    # ── Dev fallback: nohup launch if systemd services are not active ──────
    # Remove stale Beat schedule file to prevent duplicate scheduling
    rm -f "$PROJECT_DIR/celerybeat-schedule"

    if [ "$WORKER_SYSTEMD" -eq 0 ]; then
        echo "[*] Starting Celery worker (dev mode — nohup)..."
        nohup "$VENV/celery" \
            -A dashboard.backend.celery_app \
            worker \
            --loglevel=info \
            -Q scans,celery \
            -n aipet-worker@%h \
            --pidfile="$WORKER_PID" \
            > "$WORKER_LOG" 2>&1 &
        sleep 2
        echo "[+] Celery worker started"
    fi

    # Guard: refuse to start Beat if a PID file exists and the process is alive
    if [ "$BEAT_SYSTEMD" -eq 0 ]; then
        if [ -f "$BEAT_PID" ] && kill -0 "$(cat "$BEAT_PID")" 2>/dev/null; then
            echo "[!] Celery Beat already running (pid $(cat "$BEAT_PID")) — skipping"
        else
            echo "[*] Starting Celery Beat (dev mode — nohup)..."
            nohup "$VENV/celery" \
                -A dashboard.backend.celery_app \
                beat \
                --loglevel=info \
                --pidfile="$BEAT_PID" \
                --schedule="$PROJECT_DIR/celerybeat-schedule" \
                > "$BEAT_LOG" 2>&1 &
            sleep 1
            echo "[+] Celery Beat started"
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "[+] AIPET Cloud is running"
echo "[+] API:          http://localhost:5001"
echo "[+] Gunicorn log: $GUNICORN_LOG"
if [ "$SKIP_CELERY" -eq 0 ]; then
    echo "[+] Worker log:   $WORKER_LOG"
    echo "[+] Beat log:     $BEAT_LOG"
fi
echo "============================================================"

export SMTP_USER="yallewbinyam@gmail.com"
export SMTP_PASSWORD="zbggazzspycjojjp"
export SENTRY_DSN="${SENTRY_DSN:-}"

# Capability 16: Shodan API integration. Empty by default — the
# shodan blueprint loads identically when this is unset, logs a
# single WARNING, and the /api/shodan/* endpoints return 503 with
# a clear "not configured" message. Set in production secrets
# manager once a real Shodan account is provisioned.
export SHODAN_API_KEY="${SHODAN_API_KEY:-}"
