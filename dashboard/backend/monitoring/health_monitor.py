# =============================================================
# AIPET Cloud — Health Monitor
# Runs as a separate process alongside Flask.
# Checks server health every 60 seconds.
# Auto-restarts Flask if it goes down.
# Sends email alerts on failures.
# =============================================================

import os
import time
import subprocess
import smtplib
import psutil
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ── Configuration ─────────────────────────────────────────────
# How often to check (seconds)
CHECK_INTERVAL  = 60

# How many failures before restart
MAX_FAILURES    = 3

# Your Flask health endpoint
HEALTH_URL      = "http://localhost:5001/api/health"

# The command to start Flask
FLASK_CMD       = [
    "python",
    "dashboard/backend/app_cloud.py"
]

# Working directory for Flask
FLASK_DIR       = "/home/binyam/AIPET"

# Email settings — fill in your details
ALERT_EMAIL     = os.environ.get("ALERT_EMAIL", "")
SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER       = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD   = os.environ.get("SMTP_PASSWORD", "")

# Disk space warning threshold (GB)
MIN_DISK_GB     = 1.0

# Memory warning threshold (%)
MAX_MEMORY_PCT  = 90.0

# Log file
LOG_FILE        = "/tmp/aipet_monitor.log"


# ── Logging helper ─────────────────────────────────────────────
def log(message, level="INFO"):
    """
    Write a timestamped log entry to both the console
    and the monitor log file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry     = f"{timestamp} [{level}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


# ── Email alert ────────────────────────────────────────────────
def send_alert(subject, body):
    """
    Send an email alert when something goes wrong.
    Only sends if SMTP credentials are configured in .env.
    Safe to leave unconfigured in development.
    """
    if not all([ALERT_EMAIL, SMTP_USER, SMTP_PASSWORD]):
        log("Email alert skipped — SMTP not configured", "WARN")
        return

    try:
        msg              = MIMEMultipart()
        msg["From"]      = SMTP_USER
        msg["To"]        = ALERT_EMAIL
        msg["Subject"]   = f"[AIPET ALERT] {subject}"
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        log(f"Alert email sent: {subject}")

    except Exception as e:
        log(f"Failed to send alert email: {e}", "ERROR")


# ── Health check ───────────────────────────────────────────────
def check_flask():
    """
    Ping the Flask health endpoint.
    Returns True if healthy, False if down.
    """
    try:
        response = requests.get(HEALTH_URL, timeout=10)
        return response.status_code == 200
    except Exception:
        return False


# ── System resource check ──────────────────────────────────────
def check_resources():
    """
    Check disk space and memory usage.
    Logs warnings if resources are running low.
    These warnings help you act BEFORE the server crashes.
    """
    # Check disk space
    disk  = psutil.disk_usage("/")
    free_gb = disk.free / (1024 ** 3)
    if free_gb < MIN_DISK_GB:
        log(f"LOW DISK SPACE: {free_gb:.1f}GB free", "WARN")
        send_alert(
            "Low disk space",
            f"AIPET server has only {free_gb:.1f}GB disk space remaining."
        )

    # Check memory
    memory = psutil.virtual_memory()
    if memory.percent > MAX_MEMORY_PCT:
        log(f"HIGH MEMORY USAGE: {memory.percent:.1f}%", "WARN")
        send_alert(
            "High memory usage",
            f"AIPET server memory usage is at {memory.percent:.1f}%."
        )


# ── Flask restart ──────────────────────────────────────────────
def restart_flask():
    """
    Kill any existing Flask process on port 5001
    and start a fresh one.
    Called automatically after MAX_FAILURES failed checks.
    """
    log("Attempting to restart Flask...", "WARN")

    try:
        # Kill existing process on port 5001
        subprocess.run(
            ["fuser", "-k", "5001/tcp"],
            cwd=FLASK_DIR,
            capture_output=True
        )
        time.sleep(2)

        # Start Flask as a background process
        subprocess.Popen(
            FLASK_CMD,
            cwd=FLASK_DIR,
            stdout=open("/tmp/aipet_flask.log", "a"),
            stderr=subprocess.STDOUT
        )

        log("Flask restarted successfully")
        send_alert(
            "Flask restarted",
            "AIPET Flask server was down and has been automatically restarted."
        )

    except Exception as e:
        log(f"Failed to restart Flask: {e}", "ERROR")
        send_alert(
            "Flask restart FAILED",
            f"AIPET Flask server is DOWN and could not be restarted.\n\nError: {e}"
        )


# ── Main monitoring loop ───────────────────────────────────────
def run_monitor():
    """
    The main loop. Runs forever, checking health every 60 seconds.
    Keeps a failure counter — after MAX_FAILURES, restarts Flask.
    """
    log("AIPET Health Monitor started")
    log(f"Checking {HEALTH_URL} every {CHECK_INTERVAL} seconds")

    failure_count = 0

    while True:
        try:
            # Check Flask health
            if check_flask():
                log(f"Health check PASSED (failures: {failure_count})")
                failure_count = 0  # Reset counter on success

            else:
                failure_count += 1
                log(
                    f"Health check FAILED ({failure_count}/{MAX_FAILURES})",
                    "WARN"
                )

                if failure_count >= MAX_FAILURES:
                    log("Max failures reached — restarting Flask", "ERROR")
                    send_alert(
                        "Flask is DOWN",
                        f"AIPET Flask server failed {MAX_FAILURES} health checks. Restarting now."
                    )
                    restart_flask()
                    failure_count = 0

            # Check disk and memory every cycle
            check_resources()

        except Exception as e:
            log(f"Monitor error: {e}", "ERROR")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    run_monitor()