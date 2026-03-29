# =============================================================
# AIPET Cloud — Celery Tasks
# =============================================================
# What this file does:
#   Defines background tasks that Celery workers execute.
#   The main task is run_scan_task which runs the complete
#   AIPET pipeline for a user's scan request.
#
# How a scan flows:
#   1. User clicks "Start Scan" in dashboard
#   2. Flask creates Scan record in database
#   3. Flask calls run_scan_task.delay() — non-blocking
#   4. Flask immediately returns scan_id to user
#   5. Celery worker picks up run_scan_task from Redis
#   6. Worker runs full AIPET pipeline (60-90 seconds)
#   7. Worker saves results to database
#   8. User polls /api/scan/status to see progress
# =============================================================

import os
import sys
import json
import subprocess
from datetime import datetime, timezone
from celery import shared_task
from celery.utils.log import get_task_logger

# Add project root to path
BASE_DIR = '/app' if os.path.exists('/app') else '/home/binyam/AIPET'
sys.path.insert(0, BASE_DIR)

logger = get_task_logger(__name__)


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    name="dashboard.backend.tasks.run_scan_task"
)
def run_scan_task(self, scan_id, user_id, target, mode,
                  mqtt_port=1883, coap_port=5683,
                  http_port=80, firmware_path=None):
    """
    Background task that runs the complete AIPET pipeline.

    This task is executed by Celery workers, completely
    separate from the Flask web server. Multiple workers
    can run multiple scans simultaneously.

    Args:
        scan_id (int):      Database ID of the Scan record
        user_id (int):      Database ID of the User
        target (str):       IP address or CIDR range to scan
        mode (str):         "demo" or "live"
        mqtt_port (int):    MQTT broker port
        coap_port (int):    CoAP device port
        http_port (int):    HTTP interface port
        firmware_path (str): Path to firmware for analysis

    Returns:
        dict: Scan results summary
    """
    from dashboard.backend.app_cloud import create_app
    from dashboard.backend.models import db, Scan, User, Finding

    app = create_app()

    with app.app_context():
        # Get scan record from database
        scan = Scan.query.get(scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {"error": "Scan not found"}

        try:
            # Update scan status to running
            scan.status     = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.session.commit()

            logger.info(
                f"Starting scan {scan_id} for user {user_id} "
                f"target={target} mode={mode}"
            )

            # Build AIPET command
            python = os.path.join(BASE_DIR, "venv/bin/python3")
            if not os.path.exists(python):
                python = sys.executable

            aipet = os.path.join(BASE_DIR, "aipet.py")

            if mode == "demo":
                cmd = [python, aipet, "--demo"]
            else:
                cmd = [python, aipet, "--target", target]
                if firmware_path:
                    cmd += ["--firmware",
                            "--firmware-path", firmware_path]

            # Run AIPET pipeline
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                logger.warning(
                    f"AIPET returned non-zero exit code: "
                    f"{result.returncode}"
                )

            # Load results from JSON files
            findings_count = {
                "critical": 0, "high": 0,
                "medium": 0,   "low": 0
            }

            result_files = [
                ("mqtt/mqtt_results.json",         "MQTT"),
                ("coap/coap_results.json",         "CoAP"),
                ("http_attack/http_results.json",  "HTTP"),
                ("firmware/firmware_results.json", "Firmware"),
            ]

            for filepath, module_name in result_files:
                full_path = os.path.join(BASE_DIR, filepath)
                if not os.path.exists(full_path):
                    continue
                try:
                    with open(full_path) as f:
                        data = json.load(f)

                    # Count findings
                    summary = data.get("summary", {})
                    for sev in findings_count:
                        findings_count[sev] += summary.get(
                            sev, 0
                        )

                    # Save individual findings to database
                    for attack in data.get("attacks", []):
                        finding = Finding(
                            scan_id     = scan_id,
                            module      = module_name,
                            attack      = attack.get(
                                "attack", ""
                            ),
                            severity    = attack.get(
                                "severity", "INFO"
                            ),
                            description = attack.get(
                                "finding", ""
                            ),
                            target      = target,
                        )
                        db.session.add(finding)

                except Exception as e:
                    logger.warning(
                        f"Could not load {filepath}: {e}"
                    )

            # Update scan record with results
            scan.status       = "complete"
            scan.completed_at = datetime.now(timezone.utc)
            scan.critical     = findings_count["critical"]
            scan.high         = findings_count["high"]
            scan.medium       = findings_count["medium"]
            scan.low          = findings_count["low"]

            # Save report path
            reporting_dir = os.path.join(BASE_DIR, "reporting")
            if os.path.exists(reporting_dir):
                reports = sorted([
                    f for f in os.listdir(reporting_dir)
                    if f.endswith(".md")
                ], reverse=True)
                if reports:
                    scan.report_path = os.path.join(
                        reporting_dir, reports[0]
                    )

            db.session.commit()

            logger.info(
                f"Scan {scan_id} complete — "
                f"Critical: {findings_count['critical']}, "
                f"High: {findings_count['high']}"
            )

            return {
                "scan_id":  scan_id,
                "status":   "complete",
                "findings": findings_count,
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Scan {scan_id} timed out")
            scan.status = "timeout"
            db.session.commit()
            return {"scan_id": scan_id, "status": "timeout"}

        except Exception as e:
            logger.error(
                f"Scan {scan_id} failed: {str(e)}"
            )
            scan.status = "failed"
            db.session.commit()

            # Retry the task if retries remaining
            try:
                raise self.retry(exc=e)
            except self.MaxRetriesExceededError:
                return {
                    "scan_id": scan_id,
                    "status":  "failed",
                    "error":   str(e)
                }


@shared_task(name="dashboard.backend.tasks.health_check")
def health_check():
    """
    Simple health check task.
    Used to verify Celery workers are running correctly.
    Returns current timestamp.
    """
    return {
        "status": "ok",
        "time":   datetime.now(timezone.utc).isoformat(),
        "worker": "aipet-worker"
    }
