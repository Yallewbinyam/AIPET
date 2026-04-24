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
import time
import subprocess
import requests as http_requests
from datetime import datetime, timezone, timedelta
from celery import shared_task
from celery.utils.log import get_task_logger
from dashboard.backend.app_cloud import create_app

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


# ── NVD CVE Sync ──────────────────────────────────────────

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 100


def _parse_cve_item(item: dict) -> dict | None:
    """Extract fields from a NVD CVE item."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            if key.startswith("cvssMetricV3"):
                cvss_score = m.get("cvssData", {}).get("baseScore")
                severity   = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            else:
                cvss_score = m.get("cvssData", {}).get("baseScore")
                severity   = m.get("baseSeverity", "UNKNOWN")
            break

    published = cve.get("published", "")
    last_mod  = cve.get("lastModified", "")

    # Extract CPE names and product keywords
    cpe_list = []
    keywords = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria", "")
                if uri:
                    cpe_list.append(uri)
                    parts = uri.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3].replace("_", " ")
                        product = parts[4].replace("_", " ")
                        version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else ""
                        kw = product
                        if version:
                            kw += f" {version.split('.')[0]}"
                        keywords.add(kw.lower().strip())
                        keywords.add(vendor.lower().strip())

    try:
        pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
        mod_dt = datetime.fromisoformat(last_mod.replace("Z", "+00:00")) if last_mod else None
    except Exception:
        pub_dt = mod_dt = None

    return {
        "cve_id":        cve_id,
        "description":   desc[:1000],
        "cvss_score":    cvss_score,
        "severity":      severity.upper(),
        "published":     pub_dt,
        "last_modified": mod_dt,
        "cpe_list":      json.dumps(cpe_list[:30]),
        "keywords":      json.dumps(sorted(keywords)[:40]),
        "url":           f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


@shared_task(
    bind=True,
    name="dashboard.backend.tasks.sync_nvd_cves",
    max_retries=2,
    default_retry_delay=60,
)
def sync_nvd_cves(self, days_back: int = 1):
    """
    Fetch recent CVEs from NVD API and upsert into live_cves table.
    Then re-match all real_scan_results that are within the last 7 days.
    Scheduled every hour via Celery Beat.
    """
    import os
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
    )
    from dashboard.backend.models import db
    from dashboard.backend.live_cves.models import LiveCve, CveSyncLog

    app = create_app()
    with app.app_context():
        sync_log = CveSyncLog(status="running")
        db.session.add(sync_log)
        db.session.commit()

        added = updated = 0
        try:
            now    = datetime.utcnow()
            start  = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
            end    = now.strftime("%Y-%m-%dT%H:%M:%S.000")
            offset = 0

            while True:
                params = {
                    "pubStartDate":   start,
                    "pubEndDate":     end,
                    "resultsPerPage": NVD_PAGE_SIZE,
                    "startIndex":     offset,
                }
                try:
                    resp = http_requests.get(NVD_CVE_URL, params=params, timeout=15)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as e:
                    logger.warning(f"NVD fetch error at offset {offset}: {e}")
                    break

                vulns     = data.get("vulnerabilities", [])
                total_res = data.get("totalResults", 0)

                for item in vulns:
                    parsed = _parse_cve_item(item)
                    if not parsed:
                        continue
                    existing = LiveCve.query.get(parsed["cve_id"])
                    if existing:
                        for k, v in parsed.items():
                            setattr(existing, k, v)
                        existing.synced_at = datetime.utcnow()
                        updated += 1
                    else:
                        db.session.add(LiveCve(**parsed))
                        added += 1

                db.session.commit()
                offset += NVD_PAGE_SIZE
                if offset >= total_res:
                    break
                time.sleep(0.7)  # NVD rate limit: 5 req/30s unauthenticated

            # Re-match recent real_scan_results against live CVEs
            _rematch_scan_results(db, days_back=7)

            sync_log.status      = "complete"
            sync_log.finished_at = datetime.utcnow()
            sync_log.cves_added  = added
            sync_log.cves_updated= updated
            db.session.commit()

            logger.info(f"CVE sync complete: +{added} new, ~{updated} updated")
            return {"added": added, "updated": updated}

        except Exception as exc:
            sync_log.status      = "error"
            sync_log.error       = str(exc)
            sync_log.finished_at = datetime.utcnow()
            db.session.commit()
            raise self.retry(exc=exc)


@shared_task(
    name="dashboard.backend.tasks.retrain_anomaly_model",
    max_retries=1,
    default_retry_delay=300,
)
def retrain_anomaly_model():
    """
    Retrain the Isolation Forest on accumulated real scan data.

    Guard: if fewer than 20 completed real_scan_results rows exist,
    log a warning and return a skipped dict — never fall back to synthetic
    data during a scheduled run.

    Scheduled every 24 hours via Celery Beat.
    Also triggerable manually via POST /api/ml/anomaly/retrain_now.
    """
    import uuid
    import json as _json
    import os

    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
    )
    from dashboard.backend.models import db
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.ml_anomaly.models import AnomalyModelVersion
    from dashboard.backend.ml_anomaly.detector import AnomalyDetector, LATEST_PATH
    from dashboard.backend.ml_anomaly.features import FEATURE_ORDER
    from dashboard.backend.ml_anomaly.feature_extraction import extract_features_for_host

    REQUIRED_SCANS = 20
    CONTAMINATION  = 0.05
    N_ESTIMATORS   = 100
    RANDOM_STATE   = 42

    app = create_app()
    with app.app_context():
        log = app.logger

        # ── Guard: count completed scans ──────────────────────────────────
        scan_count = RealScanResult.query.filter_by(status="complete").count()
        if scan_count < REQUIRED_SCANS:
            log.warning(
                "retrain_anomaly_model: skipped — %d completed scans, need %d",
                scan_count, REQUIRED_SCANS,
            )
            return {
                "status":   "skipped",
                "reason":   "insufficient_real_data",
                "found":    scan_count,
                "required": REQUIRED_SCANS,
            }

        try:
            # ── Collect (user_id, host_ip) pairs from all completed scans ──
            all_scans = RealScanResult.query.filter_by(status="complete").all()
            pairs_seen = set()
            host_pairs = []
            for scan in all_scans:
                try:
                    hosts = _json.loads(scan.results_json or "[]")
                except Exception:
                    continue
                for host in hosts:
                    ip = host.get("ip")
                    if ip:
                        key = (scan.user_id, ip)
                        if key not in pairs_seen:
                            pairs_seen.add(key)
                            host_pairs.append((scan.user_id, ip))

            # ── Extract feature vectors ────────────────────────────────────
            import numpy as np
            vectors = []
            for user_id, host_ip in host_pairs:
                try:
                    feats = extract_features_for_host(user_id, host_ip)
                    if feats is None:
                        continue
                    vec = [float(feats.get(f, 0.0)) for f in FEATURE_ORDER]
                    vectors.append(vec)
                except Exception as e:
                    log.warning(
                        "retrain_anomaly_model: feature extraction failed for %s: %s",
                        host_ip, e,
                    )

            if len(vectors) < REQUIRED_SCANS:
                log.warning(
                    "retrain_anomaly_model: skipped — extracted %d feature vectors, need %d",
                    len(vectors), REQUIRED_SCANS,
                )
                return {
                    "status":   "skipped",
                    "reason":   "insufficient_feature_vectors",
                    "found":    len(vectors),
                    "required": REQUIRED_SCANS,
                }

            X = np.array(vectors, dtype=np.float64)

            # ── Train ─────────────────────────────────────────────────────
            detector = AnomalyDetector()
            detector.fit(
                X,
                FEATURE_ORDER,
                contamination=CONTAMINATION,
                n_estimators=N_ESTIMATORS,
                random_state=RANDOM_STATE,
            )

            # ── Save model ────────────────────────────────────────────────
            version_tag = (
                datetime.now(timezone.utc).strftime("v%Y%m%d_%H%M%S")
                + "_" + uuid.uuid4().hex[:6]
            )
            models_dir = os.path.join(
                os.path.dirname(__file__), "ml_anomaly", "models_store"
            )
            model_path = os.path.join(models_dir, f"iforest_{version_tag}.joblib")
            detector.save(model_path)
            detector.save(LATEST_PATH)

            # ── Update DB ──────────────────────────────────────────────────
            AnomalyModelVersion.query.filter_by(is_active=True).update({"is_active": False})

            # Clear SHAP explainer cache — new model invalidates old explainers.
            from dashboard.backend.ml_anomaly.explainer import clear_cache as _clear_shap
            _clear_shap()

            mv = AnomalyModelVersion(
                version_tag      = version_tag,
                algorithm        = "isolation_forest",
                contamination    = CONTAMINATION,
                n_estimators     = N_ESTIMATORS,
                feature_names    = _json.dumps(FEATURE_ORDER),
                training_samples = len(X),
                precision_score  = None,   # no ground-truth labels for real data
                recall_score     = None,
                f1_score         = None,
                model_path       = model_path,
                is_active        = True,
                node_meta        = _json.dumps({
                    "training_mode":     "real_scans_scheduled",
                    "scheduled_at":      datetime.now(timezone.utc).isoformat(),
                    "scan_rows_used":    scan_count,
                    "host_pairs_found":  len(host_pairs),
                    "vectors_extracted": len(vectors),
                }),
            )
            db.session.add(mv)
            db.session.commit()

            log.info(
                "retrain_anomaly_model: trained %s on %d vectors from %d scans",
                version_tag, len(vectors), scan_count,
            )
            return {
                "status":           "trained",
                "version":          version_tag,
                "training_samples": len(vectors),
                "scan_rows_used":   scan_count,
            }

        except Exception as exc:
            log.exception("retrain_anomaly_model: unexpected error — %s", exc)
            raise


def _rematch_scan_results(db, days_back: int = 7):
    """
    For each recent real_scan_result, match open ports/services against live_cves
    and append any new CVE IDs not already in the result's CVE list.
    """
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.live_cves.models import LiveCve

    cutoff = datetime.utcnow() - timedelta(days=days_back)
    recent_scans = RealScanResult.query.filter(
        RealScanResult.finished_at >= cutoff,
        RealScanResult.status == "complete",
    ).all()

    for scan in recent_scans:
        try:
            hosts = json.loads(scan.results_json or "[]")
            changed = False
            for host in hosts:
                existing_ids = {c["cve_id"] for c in host.get("cves", [])}
                keywords = set()
                for p in host.get("open_ports", []):
                    if p.get("product"):
                        kw = p["product"].lower()
                        if p.get("version"):
                            kw += " " + p["version"].split(" ")[0].lower()
                        keywords.add(kw)
                    elif p.get("service") and p["service"] not in ("tcpwrapped", "unknown"):
                        keywords.add(p["service"].lower())

                for kw in keywords:
                    matches = LiveCve.query.filter(
                        LiveCve.keywords.ilike(f"%{kw}%")
                    ).order_by(LiveCve.cvss_score.desc()).limit(5).all()
                    for cve in matches:
                        if cve.cve_id not in existing_ids:
                            host["cves"].append({
                                "cve_id":          cve.cve_id,
                                "description":     cve.description[:300],
                                "cvss_score":      cve.cvss_score,
                                "severity":        cve.severity,
                                "published":       cve.published.strftime("%Y-%m-%d") if cve.published else "",
                                "url":             cve.url,
                                "matched_keyword": kw,
                                "source":          "live_feed",
                            })
                            existing_ids.add(cve.cve_id)
                            changed = True

                host["cve_count"] = len(host.get("cves", []))

            if changed:
                scan.results_json = json.dumps(hosts)
                scan.cve_count    = sum(h.get("cve_count", 0) for h in hosts)
                db.session.add(scan)
        except Exception as e:
            logger.warning(f"rematch error for scan {scan.id}: {e}")

    db.session.commit()
