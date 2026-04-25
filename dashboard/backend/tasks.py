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
    name="dashboard.backend.tasks.sync_otx_threat_intel",
    max_retries=1,
    default_retry_delay=120,
)
def sync_otx_threat_intel():
    """
    Fetch subscribed OTX pulses and upsert their indicators into ioc_entries.
    Scheduled every 6 hours via Celery Beat.
    One OTX feed row (feed_type='otx') is created/reused; indicators are
    stored with pulse metadata JSON-encoded in the description field.
    """
    import time as _time

    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
    )
    # Guarantee .env is loaded regardless of worker startup order.
    # Use an explicit path derived from __file__ so the Celery worker
    # finds it even when find_dotenv() fails due to no calling frame.
    try:
        import pathlib as _pathlib
        from dotenv import load_dotenv as _load_dotenv
        _env_path = _pathlib.Path(__file__).resolve().parents[2] / ".env"
        _load_dotenv(dotenv_path=str(_env_path), override=False)
    except Exception:
        pass

    from dashboard.backend.models import db
    from dashboard.backend.threatintel.models import IocFeed, IocEntry
    from dashboard.backend.threatintel.otx_client import OTXClient

    # OTX indicator type → AIPET ioc_type mapping
    _TYPE_MAP = {
        "IPv4": "ip", "IPv6": "ip",
        "domain": "domain", "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash", "FileHash-SHA1": "hash",
        "FileHash-SHA256": "hash", "FileHash-SHA512": "hash",
    }

    # Severity from pulse tags
    _SEVERITY_TAGS = {
        "critical": {"apt", "ransomware", "c2", "command and control", "botnet"},
        "high":     {"malware", "trojan", "exploit", "backdoor", "rootkit"},
        "medium":   {"phishing", "scam", "spam"},
    }

    def _severity_from_tags(tags):
        tag_set = {t.lower() for t in (tags or [])}
        for sev, kws in _SEVERITY_TAGS.items():
            if tag_set & kws:
                return sev
        return "Low"

    app = create_app()
    with app.app_context():
        log = app.logger
        t0 = _time.time()

        try:
            client = OTXClient()
        except RuntimeError as exc:
            log.error("sync_otx_threat_intel: %s", exc)
            return {"status": "error", "error": str(exc)}

        # Ensure an index exists on ioc_entries.value for fast lookup
        try:
            db.session.execute(
                db.text(
                    "CREATE INDEX IF NOT EXISTS ix_ioc_entries_value "
                    "ON ioc_entries (value)"
                )
            )
            db.session.commit()
        except Exception as idx_exc:
            log.warning("sync_otx_threat_intel: could not create index: %s", idx_exc)
            db.session.rollback()

        # Get or create the OTX feed row
        otx_feed = IocFeed.query.filter_by(feed_type="otx").first()
        if not otx_feed:
            otx_feed = IocFeed(
                name="AlienVault OTX",
                feed_type="otx",
                description="AlienVault Open Threat Exchange — subscribed pulses",
                enabled=True,
            )
            db.session.add(otx_feed)
            db.session.flush()

        try:
            pulses = client.get_subscribed_pulses(page_size=50, max_pages=20)
        except Exception as exc:
            log.exception("sync_otx_threat_intel: pulse fetch failed: %s", exc)
            return {"status": "error", "error": str(exc)}

        added = updated = errors = 0

        for pulse in pulses:
            pulse_id   = pulse.get("id", "")
            pulse_name = pulse.get("name", "")
            tags       = pulse.get("tags", [])
            sev        = _severity_from_tags(tags)
            source_ref = f"https://otx.alienvault.com/pulse/{pulse_id}"
            meta_json  = json.dumps({
                "pulse_id":   pulse_id,
                "pulse_name": pulse_name,
                "tags":       tags,
            })

            for indicator in pulse.get("indicators", []):
                ioc_type_raw = indicator.get("type", "")
                ioc_type     = _TYPE_MAP.get(ioc_type_raw)
                if not ioc_type:
                    continue  # Skip unsupported types

                value = (indicator.get("indicator") or "").strip()
                if not value or len(value) > 490:
                    continue

                try:
                    existing = IocEntry.query.filter_by(
                        value=value, feed_id=otx_feed.id
                    ).first()
                    if existing:
                        existing.description = meta_json
                        existing.source_ref  = source_ref
                        existing.severity    = sev.capitalize()
                        existing.active      = True
                        updated += 1
                    else:
                        entry = IocEntry(
                            feed_id     = otx_feed.id,
                            ioc_type    = ioc_type,
                            value       = value,
                            threat_type = (tags[0] if tags else ioc_type_raw)[:99],
                            confidence  = 75,
                            severity    = sev.capitalize(),
                            description = meta_json,
                            source_ref  = source_ref,
                            active      = True,
                        )
                        db.session.add(entry)
                        added += 1
                except Exception as row_exc:
                    log.warning(
                        "sync_otx_threat_intel: row error for value=%s: %s",
                        value[:40], row_exc,
                    )
                    db.session.rollback()
                    errors += 1
                    continue

        db.session.flush()
        otx_feed.last_sync   = datetime.now(timezone.utc).replace(tzinfo=None)
        otx_feed.entry_count = IocEntry.query.filter_by(
            feed_id=otx_feed.id, active=True
        ).count()
        db.session.commit()

        runtime = round(_time.time() - t0, 2)
        log.info(
            "sync_otx_threat_intel: pulses=%d added=%d updated=%d errors=%d %.1fs",
            len(pulses), added, updated, errors, runtime,
        )
        return {
            "status":              "ok",
            "pulses_processed":    len(pulses),
            "indicators_added":    added,
            "indicators_updated":  updated,
            "errors":              errors,
            "runtime_seconds":     runtime,
        }


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


@shared_task(
    name="dashboard.backend.tasks.rebuild_device_baselines",
    max_retries=1,
    default_retry_delay=60,
)
def rebuild_device_baselines():
    """
    Rebuild per-device baselines for every distinct (user_id, host_ip) pair
    across all completed real_scan_results. Runs every 12 hours via Beat.
    One per-device failure does not abort the loop.
    """
    import json as _json

    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
    )
    from dashboard.backend.models import db
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline

    app = create_app()
    with app.app_context():
        log = app.logger

        all_scans = RealScanResult.query.filter_by(status="complete").all()

        # Collect distinct (user_id, host_ip) pairs
        pairs_seen: set[tuple] = set()
        host_pairs: list[tuple[int, str]] = []
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

        built = skipped = errors = 0

        for uid, ip in host_pairs:
            try:
                result = upsert_device_baseline(uid, ip)
                if result is None:
                    skipped += 1
                else:
                    built += 1
            except Exception as e:
                errors += 1
                log.warning(
                    "rebuild_device_baselines: failed for user=%s host=%s: %s",
                    uid, ip, e,
                )

        log.info(
            "rebuild_device_baselines: built=%d skipped_cold_start=%d errors=%d total=%d",
            built, skipped, errors, len(host_pairs),
        )
        return {
            "status":              "ok",
            "built":               built,
            "skipped_cold_start":  skipped,
            "errors":              errors,
            "total":               len(host_pairs),
        }


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


@shared_task(
    name="dashboard.backend.tasks.sync_cisa_kev",
    max_retries=1,
    default_retry_delay=300,
)
def sync_cisa_kev():
    """
    Download the CISA Known Exploited Vulnerabilities catalog and upsert all
    entries into kev_catalog.  Idempotent: re-running on the same day produces
    no duplicates (session.merge upserts by PK).

    Scheduled daily via Celery Beat.  Also triggerable via
    POST /api/live-cves/kev/sync_now.
    """
    import time as _time
    import pathlib as _pathlib

    try:
        from dotenv import load_dotenv as _load_dotenv
        _env_path = _pathlib.Path(__file__).resolve().parents[2] / ".env"
        _load_dotenv(dotenv_path=str(_env_path), override=False)
    except Exception:
        pass

    from dashboard.backend.models import db
    from dashboard.backend.live_cves.kev_client import CISAKEVClient
    from dashboard.backend.live_cves.models import KevCatalogEntry

    app = create_app()
    with app.app_context():
        log = app.logger
        t0  = _time.time()

        client = CISAKEVClient()
        try:
            raw = client.fetch_catalog()
        except RuntimeError as exc:
            log.error("sync_cisa_kev: fetch failed: %s", exc)
            return {"status": "error", "error": str(exc)}

        catalog_version = raw.get("catalogVersion", "unknown")
        entries = client.normalize_entries(raw)
        fetched = len(entries)

        upserted = 0
        for row in entries:
            try:
                obj = KevCatalogEntry(**row)
                db.session.merge(obj)
                upserted += 1
            except Exception as row_exc:
                log.warning("sync_cisa_kev: row error cve=%s: %s",
                            row.get("cve_id", "?")[:20], row_exc)
                db.session.rollback()

        db.session.commit()
        runtime = round(_time.time() - t0, 2)
        log.info(
            "sync_cisa_kev: version=%s fetched=%d upserted=%d %.1fs",
            catalog_version, fetched, upserted, runtime,
        )
        return {
            "status":          "ok",
            "catalog_version": catalog_version,
            "fetched_count":   fetched,
            "upserted_count":  upserted,
            "runtime_seconds": runtime,
        }


@shared_task(
    name="dashboard.backend.tasks.recompute_device_risk_scores",
    max_retries=1,
    default_retry_delay=60,
)
def recompute_device_risk_scores(user_id=None):
    """
    Recompute device_risk_scores for all entities that have central_events
    in the trailing 24-hour window.  Idempotent — running twice on the same
    data produces the same score (no cumulative drift).

    Scheduled every 5 minutes via Celery Beat (capability 9).
    Also triggerable per-user via POST /api/risk/recompute_now.

    user_id=None processes all users (Beat schedule).
    user_id=<int> processes only that user (manual trigger from UI).
    """
    import pathlib as _pathlib

    try:
        from dotenv import load_dotenv as _load_dotenv
        _env_path = _pathlib.Path(__file__).resolve().parents[2] / ".env"
        _load_dotenv(dotenv_path=str(_env_path), override=False)
    except Exception:
        pass

    from dashboard.backend.risk_engine.engine import recompute_all_scores

    app = create_app()
    with app.app_context():
        log = app.logger
        try:
            result = recompute_all_scores(user_id=user_id)
            log.info(
                "recompute_device_risk_scores: processed=%d updated=%d errors=%d %.2fs%s",
                result.get("processed", 0),
                result.get("updated",   0),
                result.get("errors",    0),
                result.get("runtime_seconds", 0),
                f" user_id={user_id}" if user_id is not None else " (all users)",
            )
            return result
        except Exception as exc:
            log.exception("recompute_device_risk_scores: fatal error: %s", exc)
            return {"status": "error", "error": str(exc)}
