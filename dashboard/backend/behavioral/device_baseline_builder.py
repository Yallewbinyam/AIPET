"""
AIPET X — Per-Device Behavioral Baseline Builder

Builds per-device baselines from real scan history using the same 12-feature
vocabulary as ml_anomaly (FEATURE_ORDER). Baselines are stored in ba_baselines
with entity_type='device' and entity_id=<host_ip>.

Reuses imputation constants from feature_extraction.py — do not duplicate.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone

from flask import current_app

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER
from dashboard.backend.ml_anomaly.feature_extraction import (
    _NIGHT_HOURS,
    _ANOMALY_PORT_THRESHOLD,
    _ANOMALY_CVE_THRESHOLD,
    _NORMAL_MEANS,
    _ANOMALY_MEANS,
)

_MIN_SCANS_FOR_NIGHT = 3


def build_device_baseline(
    user_id: int,
    host_ip: str,
    min_observations: int = 5,
) -> dict | None:
    """
    Build a per-device baseline from real scan history.

    Returns None if fewer than min_observations scans contain host_ip.
    Returns a baseline dict with mean/std for all 12 FEATURE_ORDER features,
    plus confidence and vocabulary metadata.
    """
    from dashboard.backend.real_scanner.routes import RealScanResult

    log = current_app.logger

    scans = (
        RealScanResult.query
        .filter(
            RealScanResult.user_id == user_id,
            RealScanResult.status == "complete",
        )
        .order_by(RealScanResult.started_at.asc())
        .all()
    )

    # Collect per-scan observations for real features
    observations: list[dict] = []  # open_port_count, cve_count, started_at, is_night

    for scan in scans:
        try:
            hosts = json.loads(scan.results_json or "[]")
        except (json.JSONDecodeError, TypeError):
            log.warning("device_baseline_builder: bad results_json in scan %s", scan.id)
            continue

        for host in hosts:
            if host.get("ip") == host_ip:
                open_ports = host.get("open_ports", [])
                open_port_count = float(host.get("port_count", len(open_ports)))

                cves = host.get("cves", host.get("cves_found"))
                if cves is not None:
                    cve_count = float(len(cves))
                else:
                    cve_count = float(host.get("cve_count", 0))

                ts = scan.started_at
                observations.append({
                    "open_port_count": open_port_count,
                    "cve_count": cve_count,
                    "started_at": ts,
                    "is_night": 1.0 if (ts is not None and ts.hour in _NIGHT_HOURS) else 0.0,
                })
                break

    if len(observations) < min_observations:
        log.debug(
            "device_baseline_builder: cold-start for %s — %d observations (need %d)",
            host_ip, len(observations), min_observations,
        )
        return None

    n = len(observations)

    # ── Real feature: open_port_count ────────────────────────────────────────
    port_counts = [o["open_port_count"] for o in observations]
    mean_port = sum(port_counts) / n
    std_port  = math.sqrt(sum((x - mean_port) ** 2 for x in port_counts) / (n - 1)) if n > 1 else 0.0

    # ── Real feature: cve_count ──────────────────────────────────────────────
    cve_counts = [o["cve_count"] for o in observations]
    mean_cve = sum(cve_counts) / n
    std_cve  = math.sqrt(sum((x - mean_cve) ** 2 for x in cve_counts) / (n - 1)) if n > 1 else 0.0

    # ── Real feature: night_activity ─────────────────────────────────────────
    synthetic_features_in_baseline: list[str] = []

    if n >= _MIN_SCANS_FOR_NIGHT:
        night_vals = [o["is_night"] for o in observations]
        mean_night = sum(night_vals) / n
        std_night  = math.sqrt(sum((x - mean_night) ** 2 for x in night_vals) / (n - 1)) if n > 1 else 0.0
        night_is_synthetic = False
    else:
        mean_night = None
        std_night  = None
        night_is_synthetic = True
        synthetic_features_in_baseline.append("night_activity")

    # ── Placeholder features (9 of 12) — reuse imputation logic ──────────────
    if mean_port >= _ANOMALY_PORT_THRESHOLD or mean_cve >= _ANOMALY_CVE_THRESHOLD:
        placeholder_src = _ANOMALY_MEANS
        placeholder_strategy = (
            f"anomaly_means (mean_port={mean_port:.1f} or "
            f"mean_cve={mean_cve:.1f} exceeds threshold "
            f"port>={_ANOMALY_PORT_THRESHOLD} / cve>={_ANOMALY_CVE_THRESHOLD})"
        )
    else:
        placeholder_src = _NORMAL_MEANS
        placeholder_strategy = (
            f"normal_means (mean_port={mean_port:.1f} and "
            f"mean_cve={mean_cve:.1f} within normal range)"
        )

    # ── Build feature_means and feature_stds ─────────────────────────────────
    feature_means: dict[str, float] = {}
    feature_stds:  dict[str, float] = {}

    for f in FEATURE_ORDER:
        if f == "open_port_count":
            feature_means[f] = mean_port
            feature_stds[f]  = std_port
        elif f == "cve_count":
            feature_means[f] = mean_cve
            feature_stds[f]  = std_cve
        elif f == "night_activity":
            if not night_is_synthetic:
                feature_means[f] = mean_night
                feature_stds[f]  = std_night
            else:
                feature_means[f] = placeholder_src[f]
                feature_stds[f]  = 0.0
        else:
            feature_means[f] = placeholder_src[f]
            feature_stds[f]  = 0.0
            synthetic_features_in_baseline.append(f)

    confidence_level = "high" if n >= 30 else ("medium" if n >= 10 else "low")

    return {
        "user_id":                     user_id,
        "host_ip":                     host_ip,
        "feature_means":               feature_means,
        "feature_stds":                feature_stds,
        "observations":                n,
        "confidence_level":            confidence_level,
        "feature_vocabulary":          "ml_anomaly_v1",
        "synthetic_features_in_baseline": synthetic_features_in_baseline,
        "placeholder_strategy":        placeholder_strategy,
        "first_observation_at":        observations[0]["started_at"].isoformat() if observations[0]["started_at"] else None,
        "last_observation_at":         observations[-1]["started_at"].isoformat() if observations[-1]["started_at"] else None,
    }


def upsert_device_baseline(user_id: int, host_ip: str) -> dict | None:
    """
    Build a baseline for host_ip and upsert into ba_baselines.

    Returns None if cold-start (< min_observations).
    Returns the baseline dict on success.
    """
    from dashboard.backend.behavioral.models import BaBaseline
    from dashboard.backend.models import db

    result = build_device_baseline(user_id, host_ip)
    if result is None:
        return None

    existing = BaBaseline.query.filter_by(
        entity_id   = host_ip,
        entity_type = "device",
    ).first()

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if existing:
        existing.baseline     = json.dumps(result)
        existing.confidence   = result["observations"]
        existing.last_updated = now
    else:
        row = BaBaseline(
            entity_id    = host_ip,
            entity_type  = "device",
            entity_name  = f"Device {host_ip}",
            baseline     = json.dumps(result),
            confidence   = result["observations"],
            risk_score   = 0,
            anomaly_count = 0,
            last_updated = now,
        )
        db.session.add(row)

    db.session.commit()
    return result
