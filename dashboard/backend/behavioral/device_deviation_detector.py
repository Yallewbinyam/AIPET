"""
AIPET X — Per-Device Behavioral Deviation Detector

Computes Z-score deviations for a host's current 12-feature vector against
its stored per-device baseline, and optionally records anomalies in ba_anomalies.

Severity thresholds:
  |z| >= 5 → critical
  |z| >= 3 → high
  |z| >= 2 → medium
  else     → normal
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER


def _compute_z(value: float, mean: float, std: float) -> tuple[float, bool]:
    """Return (z_score, std_was_zero). std=0 → z=0 and flag it."""
    if std == 0.0:
        return 0.0, True
    return abs(value - mean) / std, False


def _severity_from_z(max_z: float) -> str:
    if max_z >= 5.0:
        return "critical"
    if max_z >= 3.0:
        return "high"
    if max_z >= 2.0:
        return "medium"
    return "normal"


def detect_deviations(
    user_id: int,
    host_ip: str,
    current_features: dict,
) -> dict:
    """
    Compute per-feature Z-score deviations for host_ip against its stored baseline.

    Returns a dict with status 'no_baseline' | 'checked', severity, and deviation list.
    """
    from dashboard.backend.behavioral.models import BaBaseline

    baseline_row = BaBaseline.query.filter_by(
        entity_id   = host_ip,
        entity_type = "device",
    ).order_by(BaBaseline.last_updated.desc()).first()

    if baseline_row is None or not baseline_row.baseline:
        return {
            "status":  "no_baseline",
            "reason":  "insufficient_data",
            "host_ip": host_ip,
        }

    try:
        bl = json.loads(baseline_row.baseline)
    except (json.JSONDecodeError, TypeError):
        return {"status": "error", "reason": "corrupted_baseline", "host_ip": host_ip}

    feature_means = bl.get("feature_means", {})
    feature_stds  = bl.get("feature_stds", {})
    observations  = bl.get("observations", 0)
    confidence    = bl.get("confidence_level", "low")
    synthetic_set = set(bl.get("synthetic_features_in_baseline", []))

    # Only process features in FEATURE_ORDER to guarantee consistent ordering
    deviations = []
    for f in FEATURE_ORDER:
        current_val = float(current_features.get(f, 0.0))
        mean_val    = float(feature_means.get(f, 0.0))
        std_val     = float(feature_stds.get(f, 0.0))

        z, zero_std = _compute_z(current_val, mean_val, std_val)
        direction   = "above" if current_val > mean_val else "below"

        deviations.append({
            "feature":   f,
            "current":   round(current_val, 4),
            "mean":      round(mean_val, 4),
            "std":       round(std_val, 4),
            "z_score":   round(z, 3),
            "magnitude": round(z, 3),
            "direction": direction,
            "std_zero":  zero_std,
            "synthetic": f in synthetic_set,
        })

    max_z     = max(d["z_score"] for d in deviations) if deviations else 0.0
    severity  = _severity_from_z(max_z)
    top5      = sorted(deviations, key=lambda d: -d["z_score"])[:5]
    any_synth = any(d["synthetic"] for d in deviations)

    return {
        "status":                "checked",
        "host_ip":               host_ip,
        "severity":              severity,
        "max_z_score":           round(max_z, 3),
        "deviations":            deviations,
        "top_deviations":        top5,
        "baseline_observations": observations,
        "baseline_confidence":   confidence,
        "any_synthetic":         any_synth,
        "baseline_row_id":       baseline_row.id,
        "checked_at":            datetime.now(timezone.utc).isoformat(),
    }


def detect_and_record_deviations(
    user_id: int,
    host_ip: str,
    current_features: dict,
) -> dict:
    """
    Run detect_deviations and, if severity is not 'normal', write a ba_anomalies row.

    Returns the deviation result dict plus 'ba_anomaly_id' (int | None).
    """
    from dashboard.backend.behavioral.models import BaAnomaly
    from dashboard.backend.models import db

    result = detect_deviations(user_id, host_ip, current_features)
    result["ba_anomaly_id"] = None

    if result.get("status") != "checked":
        return result

    severity = result["severity"]
    if severity == "normal":
        return result

    baseline_row_id = result["baseline_row_id"]
    top5  = result.get("top_deviations", [])
    max_z = result.get("max_z_score", 0.0)

    top_feature = top5[0]["feature"] if top5 else "unknown"
    sev_label   = severity.capitalize()

    observed_payload = {
        d["feature"]: {"current": d["current"], "z_score": d["z_score"]}
        for d in top5
    }
    expected_payload = {
        d["feature"]: {"mean": d["mean"], "std": d["std"]}
        for d in top5
    }

    description = (
        f"Per-device Z-score analysis flagged {len([d for d in result['deviations'] if d['z_score'] >= 2.0])} "
        f"features deviating from baseline. "
        f"Top deviation: {top_feature} at {max_z:.1f}σ. "
        f"Baseline built from {result['baseline_observations']} observations "
        f"({result['baseline_confidence']} confidence)."
    )

    # Derive mitre_id from the top-deviating feature rather than hardcoding T1071.
    # Fixed in Capability 6 — was incorrectly hardcoded since Capability 2.
    try:
        from dashboard.backend.mitre_attack.mitre_mapper import from_behavioral_deviations
        _tech_mappings = from_behavioral_deviations(top5)
        mitre_id = _tech_mappings[0]["technique_id"] if _tech_mappings else "T1071"
    except Exception:
        mitre_id = "T1071"  # safe fallback if mapper unavailable

    anomaly = BaAnomaly(
        baseline_id  = baseline_row_id,
        entity_name  = host_ip,
        anomaly_type = "traffic_spike",
        severity     = sev_label,
        title        = f"Per-Device Baseline Deviation — {host_ip} ({max_z:.1f}σ)",
        description  = description,
        deviation    = round(max_z, 2),
        observed     = json.dumps(observed_payload),
        expected     = json.dumps(expected_payload),
        mitre_id     = mitre_id,
        status       = "new",
    )
    db.session.add(anomaly)
    db.session.commit()

    result["ba_anomaly_id"] = anomaly.id

    # ── Capability 7a: emit central event ─────────────────────────────────────
    try:
        from dashboard.backend.central_events.adapter import emit_event
        _mitre = None
        try:
            from dashboard.backend.mitre_attack.mitre_mapper import (
                from_behavioral_deviations, aggregate_techniques,
            )
            _mitre = aggregate_techniques(from_behavioral_deviations(top5))
        except Exception:
            pass

        emit_event(
            source_module    = "behavioral",
            source_table     = "ba_anomalies",
            source_row_id    = anomaly.id,
            event_type       = "behavioral_deviation",
            severity         = severity.lower(),
            user_id          = user_id,
            entity           = host_ip,
            entity_type      = "device",
            title            = (
                f"Behavioral deviation on {host_ip}: "
                f"{top_feature} at {max_z:.1f}σ"
            ),
            mitre_techniques = _mitre,
            payload          = {
                "top_deviations":        top5,
                "baseline_observations": result.get("baseline_observations"),
                "baseline_confidence":   result.get("baseline_confidence"),
                "max_z_score":           max_z,
            },
        )
    except Exception:
        pass  # belt-and-suspenders; emit_event is already non-fatal

    return result
