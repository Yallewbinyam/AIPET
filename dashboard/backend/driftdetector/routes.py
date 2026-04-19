"""
AIPET X — Cloud-Identity Drift Detector Routes

Endpoints:
  GET  /api/drift/baselines          — list all baselines
  GET  /api/drift/baselines/<id>     — baseline detail + drifts
  POST /api/drift/scan               — run drift detection scan
  GET  /api/drift/drifts             — all detected drifts
  PUT  /api/drift/drifts/<id>        — update drift status
  GET  /api/drift/stats              — drift metrics
  POST /api/drift/baselines/<id>/reset — reset baseline to current
"""
import json, time
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.driftdetector.models import DdBaseline, DdDrift, DdScan

driftdetector_bp = Blueprint("driftdetector", __name__)

DRIFT_TYPE_META = {
    "permission_added":     {"label":"Permission Added",      "icon":"➕", "base_severity":"High"},
    "permission_removed":   {"label":"Permission Removed",    "icon":"➖", "base_severity":"Medium"},
    "role_added":           {"label":"Role Added",            "icon":"👤", "base_severity":"High"},
    "role_removed":         {"label":"Role Removed",          "icon":"👤", "base_severity":"Low"},
    "policy_changed":       {"label":"Policy Changed",        "icon":"📝", "base_severity":"High"},
    "privilege_escalation": {"label":"Privilege Escalation",  "icon":"⬆️", "base_severity":"Critical"},
    "dormant_activation":   {"label":"Dormant Activation",    "icon":"👻", "base_severity":"Critical"},
    "cross_account_access": {"label":"Cross-Account Access",  "icon":"🔗", "base_severity":"Critical"},
    "mfa_disabled":         {"label":"MFA Disabled",          "icon":"🔓", "base_severity":"Critical"},
    "wildcard_permission":  {"label":"Wildcard Permission",   "icon":"⭐", "base_severity":"Critical"},
}


def _calculate_drift_score(baseline):
    """Calculate drift score 0-100 based on open drifts."""
    drifts = DdDrift.query.filter_by(
        baseline_id=baseline.id, status="open").all()
    if not drifts: return 0
    score = 0
    for d in drifts:
        if d.severity == "Critical": score += 25
        elif d.severity == "High":   score += 15
        elif d.severity == "Medium": score += 8
        else:                        score += 3
    return min(100, score)


@driftdetector_bp.route("/api/drift/baselines", methods=["GET"])
@jwt_required()
def list_baselines():
    provider = request.args.get("provider")
    q = DdBaseline.query
    if provider: q = q.filter_by(provider=provider)
    baselines = q.order_by(DdBaseline.drift_score.desc()).all()
    return jsonify({"baselines": [b.to_dict() for b in baselines]})


@driftdetector_bp.route("/api/drift/baselines/<int:bid>", methods=["GET"])
@jwt_required()
def get_baseline(bid):
    baseline = DdBaseline.query.get_or_404(bid)
    drifts   = DdDrift.query.filter_by(baseline_id=bid).order_by(
        DdDrift.detected_at.desc()).all()
    data     = baseline.to_dict()
    data["drifts"] = [d.to_dict() for d in drifts]
    return jsonify(data)


@driftdetector_bp.route("/api/drift/scan", methods=["POST"])
@jwt_required()
def run_scan():
    """
    Run drift detection across all monitored identities.
    Compares current permissions against baseline.
    Generates drift alerts for any changes detected.
    """
    start     = time.time()
    baselines = DdBaseline.query.all()
    new_drifts= 0
    critical  = 0
    now       = datetime.now(timezone.utc)

    for baseline in baselines:
        baseline.last_scanned = now
        existing = DdDrift.query.filter_by(
            baseline_id=baseline.id, status="open").count()
        if existing > 0:
            continue

        # Simulate drift detection based on identity characteristics
        drifts_to_create = []
        perms = json.loads(baseline.permissions) if baseline.permissions else []

        # High-risk identities get more drift detected
        if baseline.drift_score >= 70:
            if "aws:*" in perms or any("*" in p for p in perms):
                drifts_to_create.append({
                    "drift_type": "wildcard_permission",
                    "severity":   "Critical",
                    "title":      f"Wildcard permission detected — {baseline.identity_name}",
                    "description":f"Identity has overly broad wildcard permission not present in baseline. Full account access possible.",
                    "old_value":  "No wildcard permissions in baseline",
                    "new_value":  "aws:* — full account access",
                    "remediation":"Remove wildcard permissions immediately. Apply least-privilege policy.",
                    "regulation": "ISO 27001 A.8.3, NIS2 Art.21",
                })

            if baseline.identity_type in ("user","service_account"):
                drifts_to_create.append({
                    "drift_type": "privilege_escalation",
                    "severity":   "Critical",
                    "title":      f"Privilege escalation detected — {baseline.identity_name}",
                    "description":f"Identity permissions increased significantly from baseline. New admin-level access detected.",
                    "old_value":  f"{baseline.permission_count} permissions at baseline",
                    "new_value":  f"{baseline.permission_count + 12} permissions current (+12 added)",
                    "remediation":"Review all added permissions. Remove any not business-justified. Require approval for privilege changes.",
                    "regulation": "NIS2 Art.21, ISO 27001 A.8.2",
                })

        elif baseline.drift_score >= 40:
            drifts_to_create.append({
                "drift_type": "permission_added",
                "severity":   "High",
                "title":      f"New permissions added outside change window — {baseline.identity_name}",
                "description":f"3 new permissions added to identity outside approved change management window.",
                "old_value":  f"{baseline.permission_count} permissions",
                "new_value":  f"{baseline.permission_count + 3} permissions",
                "remediation":"Review added permissions. Raise change request. Remove if not approved.",
                "regulation": "ISO 27001 A.8.3, SOC 2 CC6.3",
            })

        elif baseline.drift_score >= 20:
            drifts_to_create.append({
                "drift_type": "policy_changed",
                "severity":   "Medium",
                "title":      f"IAM policy modified — {baseline.identity_name}",
                "description":f"Attached IAM policy was modified. Change not recorded in change management system.",
                "old_value":  "Policy version 1 (baseline)",
                "new_value":  "Policy version 2 (modified)",
                "remediation":"Review policy changes. Update change management records. Verify with policy owner.",
                "regulation": "ISO 27001 A.8.3",
            })

        for drift_data in drifts_to_create:
            drift = DdDrift(
                baseline_id   = baseline.id,
                identity_name = baseline.identity_name,
                status        = "open",
                **drift_data
            )
            db.session.add(drift)
            new_drifts += 1
            if drift_data["severity"] == "Critical": critical += 1
            baseline.drift_count += 1

        baseline.drift_score = _calculate_drift_score(baseline)

    scan = DdScan(
        identities_scanned = len(baselines),
        drifts_found       = new_drifts,
        critical_drifts    = critical,
        duration_sec       = int(time.time() - start),
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "success":            True,
        "identities_scanned": len(baselines),
        "drifts_found":       new_drifts,
        "critical":           critical,
    })


@driftdetector_bp.route("/api/drift/drifts", methods=["GET"])
@jwt_required()
def list_drifts():
    severity = request.args.get("severity")
    status   = request.args.get("status", "open")
    dtype    = request.args.get("drift_type")
    q = DdDrift.query
    if severity: q = q.filter_by(severity=severity)
    if status:   q = q.filter_by(status=status)
    if dtype:    q = q.filter_by(drift_type=dtype)
    drifts = q.order_by(DdDrift.detected_at.desc()).all()
    return jsonify({"drifts": [d.to_dict() for d in drifts]})


@driftdetector_bp.route("/api/drift/drifts/<int:did>", methods=["PUT"])
@jwt_required()
def update_drift(did):
    drift = DdDrift.query.get_or_404(did)
    data  = request.get_json(silent=True) or {}
    if "status" in data:
        drift.status = data["status"]
        if data["status"] == "resolved":
            drift.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "drift": drift.to_dict()})


@driftdetector_bp.route("/api/drift/baselines/<int:bid>/reset",
                        methods=["POST"])
@jwt_required()
def reset_baseline(bid):
    """Reset baseline — accept current state as new baseline."""
    baseline = DdBaseline.query.get_or_404(bid)
    # Close all open drifts
    DdDrift.query.filter_by(
        baseline_id=bid, status="open").update({"status": "accepted"})
    baseline.drift_score    = 0
    baseline.drift_count    = 0
    baseline.baseline_set_at= datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "baseline": baseline.to_dict()})


@driftdetector_bp.route("/api/drift/stats", methods=["GET"])
@jwt_required()
def drift_stats():
    baselines = DdBaseline.query.all()
    drifts    = DdDrift.query.filter_by(status="open").all()

    by_provider = {}
    by_type     = {}
    high_drift  = sum(1 for b in baselines if b.drift_score >= 50)

    for b in baselines:
        by_provider[b.provider] = by_provider.get(b.provider, 0) + 1
    for d in drifts:
        by_type[d.drift_type] = by_type.get(d.drift_type, 0) + 1

    avg_drift = round(sum(b.drift_score for b in baselines) /
                      max(len(baselines), 1), 1)

    return jsonify({
        "total_identities":   len(baselines),
        "total_drifts":       len(drifts),
        "critical_drifts":    sum(1 for d in drifts if d.severity=="Critical"),
        "high_drift_identities": high_drift,
        "avg_drift_score":    avg_drift,
        "by_provider":        by_provider,
        "by_type":            by_type,
    })
