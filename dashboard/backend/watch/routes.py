"""
AIPET Watch — Cloud API Routes
Receives reports from the Watch agent and serves the dashboard.

Endpoints:
    POST  /api/watch/report                    — Receive agent report
    GET   /api/watch/baselines                 — Get device baselines
    POST  /api/watch/baselines/build           — Build baselines from scan
    GET   /api/watch/alerts                    — Get watch alerts
    PATCH /api/watch/alerts/<id>/acknowledge   — Acknowledge alert
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from dashboard.backend.models import db, Finding, Scan, DeviceTag, WatchBaseline, WatchAlert
from dashboard.backend.watch.baseline import build_baselines, compare_baselines

watch_bp = Blueprint("watch", __name__)

ALLOWED_PLANS = ["enterprise"]


def check_plan_access(user):
    """AIPET Watch is Enterprise only."""
    return user.plan in ALLOWED_PLANS


@watch_bp.route("/api/watch/baselines/build", methods=["POST"])
@jwt_required()
def build_watch_baselines():
    """
    Builds device baselines from existing scan findings.
    Called when the user first enables AIPET Watch or
    wants to reset their baselines.

    Uses the most recent completed scan for the user.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Watch is available on Enterprise plan only.",
            "upgrade": True
        }), 403

    # Get the most recent completed scan
    scan = Scan.query.filter(
        Scan.user_id == current_user_id,
        Scan.status.in_(["completed", "complete"])
    ).order_by(Scan.id.desc()).first()

    if not scan:
        return jsonify({
            "error": "No completed scan found. Run a scan first."
        }), 400

    findings    = Finding.query.filter_by(scan_id=scan.id).all()
    tags        = DeviceTag.query.filter_by(user_id=current_user_id).all()
    device_tags = {t.device_ip: t.business_function for t in tags}

    if not findings:
        return jsonify({"error": "No findings in this scan."}), 400

    findings_data = [f.to_dict() for f in findings]
    baselines     = build_baselines(findings_data, device_tags)

    saved = 0
    for ip, baseline_data in baselines.items():
        existing = WatchBaseline.query.filter_by(
            user_id=current_user_id, device_ip=ip
        ).first()

        if existing:
            existing.baseline_data   = baseline_data
            existing.device_function = baseline_data.get("device_function", "Unknown")
            existing.last_seen       = datetime.now(timezone.utc)
        else:
            new_baseline = WatchBaseline(
                user_id        = current_user_id,
                device_ip      = ip,
                device_function = baseline_data.get("device_function", "Unknown"),
                baseline_data  = baseline_data,
            )
            db.session.add(new_baseline)
        saved += 1

    db.session.commit()

    return jsonify({
        "message":  f"Successfully built baselines for {saved} devices",
        "devices":  saved,
        "scan_id":  scan.id,
    }), 200


@watch_bp.route("/api/watch/baselines", methods=["GET"])
@jwt_required()
def get_baselines():
    """Returns all device baselines for the current user."""
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Watch is available on Enterprise plan only.",
            "upgrade": True
        }), 403

    baselines = WatchBaseline.query.filter_by(
        user_id=current_user_id, is_active=True
    ).all()

    return jsonify([b.to_dict() for b in baselines]), 200


@watch_bp.route("/api/watch/report", methods=["POST"])
@jwt_required()
def receive_agent_report():
    """
    Receives a traffic report from the AIPET Watch agent.

    The agent calls this endpoint every interval with:
    - Traffic stats per device
    - Detected anomalies

    This endpoint stores any anomalies as WatchAlerts and
    updates device last_seen timestamps.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({"error": "Plan upgrade required"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    stats     = data.get("stats", {})
    anomalies = data.get("anomalies", [])

    # Update last_seen for each device in the report
    for ip in stats.keys():
        baseline = WatchBaseline.query.filter_by(
            user_id=current_user_id, device_ip=ip
        ).first()
        if baseline:
            baseline.last_seen = datetime.now(timezone.utc)

    # Store anomalies as watch alerts
    saved_alerts = 0
    for anomaly in anomalies:
        alert = WatchAlert(
            user_id     = current_user_id,
            device_ip   = anomaly.get("details", {}).get("device_ip", "Unknown"),
            alert_type  = anomaly.get("type", "unknown"),
            severity    = anomaly.get("severity", "Medium"),
            description = anomaly.get("description", ""),
            details     = anomaly.get("details", {}),
        )
        db.session.add(alert)
        saved_alerts += 1

    db.session.commit()

    return jsonify({
        "message":      "Report received",
        "devices_seen": len(stats),
        "alerts_saved": saved_alerts,
    }), 200


@watch_bp.route("/api/watch/alerts", methods=["GET"])
@jwt_required()
def get_watch_alerts():
    """
    Returns all watch alerts for the current user.
    Sorted by created_at descending (newest first).
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Watch is available on Enterprise plan only.",
            "upgrade": True
        }), 403

    limit  = min(int(request.args.get("limit", 50)), 200)
    alerts = WatchAlert.query.filter_by(
        user_id=current_user_id
    ).order_by(
        WatchAlert.created_at.desc()
    ).limit(limit).all()

    return jsonify([a.to_dict() for a in alerts]), 200


@watch_bp.route("/api/watch/alerts/<int:alert_id>/acknowledge", methods=["PATCH"])
@jwt_required()
def acknowledge_alert(alert_id):
    """Acknowledges a watch alert."""
    current_user_id = get_jwt_identity()

    alert = WatchAlert.query.filter_by(
        id=alert_id, user_id=current_user_id
    ).first()

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.is_acknowledged = True
    db.session.commit()

    return jsonify({
        "message":        "Alert acknowledged",
        "alert_id":       alert_id,
        "is_acknowledged": True
    }), 200


@watch_bp.route("/api/watch/status", methods=["GET"])
@jwt_required()
def get_watch_status():
    """
    Returns the current watch status for the user.
    Used by the dashboard to show monitoring overview.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Watch is available on Enterprise plan only.",
            "upgrade": True
        }), 403

    baselines = WatchBaseline.query.filter_by(
        user_id=current_user_id, is_active=True
    ).all()

    unacked_alerts = WatchAlert.query.filter_by(
        user_id=current_user_id, is_acknowledged=False
    ).count()

    total_alerts = WatchAlert.query.filter_by(
        user_id=current_user_id
    ).count()

    return jsonify({
        "devices_monitored": len(baselines),
        "unacked_alerts":    unacked_alerts,
        "total_alerts":      total_alerts,
        "baselines":         [b.to_dict() for b in baselines],
    }), 200