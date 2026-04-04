"""
AIPET Predict — CVE Intelligence Routes
Handles all endpoints for CVE monitoring and alerting.

Endpoints:
    POST  /api/predict/scan/<scan_id>        — Fetch and match new CVEs
    GET   /api/predict/alerts                — Get all alerts for user
    PATCH /api/predict/alerts/<id>/review    — Mark alert as reviewed
    DELETE /api/predict/alerts/<id>          — Dismiss an alert
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from dashboard.backend.models import db, Finding, Scan, DeviceTag, PredictAlert
from dashboard.backend.predict.nvd_client import fetch_recent_cves
from dashboard.backend.predict.matcher import match_cves

predict_bp = Blueprint("predict", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]


def check_plan_access(user):
    """Checks if the user's plan allows access to AIPET Predict."""
    return user.plan in ALLOWED_PLANS


@predict_bp.route("/api/predict/scan/<int:scan_id>", methods=["POST"])
@jwt_required()
def run_prediction_scan(scan_id):
    """
    Fetches recent CVEs from NVD and matches them against the user's
    scan findings and device tags.

    Stores new matches as alerts in the database.
    Skips CVEs that have already been alerted for this user.

    Request body (optional):
    {
        "days": 7  — how many days of CVEs to fetch (default 7)
    }

    Access: Professional and Enterprise plans only.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Predict is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return jsonify({
            "error": "No findings for this scan. Run a scan first."
        }), 400

    # Get device tags
    tags        = DeviceTag.query.filter_by(user_id=current_user_id).all()
    device_tags = {t.device_ip: t.business_function for t in tags}

    # Get days parameter from request
    data = request.get_json() or {}
    days = data.get("days", 7)
    days = max(1, min(days, 30))  # Clamp between 1 and 30

    # Fetch CVEs from NVD
    nvd_result = fetch_recent_cves(days=days, max_results=200)
    if not nvd_result["success"]:
        return jsonify({
            "error":   "Failed to fetch CVEs from NVD",
            "details": nvd_result.get("error", "Unknown error")
        }), 503

    # Match CVEs against user's findings
    findings_data = [f.to_dict() for f in findings]
    matched       = match_cves(nvd_result["cves"], findings_data, device_tags)

    # Get existing alert CVE IDs for this user to avoid duplicates
    existing_cve_ids = set(
        a.cve_id for a in PredictAlert.query.filter_by(user_id=current_user_id).all()
    )

    # Store new alerts
    new_alerts = []
    for match in matched:
        if match["cve_id"] in existing_cve_ids:
            continue

        published_date = match["published_date"]
        if published_date.tzinfo is not None:
            published_date = published_date.replace(tzinfo=None)

        alert = PredictAlert(
            user_id          = current_user_id,
            cve_id           = match["cve_id"],
            title            = match["title"],
            description      = match["description"][:2000],
            severity         = match["severity"],
            cvss_score       = match["cvss_score"],
            affected_devices = match["affected_devices"],
            weaponisation_pct = match["weaponisation_pct"],
            published_date   = published_date,
            nvd_url          = match["nvd_url"],
            is_reviewed      = False
        )
        db.session.add(alert)
        new_alerts.append(match["cve_id"])

    db.session.commit()

    return jsonify({
        "message":        f"Scan complete. Found {len(new_alerts)} new CVE alerts.",
        "new_alerts":     len(new_alerts),
        "total_matched":  len(matched),
        "cves_checked":   len(nvd_result["cves"]),
        "days_checked":   days,
        "new_cve_ids":    new_alerts,
    }), 200


@predict_bp.route("/api/predict/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    """
    Returns all CVE alerts for the current user.
    Sorted by severity then CVSS score descending.

    Query params:
        reviewed=true/false  — filter by review status
        limit=N              — limit results (default 50)
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Predict is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    reviewed_filter = request.args.get("reviewed")
    limit           = min(int(request.args.get("limit", 50)), 200)

    query = PredictAlert.query.filter_by(user_id=current_user_id)

    if reviewed_filter == "false":
        query = query.filter_by(is_reviewed=False)
    elif reviewed_filter == "true":
        query = query.filter_by(is_reviewed=True)

    alerts = query.order_by(
        PredictAlert.cvss_score.desc()
    ).limit(limit).all()

    return jsonify([a.to_dict() for a in alerts]), 200


@predict_bp.route("/api/predict/alerts/<int:alert_id>/review", methods=["PATCH"])
@jwt_required()
def mark_reviewed(alert_id):
    """
    Marks a CVE alert as reviewed.
    Used when the user has read and acknowledged the alert.
    """
    current_user_id = get_jwt_identity()

    alert = PredictAlert.query.filter_by(
        id=alert_id, user_id=current_user_id
    ).first()

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.is_reviewed = True
    db.session.commit()

    return jsonify({
        "message":     "Alert marked as reviewed",
        "alert_id":    alert_id,
        "is_reviewed": True
    }), 200


@predict_bp.route("/api/predict/alerts/<int:alert_id>", methods=["DELETE"])
@jwt_required()
def dismiss_alert(alert_id):
    """
    Permanently dismisses and deletes a CVE alert.
    """
    current_user_id = get_jwt_identity()

    alert = PredictAlert.query.filter_by(
        id=alert_id, user_id=current_user_id
    ).first()

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    db.session.delete(alert)
    db.session.commit()

    return jsonify({
        "message":  "Alert dismissed",
        "alert_id": alert_id
    }), 200