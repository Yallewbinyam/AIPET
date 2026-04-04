"""
AIPET Score — Financial Risk Score Routes
Handles all endpoints for financial risk scoring.

Endpoints:
    POST /api/score/tags              — Save device business function tags
    GET  /api/score/tags              — Get existing device tags for user
    POST /api/score/calculate/<scan_id> — Calculate financial risk score
    GET  /api/score/result/<scan_id>  — Get existing score result
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Finding, Scan, DeviceTag, ScoreResult
from dashboard.backend.score.calculator import (
    calculate_score, BUSINESS_FUNCTIONS, INDUSTRIES
)

score_bp = Blueprint("score", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]


def check_plan_access(user):
    """Checks if the user's plan allows access to AIPET Score."""
    return user.plan in ALLOWED_PLANS


@score_bp.route("/api/score/options", methods=["GET"])
@jwt_required()
def get_options():
    """
    Returns the available business functions and industries
    for the device tagging UI dropdowns.
    No plan restriction — needed to show upgrade prompt correctly.
    """
    return jsonify({
        "business_functions": BUSINESS_FUNCTIONS,
        "industries":         INDUSTRIES,
    }), 200


@score_bp.route("/api/score/tags", methods=["GET"])
@jwt_required()
def get_tags():
    """
    Returns all device tags for the current user.
    Used to pre-populate the device tagging UI.
    """
    current_user_id = get_jwt_identity()
    tags = DeviceTag.query.filter_by(user_id=current_user_id).all()
    return jsonify([t.to_dict() for t in tags]), 200


@score_bp.route("/api/score/tags", methods=["POST"])
@jwt_required()
def save_tags():
    """
    Saves or updates device business function tags for the current user.

    Request body:
    {
        "tags": [
            {"device_ip": "192.168.1.1", "business_function": "Infrastructure / Network"},
            {"device_ip": "192.168.1.2", "business_function": "Customer Data"}
        ],
        "industry": "Healthcare"
    }

    Uses upsert logic — if a tag for this IP already exists it is updated,
    otherwise a new one is created.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Score is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    tags     = data.get("tags", [])
    industry = data.get("industry", "General Business")

    if not tags:
        return jsonify({"error": "No tags provided"}), 400

    if industry not in INDUSTRIES:
        return jsonify({
            "error": f"Invalid industry. Must be one of: {', '.join(INDUSTRIES)}"
        }), 400

    saved = 0
    for tag_data in tags:
        device_ip        = tag_data.get("device_ip")
        business_function = tag_data.get("business_function")

        if not device_ip or not business_function:
            continue

        if business_function not in BUSINESS_FUNCTIONS:
            continue

        # Upsert — update if exists, create if not
        existing = DeviceTag.query.filter_by(
            user_id=current_user_id,
            device_ip=device_ip
        ).first()

        if existing:
            existing.business_function = business_function
            existing.industry          = industry
        else:
            new_tag = DeviceTag(
                user_id          = current_user_id,
                device_ip        = device_ip,
                business_function = business_function,
                industry         = industry
            )
            db.session.add(new_tag)
        saved += 1

    db.session.commit()

    return jsonify({
        "message": f"Successfully saved {saved} device tags",
        "saved":   saved
    }), 200


@score_bp.route("/api/score/calculate/<int:scan_id>", methods=["POST"])
@jwt_required()
def calculate_risk_score(scan_id):
    """
    Calculates the financial risk score for a scan.

    Uses the device tags saved by the user and the findings
    from the specified scan to calculate financial exposure.

    The industry is taken from the user's device tags —
    all devices for a user share the same industry setting.

    Returns the full score result including per-finding breakdown.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Score is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    # Verify scan belongs to this user
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Get all findings for this scan
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return jsonify({
            "error": "No findings found for this scan. Run a scan first."
        }), 400

    # Get device tags for this user
    tags = DeviceTag.query.filter_by(user_id=current_user_id).all()
    device_tags = {t.device_ip: t.business_function for t in tags}

    # Get industry from tags (use first tag's industry, or default)
    industry = tags[0].industry if tags else "General Business"

    # Allow industry override from request body
    data = request.get_json() or {}
    if data.get("industry") and data["industry"] in INDUSTRIES:
        industry = data["industry"]

    # Convert findings to dicts for calculator
    findings_data = [f.to_dict() for f in findings]

    # Run the calculation
    result = calculate_score(findings_data, device_tags, industry)

    # Delete any existing score for this scan and store fresh result
    ScoreResult.query.filter_by(scan_id=scan_id, user_id=current_user_id).delete()

    score_result = ScoreResult(
        scan_id            = scan_id,
        user_id            = current_user_id,
        industry           = industry,
        total_exposure_gbp = result["total_exposure_gbp"],
        findings_breakdown = result["findings_breakdown"]
    )
    db.session.add(score_result)
    db.session.commit()

    return jsonify(result), 200


@score_bp.route("/api/score/result/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_score_result(scan_id):
    """
    Retrieves an existing score result for a scan.
    Returns 404 if no score has been calculated yet.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Score is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    existing = ScoreResult.query.filter_by(
        scan_id=scan_id,
        user_id=current_user_id
    ).first()

    if not existing:
        return jsonify({
            "error":      "No score calculated yet",
            "calculated": False
        }), 404

    return jsonify({
        "calculated":         True,
        "industry":           existing.industry,
        "total_exposure_gbp": existing.total_exposure_gbp,
        "total_exposure_fmt": f"£{existing.total_exposure_gbp:,}",
        "findings_breakdown": existing.findings_breakdown,
        "created_at":         str(existing.created_at),
    }), 200