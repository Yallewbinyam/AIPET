"""
AIPET Explain — API Routes
Handles all endpoints for AI-powered explanations.

Endpoints:
    GET  /api/explain/finding/<finding_id> — Get plain English explanation for a finding
    POST /api/explain/report/<scan_id>     — Generate executive report for a scan
    GET  /api/explain/report/<scan_id>     — Retrieve existing executive report
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Finding, Scan, ExplainResult
from dashboard.backend.explain.claude_client import generate_explanation
from dashboard.backend.explain.prompts import finding_explanation_prompt, executive_report_prompt

explain_bp = Blueprint("explain", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]


def check_plan_access(user):
    """
    Checks if the user's plan allows access to AIPET Explain.
    Returns True if allowed, False if not.
    """
    return user.plan in ALLOWED_PLANS


@explain_bp.route("/api/explain/finding/<int:finding_id>", methods=["GET"])
@jwt_required()
def explain_finding(finding_id):
    """
    Returns a plain English explanation for a specific finding.

    First checks if an explanation already exists in the database.
    If yes — returns it instantly (no API call).
    If no  — generates it via Claude, stores it, returns it.

    Access: Professional and Enterprise plans only.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Check plan access
    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Explain is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    # Verify finding exists and belongs to this user
    finding = Finding.query.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404

    scan = Scan.query.filter_by(id=finding.scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Unauthorised"}), 403

    # Check if explanation already exists in database
    existing = ExplainResult.query.filter_by(
        finding_id=finding_id,
        explain_type="finding"
    ).first()

    if existing:
        return jsonify({
            "finding_id":  finding_id,
            "content":     existing.content,
            "model":       existing.model_used,
            "tokens_used": existing.tokens_used,
            "cached":      True
        }), 200

    # Generate new explanation via Claude
    prompt = finding_explanation_prompt(finding.to_dict())
    result = generate_explanation(prompt)

    if not result["success"]:
        return jsonify({
            "error":   "Failed to generate explanation",
            "details": result.get("error", "Unknown error")
        }), 500

    # Store the result in the database
    explain_result = ExplainResult(
        scan_id      = finding.scan_id,
        finding_id   = finding_id,
        explain_type = "finding",
        content      = result["content"],
        model_used   = result["model"],
        tokens_used  = result["tokens_used"]
    )
    db.session.add(explain_result)
    db.session.commit()

    return jsonify({
        "finding_id":  finding_id,
        "content":     result["content"],
        "model":       result["model"],
        "tokens_used": result["tokens_used"],
        "cached":      False
    }), 200


@explain_bp.route("/api/explain/report/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_executive_report(scan_id):
    """
    Retrieves an existing executive report for a scan.
    Returns 404 if no report has been generated yet.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Explain is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    existing = ExplainResult.query.filter_by(
        scan_id=scan_id,
        explain_type="executive_report"
    ).first()

    if not existing:
        return jsonify({
            "error":     "No report generated yet",
            "generated": False
        }), 404

    return jsonify({
        "scan_id":     scan_id,
        "content":     existing.content,
        "model":       existing.model_used,
        "tokens_used": existing.tokens_used,
        "generated":   True,
        "created_at":  str(existing.created_at)
    }), 200


@explain_bp.route("/api/explain/report/<int:scan_id>", methods=["POST"])
@jwt_required()
def generate_executive_report(scan_id):
    """
    Generates a CEO-readable executive report for a complete scan.

    Gathers all findings for the scan, builds a structured prompt,
    calls Claude, stores the result, and returns it.

    If a report already exists it is regenerated fresh — POST always
    generates a new report so users can refresh after fixing findings.

    Access: Professional and Enterprise plans only.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Explain is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Gather all findings for this scan
    findings = Finding.query.filter_by(scan_id=scan_id).all()

    if not findings:
        return jsonify({
            "error": "No findings found for this scan. Run a scan first."
        }), 400

    # Calculate fix statistics
    fixed_count      = sum(1 for f in findings if f.fix_status == "fixed")
    severity_weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
    total_risk       = sum(severity_weights.get(f.severity, 5) for f in findings)
    reduced_risk     = sum(
        severity_weights.get(f.severity, 5)
        for f in findings
        if f.fix_status in ["fixed", "accepted_risk"]
    )
    risk_reduction_pct = round((reduced_risk / total_risk * 100), 1) if total_risk > 0 else 0

    # Determine overall risk level
    critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
    high_count     = sum(1 for f in findings if f.severity.lower() == "high")

    if critical_count >= 3:
        risk_level = "CRITICAL"
    elif critical_count >= 1:
        risk_level = "HIGH"
    elif high_count >= 3:
        risk_level = "HIGH"
    elif high_count >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Build top findings list (sorted by severity)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.severity, 4)
    )
    top_findings = [
        {
            "attack":   f.attack,
            "severity": f.severity,
            "target":   f.target
        }
        for f in sorted_findings[:5]
    ]

    # Build scan data for prompt
    scan_data = {
        "target":             scan.target,
        "total_findings":     len(findings),
        "critical":           critical_count,
        "high":               high_count,
        "medium":             sum(1 for f in findings if f.severity.lower() == "medium"),
        "low":                sum(1 for f in findings if f.severity.lower() == "low"),
        "risk_level":         risk_level,
        "devices_scanned":    len(set(f.target for f in findings if f.target)),
        "fixed_count":        fixed_count,
        "risk_reduction_pct": risk_reduction_pct,
        "top_findings":       top_findings
    }

    # Generate the report via Claude
    prompt = executive_report_prompt(scan_data)
    result = generate_explanation(prompt, max_tokens=1000)

    if not result["success"]:
        return jsonify({
            "error":   "Failed to generate report",
            "details": result.get("error", "Unknown error")
        }), 500

    # Delete any existing report for this scan and store fresh one
    ExplainResult.query.filter_by(
        scan_id=scan_id,
        explain_type="executive_report"
    ).delete()

    explain_result = ExplainResult(
        scan_id      = scan_id,
        finding_id   = None,
        explain_type = "executive_report",
        content      = result["content"],
        model_used   = result["model"],
        tokens_used  = result["tokens_used"]
    )
    db.session.add(explain_result)
    db.session.commit()

    return jsonify({
        "scan_id":     scan_id,
        "content":     result["content"],
        "model":       result["model"],
        "tokens_used": result["tokens_used"],
        "generated":   True
    }), 200