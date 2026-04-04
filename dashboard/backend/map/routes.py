"""
AIPET Map — Network Attack Map Routes
Handles all endpoints for network attack path visualisation.

Endpoints:
    GET /api/map/<scan_id>        — Get full network graph for a scan
    GET /api/map/<scan_id>/paths  — Get attack paths only (for animation)
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import Finding, Scan, DeviceTag
from dashboard.backend.map.graph import build_graph

map_bp = Blueprint("map", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]


def check_plan_access(user):
    """Checks if the user's plan allows access to AIPET Map."""
    return user.plan in ALLOWED_PLANS


@map_bp.route("/api/map/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_network_map(scan_id):
    """
    Returns the complete network graph for a scan.

    Fetches all findings, loads device tags, runs the graph
    calculator, and returns nodes, edges, attack paths,
    recommendations, and stats.

    Access: Professional and Enterprise plans only.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Map is available on Professional and Enterprise plans.",
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
            "nodes":           [],
            "edges":           [],
            "attack_paths":    [],
            "recommendations": [],
            "stats": {
                "total_devices":   0,
                "entry_points":    0,
                "critical_assets": 0,
                "attack_paths":    0,
                "total_findings":  0,
            },
            "message": "No findings found for this scan."
        }), 200

    # Get device tags for this user
    tags    = DeviceTag.query.filter_by(user_id=current_user_id).all()
    device_tags = {t.device_ip: t.business_function for t in tags}

    # Convert findings to dicts
    findings_data = [f.to_dict() for f in findings]

    # Build the graph
    graph = build_graph(findings_data, device_tags)

    return jsonify(graph), 200


@map_bp.route("/api/map/<int:scan_id>/paths", methods=["GET"])
@jwt_required()
def get_attack_paths(scan_id):
    """
    Returns just the attack paths for a scan.
    Used by the frontend to animate attack paths
    without re-fetching the full graph.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not check_plan_access(user):
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Map is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings    = Finding.query.filter_by(scan_id=scan_id).all()
    tags        = DeviceTag.query.filter_by(user_id=current_user_id).all()
    device_tags = {t.device_ip: t.business_function for t in tags}
    findings_data = [f.to_dict() for f in findings]

    graph = build_graph(findings_data, device_tags)

    return jsonify({
        "attack_paths":    graph["attack_paths"],
        "recommendations": graph["recommendations"],
        "stats":           graph["stats"],
    }), 200