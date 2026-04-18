"""
AIPET X — Cloud-Cost Security Optimizer Routes

Endpoints:
  GET  /api/costsecurity/resources         — list resources
  GET  /api/costsecurity/recommendations   — list recommendations
  PUT  /api/costsecurity/recommendations/<id> — update status
  GET  /api/costsecurity/stats             — metrics + totals
  POST /api/costsecurity/analyse           — run analysis
"""
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.costsecurity.models import CsResource, CsRecommendation

costsecurity_bp = Blueprint("costsecurity", __name__)


@costsecurity_bp.route("/api/costsecurity/resources", methods=["GET"])
@jwt_required()
def list_resources():
    cloud    = request.args.get("cloud_provider")
    sort     = request.args.get("sort", "saving")
    q = CsResource.query
    if cloud: q = q.filter_by(cloud_provider=cloud)
    resources = q.all()
    if sort == "saving":
        resources.sort(key=lambda r: r.monthly_cost - r.optimised_cost, reverse=True)
    elif sort == "security":
        resources.sort(key=lambda r: r.security_score)
    elif sort == "cost":
        resources.sort(key=lambda r: r.monthly_cost, reverse=True)
    return jsonify({"resources": [r.to_dict() for r in resources]})


@costsecurity_bp.route("/api/costsecurity/recommendations", methods=["GET"])
@jwt_required()
def list_recommendations():
    priority = request.args.get("priority")
    status   = request.args.get("status", "open")
    q = CsRecommendation.query
    if priority: q = q.filter_by(priority=priority)
    if status:   q = q.filter_by(status=status)
    recs = q.order_by(CsRecommendation.monthly_saving.desc()).all()
    return jsonify({"recommendations": [r.to_dict() for r in recs]})


@costsecurity_bp.route("/api/costsecurity/recommendations/<int:rid>",
                       methods=["PUT"])
@jwt_required()
def update_recommendation(rid):
    rec  = CsRecommendation.query.get_or_404(rid)
    data = request.get_json(silent=True) or {}
    if "status" in data:
        rec.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "recommendation": rec.to_dict()})


@costsecurity_bp.route("/api/costsecurity/stats", methods=["GET"])
@jwt_required()
def costsecurity_stats():
    resources = CsResource.query.all()
    recs      = CsRecommendation.query.filter_by(status="open").all()

    total_monthly   = sum(r.monthly_cost for r in resources)
    total_optimised = sum(r.optimised_cost for r in resources)
    total_saving    = total_monthly - total_optimised
    total_recs      = len(recs)
    critical_recs   = sum(1 for r in recs if r.priority == "critical")
    avg_security    = round(sum(r.security_score for r in resources) /
                            max(len(resources), 1), 1)

    by_cloud = {}
    by_type  = {}
    for r in resources:
        by_cloud[r.cloud_provider] = by_cloud.get(r.cloud_provider, 0) + r.monthly_cost
        by_type[r.resource_type]   = by_type.get(r.resource_type, 0) + 1

    return jsonify({
        "total_resources":     len(resources),
        "total_monthly_cost":  round(total_monthly, 2),
        "total_optimised":     round(total_optimised, 2),
        "total_monthly_saving":round(total_saving, 2),
        "total_annual_saving": round(total_saving * 12, 2),
        "total_recommendations":total_recs,
        "critical_recommendations":critical_recs,
        "avg_security_score":  avg_security,
        "by_cloud":            {k: round(v, 2) for k,v in by_cloud.items()},
        "by_type":             by_type,
    })


@costsecurity_bp.route("/api/costsecurity/analyse", methods=["POST"])
@jwt_required()
def run_analysis():
    """Re-run cost+security analysis across all resources."""
    resources = CsResource.query.all()
    updated   = 0
    for r in resources:
        # Recalculate security score based on issues
        r.security_score = max(0, 100 - (r.security_issues * 15))
        updated += 1
    db.session.commit()
    stats = {
        "resources_analysed": updated,
        "total_saving": sum(r.monthly_cost - r.optimised_cost for r in resources),
    }
    return jsonify({"success": True, **stats})
