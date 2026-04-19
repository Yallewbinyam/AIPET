"""
AIPET X — Resilience Engine Routes

Endpoints:
  GET  /api/resilience/assets          — list all assets
  GET  /api/resilience/assets/<id>     — asset detail + plan + tests
  PUT  /api/resilience/assets/<id>     — update asset
  GET  /api/resilience/plans           — list all DR plans
  POST /api/resilience/plans           — create DR plan
  PUT  /api/resilience/plans/<id>      — update plan
  GET  /api/resilience/tests           — list all tests
  POST /api/resilience/tests           — log a test result
  POST /api/resilience/simulate/<id>   — simulate failover
  GET  /api/resilience/stats           — resilience metrics
"""
import json, random
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.resilience.models import ReAsset, RePlan, ReTest

resilience_bp = Blueprint("resilience", __name__)


def _calculate_readiness(asset):
    """Calculate readiness score 0-100 for an asset."""
    score = 0
    if asset.has_dr_plan:    score += 25
    if asset.has_backup:     score += 25
    if asset.backup_tested:  score += 25
    if asset.failover_ready: score += 15
    if asset.last_tested:
        days_since = (datetime.now(timezone.utc) -
                      asset.last_tested.replace(tzinfo=timezone.utc)).days
        if days_since < 30:   score += 10
        elif days_since < 90: score += 5
    return min(100, score)


@resilience_bp.route("/api/resilience/assets", methods=["GET"])
@jwt_required()
def list_assets():
    criticality = request.args.get("criticality")
    q = ReAsset.query
    if criticality: q = q.filter_by(criticality=criticality)
    assets = q.order_by(ReAsset.readiness_score.asc()).all()
    return jsonify({"assets": [a.to_dict() for a in assets]})


@resilience_bp.route("/api/resilience/assets/<int:aid>", methods=["GET"])
@jwt_required()
def get_asset(aid):
    asset  = ReAsset.query.get_or_404(aid)
    plans  = RePlan.query.filter_by(asset_id=aid).all()
    tests  = ReTest.query.filter_by(asset_id=aid).order_by(
        ReTest.created_at.desc()).limit(10).all()
    data   = asset.to_dict()
    data["plans"] = [p.to_dict() for p in plans]
    data["tests"] = [t.to_dict() for t in tests]
    return jsonify(data)


@resilience_bp.route("/api/resilience/assets/<int:aid>", methods=["PUT"])
@jwt_required()
def update_asset(aid):
    asset = ReAsset.query.get_or_404(aid)
    data  = request.get_json(silent=True) or {}
    for field in ["has_dr_plan","has_backup","backup_tested",
                  "failover_ready","rto_target","rpo_target"]:
        if field in data:
            setattr(asset, field, data[field])
    asset.readiness_score = _calculate_readiness(asset)
    db.session.commit()
    return jsonify({"success": True, "asset": asset.to_dict()})


@resilience_bp.route("/api/resilience/plans", methods=["GET"])
@jwt_required()
def list_plans():
    plans = RePlan.query.order_by(RePlan.created_at.desc()).all()
    return jsonify({"plans": [p.to_dict() for p in plans]})


@resilience_bp.route("/api/resilience/plans", methods=["POST"])
@jwt_required()
def create_plan():
    data = request.get_json(silent=True) or {}
    if not data.get("asset_id") or not data.get("title"):
        return jsonify({"error": "asset_id and title required"}), 400
    plan = RePlan(
        asset_id    = data["asset_id"],
        title       = data["title"],
        description = data.get("description"),
        steps       = json.dumps(data.get("steps", [])),
        contacts    = json.dumps(data.get("contacts", [])),
        status      = "active",
        last_reviewed = datetime.now(timezone.utc),
    )
    db.session.add(plan)
    # Mark asset as having a DR plan
    asset = ReAsset.query.get(data["asset_id"])
    if asset:
        asset.has_dr_plan     = True
        asset.readiness_score = _calculate_readiness(asset)
    db.session.commit()
    return jsonify({"success": True, "plan": plan.to_dict()}), 201


@resilience_bp.route("/api/resilience/plans/<int:pid>", methods=["PUT"])
@jwt_required()
def update_plan(pid):
    plan = RePlan.query.get_or_404(pid)
    data = request.get_json(silent=True) or {}
    for field in ["title","description","status"]:
        if field in data:
            setattr(plan, field, data[field])
    if "steps" in data:
        plan.steps = json.dumps(data["steps"])
    plan.last_reviewed = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "plan": plan.to_dict()})


@resilience_bp.route("/api/resilience/tests", methods=["GET"])
@jwt_required()
def list_tests():
    tests = ReTest.query.order_by(
        ReTest.created_at.desc()).limit(50).all()
    return jsonify({"tests": [t.to_dict() for t in tests]})


@resilience_bp.route("/api/resilience/tests", methods=["POST"])
@jwt_required()
def create_test():
    data = request.get_json(silent=True) or {}
    if not data.get("asset_id"):
        return jsonify({"error": "asset_id required"}), 400
    test = ReTest(
        asset_id     = data["asset_id"],
        test_type    = data.get("test_type", "tabletop"),
        result       = data.get("result", "passed"),
        rto_achieved = data.get("rto_achieved"),
        rpo_achieved = data.get("rpo_achieved"),
        notes        = data.get("notes"),
        conducted_by = data.get("conducted_by"),
    )
    db.session.add(test)
    asset = ReAsset.query.get(data["asset_id"])
    if asset:
        asset.last_tested   = datetime.now(timezone.utc)
        asset.backup_tested = True
        if data.get("rto_achieved"):
            asset.rto_actual = data["rto_achieved"]
        if data.get("rpo_achieved"):
            asset.rpo_actual = data["rpo_achieved"]
        asset.readiness_score = _calculate_readiness(asset)
    db.session.commit()
    return jsonify({"success": True, "test": test.to_dict()}), 201


@resilience_bp.route("/api/resilience/simulate/<int:aid>",
                     methods=["POST"])
@jwt_required()
def simulate_failover(aid):
    """
    Safe failover simulation — no real systems affected.
    Calculates estimated recovery time based on DR plan maturity.
    """
    asset = ReAsset.query.get_or_404(aid)
    plan  = RePlan.query.filter_by(asset_id=aid).first()

    # Simulate recovery time based on readiness
    base_rto = asset.rto_target
    if asset.failover_ready: multiplier = 0.8
    elif asset.has_backup:   multiplier = 1.5
    else:                    multiplier = 3.0

    simulated_rto = round(base_rto * multiplier, 1)
    simulated_rpo = round(asset.rpo_target * (1.2 if asset.has_backup else 2.5), 1)
    rto_met       = simulated_rto <= asset.rto_target
    rpo_met       = simulated_rpo <= asset.rpo_target

    steps_completed = []
    steps_failed    = []

    if plan:
        plan_steps = json.loads(plan.steps) if plan.steps else []
        for i, step in enumerate(plan_steps):
            if asset.readiness_score >= 75 or i < len(plan_steps) * 0.8:
                steps_completed.append(step)
            else:
                steps_failed.append(step)
    else:
        steps_failed = ["No DR plan found — manual recovery required"]

    result = {
        "success":           True,
        "asset":             asset.name,
        "simulation_type":   "Failover Simulation (Safe — No Real Impact)",
        "simulated_rto":     simulated_rto,
        "simulated_rpo":     simulated_rpo,
        "rto_target":        asset.rto_target,
        "rpo_target":        asset.rpo_target,
        "rto_met":           rto_met,
        "rpo_met":           rpo_met,
        "readiness_score":   asset.readiness_score,
        "steps_completed":   steps_completed,
        "steps_failed":      steps_failed,
        "recommendation":    (
            "DR plan is effective — RTO and RPO targets met"
            if rto_met and rpo_met else
            "DR plan needs improvement — consider automated failover"
            if asset.has_backup else
            "CRITICAL: No backup or DR plan — immediate action required"
        ),
    }

    # Log the simulation as a test
    test = ReTest(
        asset_id     = aid,
        test_type    = "simulation",
        result       = "passed" if rto_met and rpo_met else "failed",
        rto_achieved = simulated_rto,
        rpo_achieved = simulated_rpo,
        notes        = f"Automated simulation — {result['recommendation']}",
        conducted_by = "AIPET X Resilience Engine",
    )
    db.session.add(test)
    asset.last_tested     = datetime.now(timezone.utc)
    asset.rto_actual      = simulated_rto
    asset.rpo_actual      = simulated_rpo
    asset.readiness_score = _calculate_readiness(asset)
    db.session.commit()
    return jsonify(result)


@resilience_bp.route("/api/resilience/stats", methods=["GET"])
@jwt_required()
def resilience_stats():
    assets = ReAsset.query.all()
    plans  = RePlan.query.all()
    tests  = ReTest.query.all()

    no_plan    = sum(1 for a in assets if not a.has_dr_plan)
    no_backup  = sum(1 for a in assets if not a.has_backup)
    rto_breach = sum(1 for a in assets
                     if a.rto_actual and a.rto_actual > a.rto_target)
    avg_score  = round(sum(a.readiness_score for a in assets) /
                       max(len(assets), 1), 1)
    by_criticality = {}
    for a in assets:
        by_criticality[a.criticality] =             by_criticality.get(a.criticality, 0) + 1

    return jsonify({
        "total_assets":      len(assets),
        "total_plans":       len(plans),
        "total_tests":       len(tests),
        "no_dr_plan":        no_plan,
        "no_backup":         no_backup,
        "rto_breached":      rto_breach,
        "avg_readiness":     avg_score,
        "fully_ready":       sum(1 for a in assets if a.readiness_score >= 75),
        "critical_gaps":     sum(1 for a in assets
                                 if a.criticality == "Critical"
                                 and not a.has_dr_plan),
        "by_criticality":    by_criticality,
    })
