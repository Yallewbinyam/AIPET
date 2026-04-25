"""
AIPET X — Device Risk Score Endpoints

GET  /api/risk/scores              — paginated list for current user
GET  /api/risk/<entity>            — single entity score (?recompute=true for live)
GET  /api/risk/top                 — top-N highest-risk entities
GET  /api/risk/stats               — bucket summary for current user
POST /api/risk/recompute_now       — trigger per-user recompute (rate: 1/hour)
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from dashboard.backend.models import db
from dashboard.backend.risk_engine.models import DeviceRiskScore
from dashboard.backend.risk_engine.engine import (
    compute_score_for_entity,
    upsert_score_for_entity,
    recompute_all_scores,
)

risk_engine_bp = Blueprint("risk_engine", __name__)


@risk_engine_bp.route("/api/risk/scores", methods=["GET"])
@jwt_required()
def list_scores():
    """Paginated device risk scores for the current user."""
    uid       = int(get_jwt_identity())
    limit     = min(int(request.args.get("limit", 50)), 200)
    offset    = int(request.args.get("offset", 0))
    min_score = int(request.args.get("min_score", 0))
    order     = request.args.get("order", "desc").lower()

    q = DeviceRiskScore.query.filter(
        DeviceRiskScore.user_id == uid,
        DeviceRiskScore.score   >= min_score,
    )
    if order == "asc":
        q = q.order_by(DeviceRiskScore.score.asc())
    else:
        q = q.order_by(DeviceRiskScore.score.desc())

    total = q.count()
    rows  = q.offset(offset).limit(limit).all()
    return jsonify({
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "scores":  [r.to_dict() for r in rows],
    }), 200


@risk_engine_bp.route("/api/risk/top", methods=["GET"])
@jwt_required()
def top_scores():
    """Top-N highest-risk entities for the current user."""
    uid   = int(get_jwt_identity())
    limit = min(int(request.args.get("limit", 10)), 50)
    rows  = (
        DeviceRiskScore.query
        .filter_by(user_id=uid)
        .order_by(DeviceRiskScore.score.desc())
        .limit(limit)
        .all()
    )
    return jsonify({"top": [r.to_dict() for r in rows]}), 200


@risk_engine_bp.route("/api/risk/stats", methods=["GET"])
@jwt_required()
def risk_stats():
    """Score-bucket summary for the current user."""
    uid  = int(get_jwt_identity())
    rows = DeviceRiskScore.query.filter_by(user_id=uid).all()

    if not rows:
        return jsonify({
            "total_entities":  0,
            "by_score_bucket": {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0},
            "average_score":   None,
            "max_score":       None,
            "last_recompute_at": None,
        }), 200

    scores = [r.score for r in rows]
    buckets = {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0}
    for s in scores:
        if s <= 25:
            buckets["0-25"] += 1
        elif s <= 50:
            buckets["26-50"] += 1
        elif s <= 75:
            buckets["51-75"] += 1
        else:
            buckets["76-100"] += 1

    latest = max((r.last_recomputed_at for r in rows if r.last_recomputed_at),
                 default=None)

    return jsonify({
        "total_entities":    len(rows),
        "by_score_bucket":   buckets,
        "average_score":     round(sum(scores) / len(scores), 1),
        "max_score":         max(scores),
        "last_recompute_at": latest.isoformat() if latest else None,
    }), 200


@risk_engine_bp.route("/api/risk/<path:entity>", methods=["GET"])
@jwt_required()
def get_entity_score(entity):
    """
    Return stored score for one entity.
    ?recompute=true forces a live recompute (rate-limited at call site).
    """
    uid       = int(get_jwt_identity())
    recompute = request.args.get("recompute", "false").lower() == "true"

    if recompute:
        result = upsert_score_for_entity(uid, entity)
        return jsonify(result), 200

    row = DeviceRiskScore.query.filter_by(user_id=uid, entity=entity).first()
    if not row:
        return jsonify({"error": "No risk score found for this entity"}), 404
    return jsonify(row.to_dict()), 200


@risk_engine_bp.route("/api/risk/recompute_now", methods=["POST"])
@jwt_required()
def recompute_now():
    """
    Trigger an async risk score recompute for the current user.
    Rate-limited at 1/hour via Flask-Limiter view_functions reassignment
    in app_cloud.py.
    Returns 202 with the Celery task id.
    """
    uid = int(get_jwt_identity())
    try:
        from dashboard.backend.tasks import recompute_device_risk_scores
        task = recompute_device_risk_scores.delay(user_id=uid)
        return jsonify({
            "status":  "queued",
            "task_id": task.id,
            "message": "Recompute queued. Check /api/risk/scores in ~30s.",
        }), 202
    except Exception as exc:
        from flask import current_app
        current_app.logger.exception("recompute_now: failed to queue task")
        return jsonify({"error": "Failed to queue recompute", "detail": str(exc)}), 500
