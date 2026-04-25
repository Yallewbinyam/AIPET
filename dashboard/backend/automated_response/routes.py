"""
AIPET X — Automated Response Endpoints

GET  /api/response/thresholds          — list user's thresholds (seeds defaults on first call)
PUT  /api/response/thresholds/<id>     — update a threshold
GET  /api/response/history             — response history with filters
GET  /api/response/history/<id>        — single history row
GET  /api/response/stats               — 24h summary by threshold and status
POST /api/response/check_now           — trigger recompute+check for current user (1/hour)
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from dashboard.backend.models import db
from dashboard.backend.automated_response.models import ResponseThreshold, ResponseHistory
from dashboard.backend.automated_response.engine import (
    seed_default_thresholds_for_user,
    check_thresholds_and_respond,
)
from dashboard.backend.validation import validate_body, THRESHOLD_UPDATE_SCHEMA

automated_response_bp = Blueprint("automated_response", __name__)


@automated_response_bp.route("/api/response/thresholds", methods=["GET"])
@jwt_required()
def list_thresholds():
    uid = int(get_jwt_identity())
    seed_default_thresholds_for_user(uid)
    rows = (
        ResponseThreshold.query
        .filter_by(user_id=uid)
        .order_by(ResponseThreshold.min_score.desc())
        .all()
    )
    return jsonify({"thresholds": [r.to_dict() for r in rows]}), 200


@automated_response_bp.route("/api/response/thresholds/<int:threshold_id>", methods=["PUT"])
@jwt_required()
@validate_body(THRESHOLD_UPDATE_SCHEMA)
def update_threshold(threshold_id):
    uid  = int(get_jwt_identity())
    row  = ResponseThreshold.query.filter_by(id=threshold_id, user_id=uid).first()
    if not row:
        return jsonify({"error": "Threshold not found or not owned by you"}), 404

    data = request.get_json(silent=True) or {}
    now  = datetime.now(timezone.utc).replace(tzinfo=None)

    if "min_score"      in data: row.min_score      = int(data["min_score"])
    if "enabled"        in data: row.enabled        = bool(data["enabled"])
    if "cooldown_hours" in data: row.cooldown_hours = int(data["cooldown_hours"])
    if "playbook_id"    in data: row.playbook_id    = data["playbook_id"]
    row.last_modified_at = now

    db.session.commit()
    return jsonify({"success": True, "threshold": row.to_dict()}), 200


@automated_response_bp.route("/api/response/history", methods=["GET"])
@jwt_required()
def response_history():
    uid    = int(get_jwt_identity())
    limit  = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    entity = request.args.get("entity")
    since  = request.args.get("since")

    q = ResponseHistory.query.filter_by(user_id=uid)
    if entity:
        q = q.filter(ResponseHistory.entity == entity)
    if since:
        try:
            dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
            q  = q.filter(ResponseHistory.fired_at >= dt)
        except ValueError:
            return jsonify({"error": "Invalid 'since' datetime format"}), 400

    total = q.count()
    rows  = q.order_by(ResponseHistory.fired_at.desc()).offset(offset).limit(limit).all()
    return jsonify({
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "history": [r.to_dict() for r in rows],
    }), 200


@automated_response_bp.route("/api/response/history/<int:history_id>", methods=["GET"])
@jwt_required()
def get_history_entry(history_id):
    uid = int(get_jwt_identity())
    row = ResponseHistory.query.filter_by(id=history_id, user_id=uid).first()
    if not row:
        return jsonify({"error": "History entry not found"}), 404
    return jsonify(row.to_dict()), 200


@automated_response_bp.route("/api/response/stats", methods=["GET"])
@jwt_required()
def response_stats():
    uid = int(get_jwt_identity())
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

    rows = ResponseHistory.query.filter(
        ResponseHistory.user_id  == uid,
        ResponseHistory.fired_at >= cutoff,
    ).all()

    by_threshold = {}
    by_status    = {}
    by_entity: dict[str, int] = {}

    for r in rows:
        by_threshold[r.threshold_name or "unknown"] = by_threshold.get(r.threshold_name or "unknown", 0) + 1
        by_status[r.status]                          = by_status.get(r.status, 0) + 1
        by_entity[r.entity]                          = by_entity.get(r.entity, 0) + 1

    top_entities = sorted(by_entity.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify({
        "total_responses_24h": len(rows),
        "by_threshold":        by_threshold,
        "by_status":           by_status,
        "by_entity_top_5":     [{"entity": e, "count": c} for e, c in top_entities],
    }), 200


@automated_response_bp.route("/api/response/check_now", methods=["POST"])
@jwt_required()
def check_now():
    """
    Trigger recompute + threshold check for the current user only.
    Rate-limited to 1/hour via Flask-Limiter view_functions reassignment in app_cloud.py.
    """
    uid = int(get_jwt_identity())
    try:
        from dashboard.backend.tasks import recompute_device_risk_scores
        task = recompute_device_risk_scores.delay(user_id=uid)
        return jsonify({
            "status":  "queued",
            "task_id": task.id,
            "message": "Recompute and response check queued. Check /api/response/history in ~30s.",
        }), 202
    except Exception as exc:
        from flask import current_app
        current_app.logger.exception("check_now: failed to queue task")
        return jsonify({"error": "Failed to queue check", "detail": str(exc)}), 500
