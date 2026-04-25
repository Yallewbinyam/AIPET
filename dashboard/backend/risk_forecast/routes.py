"""
AIPET X — Risk Forecast Endpoints (Capability 11)

GET  /api/forecast/scores              — all entity forecasts for current user
GET  /api/forecast/<entity>            — single entity forecast (?recompute=true for live)
GET  /api/forecast/alerts              — forecast alerts (?status=active)
PUT  /api/forecast/alerts/<id>/acknowledge
PUT  /api/forecast/alerts/<id>/dismiss
GET  /api/forecast/stats               — summary stats
POST /api/forecast/recompute_all       — trigger hourly forecast (1/hour rate limit)
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from dashboard.backend.models import db
from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory, ForecastAlert
from dashboard.backend.risk_forecast.engine import (
    forecast_for_entity,
    forecast_all_entities,
    get_history_for_entity,
)

risk_forecast_bp = Blueprint("risk_forecast", __name__)


@risk_forecast_bp.route("/api/forecast/scores", methods=["GET"])
@jwt_required()
def list_forecasts():
    """Latest per-entity forecasts derived from stored history."""
    uid   = int(get_jwt_identity())
    limit = min(int(request.args.get("limit", 50)), 200)

    # Get distinct entities with any history
    entities = (
        db.session.query(
            DeviceRiskScoreHistory.entity,
            DeviceRiskScoreHistory.entity_type,
        )
        .filter_by(user_id=uid)
        .distinct()
        .all()
    )

    results = []
    for entity, entity_type in entities:
        result = forecast_for_entity(uid, entity, entity_type)
        results.append(result)
        if len(results) >= limit:
            break

    # Sort: increasing trend first, then by current_score desc
    trend_order = {"increasing": 0, "stable": 1, "decreasing": 2, "unknown": 3}
    results.sort(key=lambda r: (trend_order.get(r.get("trend", "unknown"), 3),
                                -r.get("current_score", 0)))

    return jsonify({"forecasts": results, "total": len(results)}), 200


@risk_forecast_bp.route("/api/forecast/alerts", methods=["GET"])
@jwt_required()
def list_alerts():
    uid    = int(get_jwt_identity())
    status = request.args.get("status", "active")
    limit  = min(int(request.args.get("limit", 50)), 200)

    q = ForecastAlert.query.filter_by(user_id=uid)
    if status and status != "all":
        q = q.filter_by(status=status)
    rows = q.order_by(ForecastAlert.created_at.desc()).limit(limit).all()
    return jsonify({"alerts": [r.to_dict() for r in rows], "total": len(rows)}), 200


@risk_forecast_bp.route("/api/forecast/alerts/<int:alert_id>/acknowledge", methods=["PUT"])
@jwt_required()
def acknowledge_alert(alert_id):
    uid  = int(get_jwt_identity())
    row  = ForecastAlert.query.filter_by(id=alert_id, user_id=uid).first()
    if not row:
        return jsonify({"error": "Alert not found"}), 404
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row.status          = "acknowledged"
    row.acknowledged_at = now
    db.session.commit()
    return jsonify({"success": True, "alert": row.to_dict()}), 200


@risk_forecast_bp.route("/api/forecast/alerts/<int:alert_id>/dismiss", methods=["PUT"])
@jwt_required()
def dismiss_alert(alert_id):
    uid = int(get_jwt_identity())
    row = ForecastAlert.query.filter_by(id=alert_id, user_id=uid).first()
    if not row:
        return jsonify({"error": "Alert not found"}), 404
    row.status = "dismissed"
    db.session.commit()
    return jsonify({"success": True, "alert": row.to_dict()}), 200


@risk_forecast_bp.route("/api/forecast/stats", methods=["GET"])
@jwt_required()
def forecast_stats():
    uid = int(get_jwt_identity())

    entities = (
        db.session.query(DeviceRiskScoreHistory.entity, DeviceRiskScoreHistory.entity_type)
        .filter_by(user_id=uid).distinct().all()
    )

    by_trend  = {"increasing": 0, "stable": 0, "decreasing": 0, "unknown": 0}
    by_status = {"ok": 0, "low_confidence": 0, "insufficient_data": 0}

    for entity, entity_type in entities:
        r = forecast_for_entity(uid, entity, entity_type)
        by_trend[r.get("trend", "unknown")] = by_trend.get(r.get("trend", "unknown"), 0) + 1
        by_status[r.get("status", "insufficient_data")] = (
            by_status.get(r.get("status", "insufficient_data"), 0) + 1
        )

    active_alerts = ForecastAlert.query.filter_by(user_id=uid, status="active").count()
    by_threshold  = {}
    for row in ForecastAlert.query.filter_by(user_id=uid, status="active").all():
        by_threshold[row.threshold_name] = by_threshold.get(row.threshold_name, 0) + 1

    return jsonify({
        "total_forecasts":    len(entities),
        "by_trend":           by_trend,
        "by_status":          by_status,
        "active_alerts_count": active_alerts,
        "alerts_by_threshold": by_threshold,
    }), 200


@risk_forecast_bp.route("/api/forecast/<path:entity>", methods=["GET"])
@jwt_required()
def get_entity_forecast(entity):
    """
    Returns the live forecast for this entity.
    ?recompute=true forces a fresh computation (rate-limited at call site).
    """
    uid        = int(get_jwt_identity())
    history    = get_history_for_entity(uid, entity)
    if not history and request.args.get("recompute", "false").lower() != "true":
        return jsonify({"error": "No history found for this entity"}), 404
    result = forecast_for_entity(uid, entity)
    return jsonify(result), 200


@risk_forecast_bp.route("/api/forecast/recompute_all", methods=["POST"])
@jwt_required()
def recompute_all():
    """
    Trigger forecast computation for current user. Rate-limited 1/hour via
    Flask-Limiter view_functions reassignment in app_cloud.py.
    """
    uid = int(get_jwt_identity())
    try:
        from dashboard.backend.tasks import generate_risk_forecasts
        task = generate_risk_forecasts.delay(user_id=uid)
        return jsonify({
            "status":  "queued",
            "task_id": task.id,
            "message": "Forecast recompute queued. Check /api/forecast/scores in ~60s.",
        }), 202
    except Exception as exc:
        from flask import current_app
        current_app.logger.exception("recompute_all: failed to queue forecast task")
        return jsonify({"error": "Failed to queue forecast", "detail": str(exc)}), 500
