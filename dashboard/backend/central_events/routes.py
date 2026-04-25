# ============================================================
# AIPET X — Central Event Pipeline Routes
# ============================================================
#
# GET /api/events/feed          — paginated event feed with filters
# GET /api/events/stats         — counts by severity, module, entity
# GET /api/events/<id>          — single event detail
# GET /api/events/entity/<name> — all events for a device/IP/user
#
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from dashboard.backend.central_events.models import CentralEvent
from dashboard.backend.models import db

central_events_bp = Blueprint("central_events", __name__)


@central_events_bp.route("/api/events/feed", methods=["GET"])
@jwt_required()
def feed():
    """
    GET /api/events/feed
    Query params:
      days (1-90, default 7)   — time window
      severity                  — filter by severity
      source_module             — filter by originating module
      entity                    — filter by entity (exact match)
      event_type                — filter by event_type
      limit (max 200, default 50)
      offset (default 0)
    """
    days    = min(int(request.args.get("days", 7)), 90)
    limit   = min(int(request.args.get("limit", 50)), 200)
    offset  = int(request.args.get("offset", 0))
    since   = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    q = CentralEvent.query.filter(CentralEvent.created_at >= since)

    for param, col in [
        ("severity",      CentralEvent.severity),
        ("source_module", CentralEvent.source_module),
        ("entity",        CentralEvent.entity),
        ("event_type",    CentralEvent.event_type),
    ]:
        val = request.args.get(param, "").strip()
        if val:
            q = q.filter(col == val)

    total  = q.count()
    events = q.order_by(CentralEvent.created_at.desc()).offset(offset).limit(limit).all()

    return jsonify({
        "events": [e.to_dict() for e in events],
        "total":  total,
        "offset": offset,
        "limit":  limit,
    })


@central_events_bp.route("/api/events/stats", methods=["GET"])
@jwt_required()
def stats():
    """
    GET /api/events/stats — counts by severity, source_module, top entities.
    """
    from sqlalchemy import func

    days  = min(int(request.args.get("days", 7)), 90)
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    base = CentralEvent.query.filter(CentralEvent.created_at >= since)
    total = base.count()

    by_severity = (
        db.session.query(CentralEvent.severity, func.count())
        .filter(CentralEvent.created_at >= since)
        .group_by(CentralEvent.severity)
        .order_by(func.count().desc())
        .all()
    )
    by_module = (
        db.session.query(CentralEvent.source_module, func.count())
        .filter(CentralEvent.created_at >= since)
        .group_by(CentralEvent.source_module)
        .order_by(func.count().desc())
        .limit(10).all()
    )
    top_entities = (
        db.session.query(CentralEvent.entity, func.count())
        .filter(CentralEvent.created_at >= since, CentralEvent.entity.isnot(None))
        .group_by(CentralEvent.entity)
        .order_by(func.count().desc())
        .limit(10).all()
    )

    return jsonify({
        "total":        total,
        "days":         days,
        "by_severity":  [{"severity": s, "count": c} for s, c in by_severity],
        "by_module":    [{"module": m, "count": c} for m, c in by_module],
        "top_entities": [{"entity": e, "count": c} for e, c in top_entities],
    })


@central_events_bp.route("/api/events/<int:event_id>", methods=["GET"])
@jwt_required()
def get_event(event_id):
    """GET /api/events/<id> — single event or 404."""
    ev = db.session.get(CentralEvent, event_id)
    if ev is None:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(ev.to_dict())


@central_events_bp.route("/api/events/entity/<path:entity_name>", methods=["GET"])
@jwt_required()
def entity_timeline(entity_name):
    """GET /api/events/entity/<name> — all central events for one entity, newest first."""
    days   = min(int(request.args.get("days", 30)), 90)
    limit  = min(int(request.args.get("limit", 100)), 200)
    since  = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    events = (
        CentralEvent.query
        .filter(CentralEvent.entity == entity_name,
                CentralEvent.created_at >= since)
        .order_by(CentralEvent.created_at.desc())
        .limit(limit).all()
    )
    return jsonify({
        "entity": entity_name,
        "events": [e.to_dict() for e in events],
        "count":  len(events),
    })
