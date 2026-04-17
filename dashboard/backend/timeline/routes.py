"""
AIPET X — Unified Security Timeline Routes

Endpoints:
  GET  /api/timeline/events         — paginated event feed
  GET  /api/timeline/stats          — counts by source/severity
  POST /api/timeline/events         — create event (internal use)
  PUT  /api/timeline/events/<id>    — mark resolved
  DEL  /api/timeline/events/<id>    — delete event
  GET  /api/timeline/export         — export as JSON
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.timeline.models import TimelineEvent

timeline_bp = Blueprint("timeline", __name__)


def log_event(source, event_type, title, severity="Info",
              detail=None, entity=None, mitre_id=None, user_id=None):
    """
    Helper function — call from any module to log a timeline event.
    Example:
      from dashboard.backend.timeline.routes import log_event
      log_event("scan", "scan_complete", "Scan completed on 192.168.1.1",
                severity="Info", entity="192.168.1.1")
    """
    try:
        event = TimelineEvent(
            source     = source,
            event_type = event_type,
            severity   = severity,
            title      = title,
            detail     = detail,
            entity     = entity,
            mitre_id   = mitre_id,
            user_id    = user_id,
        )
        db.session.add(event)
        db.session.commit()
        return event
    except Exception as e:
        db.session.rollback()
        print(f"[Timeline] Failed to log event: {e}")
        return None


@timeline_bp.route("/api/timeline/events", methods=["GET"])
@jwt_required()
def get_events():
    """
    Get paginated timeline events.
    Query params:
      page:     page number (default 1)
      per_page: events per page (default 50, max 200)
      source:   filter by source module
      severity: filter by severity
      resolved: filter by resolved status (true/false)
      search:   search in title/detail
      days:     last N days (default 30)
    """
    page     = int(request.args.get("page",     1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    source   = request.args.get("source")
    severity = request.args.get("severity")
    resolved = request.args.get("resolved")
    search   = request.args.get("search", "")
    days     = int(request.args.get("days", 30))

    q = TimelineEvent.query

    # Date filter
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = q.filter(TimelineEvent.created_at >= since)

    if source:
        q = q.filter_by(source=source)
    if severity:
        q = q.filter_by(severity=severity)
    if resolved is not None:
        q = q.filter_by(resolved=resolved.lower() == "true")
    if search:
        q = q.filter(
            TimelineEvent.title.ilike(f"%{search}%") |
            TimelineEvent.detail.ilike(f"%{search}%") |
            TimelineEvent.entity.ilike(f"%{search}%")
        )

    q = q.order_by(TimelineEvent.created_at.desc())
    total = q.count()
    events = q.offset((page-1)*per_page).limit(per_page).all()

    return jsonify({
        "events":   [e.to_dict() for e in events],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
    })


@timeline_bp.route("/api/timeline/stats", methods=["GET"])
@jwt_required()
def timeline_stats():
    """Timeline statistics — counts by source and severity."""
    days  = int(request.args.get("days", 30))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    events = TimelineEvent.query.filter(
        TimelineEvent.created_at >= since).all()

    by_source   = {}
    by_severity = {}
    by_day      = {}

    for e in events:
        by_source[e.source]     = by_source.get(e.source, 0) + 1
        by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        day = e.created_at.strftime("%Y-%m-%d")
        by_day[day] = by_day.get(day, 0) + 1

    return jsonify({
        "total":       len(events),
        "unresolved":  sum(1 for e in events if not e.resolved),
        "critical":    sum(1 for e in events if e.severity == "Critical"),
        "by_source":   by_source,
        "by_severity": by_severity,
        "by_day":      by_day,
    })


@timeline_bp.route("/api/timeline/events", methods=["POST"])
@jwt_required()
def create_event():
    """Create a timeline event manually."""
    data = request.get_json(silent=True) or {}
    if not data.get("title") or not data.get("source"):
        return jsonify({"error": "title and source required"}), 400

    event = log_event(
        source     = data["source"],
        event_type = data.get("event_type", "manual"),
        title      = data["title"],
        severity   = data.get("severity", "Info"),
        detail     = data.get("detail"),
        entity     = data.get("entity"),
        mitre_id   = data.get("mitre_id"),
        user_id    = int(get_jwt_identity()),
    )
    if event:
        return jsonify({"success": True, "event": event.to_dict()}), 201
    return jsonify({"error": "Failed to create event"}), 500


@timeline_bp.route("/api/timeline/events/<int:eid>", methods=["PUT"])
@jwt_required()
def update_event(eid):
    """Mark event as resolved or update details."""
    event = TimelineEvent.query.get_or_404(eid)
    data  = request.get_json(silent=True) or {}
    if "resolved" in data:
        event.resolved = bool(data["resolved"])
    if "detail" in data:
        event.detail = data["detail"]
    db.session.commit()
    return jsonify({"success": True, "event": event.to_dict()})


@timeline_bp.route("/api/timeline/events/<int:eid>", methods=["DELETE"])
@jwt_required()
def delete_event(eid):
    """Delete a timeline event."""
    event = TimelineEvent.query.get_or_404(eid)
    db.session.delete(event)
    db.session.commit()
    return jsonify({"success": True})


@timeline_bp.route("/api/timeline/export", methods=["GET"])
@jwt_required()
def export_timeline():
    """Export timeline as JSON."""
    days   = int(request.args.get("days", 30))
    since  = datetime.now(timezone.utc) - timedelta(days=days)
    events = TimelineEvent.query.filter(
        TimelineEvent.created_at >= since
    ).order_by(TimelineEvent.created_at.desc()).all()
    return jsonify({
        "export_date": str(datetime.now(timezone.utc)),
        "period_days": days,
        "total":       len(events),
        "events":      [e.to_dict() for e in events],
    })
