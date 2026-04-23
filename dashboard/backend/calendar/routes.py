# ============================================================
# AIPET X — Calendar Module
# Scheduled scans · Compliance deadlines · Incidents
# ============================================================

import uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.validation import validate_body, CALENDAR_EVENT_SCHEMA
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Boolean

calendar_bp = Blueprint("calendar", __name__)


class CalendarEvent(db.Model):
    __tablename__ = "calendar_events"
    id          = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = Column(Integer, nullable=False, index=True)
    title       = Column(String(256), nullable=False)
    description = Column(Text, default="")
    event_type  = Column(String(64), default="general")   # scan | compliance | incident | general
    start_date  = Column(DateTime, nullable=False)
    end_date    = Column(DateTime, nullable=True)
    all_day     = Column(Boolean, default=True)
    status      = Column(String(32), default="scheduled") # scheduled | completed | overdue | cancelled
    priority    = Column(String(16), default="medium")    # low | medium | high | critical
    node_meta   = Column(Text, default="{}")
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "title":       self.title,
            "description": self.description,
            "event_type":  self.event_type,
            "start_date":  self.start_date.isoformat() if self.start_date else None,
            "end_date":    self.end_date.isoformat() if self.end_date else None,
            "all_day":     self.all_day,
            "status":      self.status,
            "priority":    self.priority,
            "created_at":  self.created_at.isoformat(),
        }


def _seed_sample_events(user_id):
    now = datetime.datetime.utcnow()
    samples = [
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="Weekly IoT Vulnerability Scan", event_type="scan", start_date=now + datetime.timedelta(days=1), all_day=True, status="scheduled", priority="high", description="Full network sweep — all registered IoT devices"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="NIS2 Compliance Audit", event_type="compliance", start_date=now + datetime.timedelta(days=7), all_day=True, status="scheduled", priority="critical", description="Quarterly NIS2 compliance review and evidence collection"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="ISO 27001 Deadline — Risk Assessment", event_type="compliance", start_date=now + datetime.timedelta(days=14), all_day=True, status="scheduled", priority="critical", description="Annual ISO 27001 risk assessment submission deadline"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="Incident INC-042 Review", event_type="incident", start_date=now + datetime.timedelta(days=2), all_day=True, status="scheduled", priority="high", description="Post-incident review for cloud misconfiguration event"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="GDPR DPIA Submission", event_type="compliance", start_date=now + datetime.timedelta(days=21), all_day=True, status="scheduled", priority="high", description="Data Protection Impact Assessment — new IoT data pipeline"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="Red Team Exercise", event_type="scan", start_date=now + datetime.timedelta(days=10), all_day=True, status="scheduled", priority="medium", description="Scheduled adversary simulation campaign"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="Patch Compliance Review", event_type="general", start_date=now + datetime.timedelta(days=5), all_day=True, status="scheduled", priority="medium", description="Monthly patch status review across all endpoints"),
        CalendarEvent(id=str(uuid.uuid4()), user_id=user_id, title="PCI DSS Annual Assessment", event_type="compliance", start_date=now + datetime.timedelta(days=30), all_day=True, status="scheduled", priority="critical", description="External PCI DSS QSA assessment — prepare evidence package"),
    ]
    for s in samples:
        db.session.add(s)
    db.session.commit()


@calendar_bp.route("/api/calendar/events", methods=["GET"])
@jwt_required()
def list_events():
    uid = get_jwt_identity()
    events = CalendarEvent.query.filter_by(user_id=uid).order_by(CalendarEvent.start_date.asc()).all()
    if not events:
        _seed_sample_events(uid)
        events = CalendarEvent.query.filter_by(user_id=uid).order_by(CalendarEvent.start_date.asc()).all()
    month = request.args.get("month")
    year  = request.args.get("year")
    if month and year:
        try:
            m, y = int(month), int(year)
            events = [e for e in events if e.start_date.month == m and e.start_date.year == y]
        except Exception:
            pass
    return jsonify({"events": [e.to_dict() for e in events]}), 200


@calendar_bp.route("/api/calendar/events", methods=["POST"])
@jwt_required()
@validate_body(CALENDAR_EVENT_SCHEMA)
def create_event():
    uid  = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "Title required"}), 400
    try:
        start = datetime.datetime.fromisoformat(data["start_date"])
    except Exception:
        return jsonify({"error": "Valid start_date (ISO format) required"}), 400
    end = None
    if data.get("end_date"):
        try:
            end = datetime.datetime.fromisoformat(data["end_date"])
        except Exception:
            pass
    ev = CalendarEvent(
        user_id=uid, title=title,
        description=data.get("description", ""),
        event_type=data.get("event_type", "general"),
        start_date=start, end_date=end,
        all_day=data.get("all_day", True),
        status=data.get("status", "scheduled"),
        priority=data.get("priority", "medium"),
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify(ev.to_dict()), 201


@calendar_bp.route("/api/calendar/events/<event_id>", methods=["PUT"])
@jwt_required()
def update_event(event_id):
    uid = get_jwt_identity()
    ev  = CalendarEvent.query.filter_by(id=event_id, user_id=uid).first()
    if not ev:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    for field in ("title", "description", "event_type", "status", "priority", "all_day"):
        if field in data:
            setattr(ev, field, data[field])
    if "start_date" in data:
        try:
            ev.start_date = datetime.datetime.fromisoformat(data["start_date"])
        except Exception:
            pass
    if "end_date" in data and data["end_date"]:
        try:
            ev.end_date = datetime.datetime.fromisoformat(data["end_date"])
        except Exception:
            pass
    db.session.commit()
    return jsonify(ev.to_dict()), 200


@calendar_bp.route("/api/calendar/events/<event_id>", methods=["DELETE"])
@jwt_required()
def delete_event(event_id):
    uid = get_jwt_identity()
    ev  = CalendarEvent.query.filter_by(id=event_id, user_id=uid).first()
    if not ev:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(ev)
    db.session.commit()
    return jsonify({"deleted": True}), 200


@calendar_bp.route("/api/calendar/upcoming", methods=["GET"])
@jwt_required()
def upcoming():
    uid  = get_jwt_identity()
    now  = datetime.datetime.utcnow()
    days = int(request.args.get("days", 7))
    cutoff = now + datetime.timedelta(days=days)
    events = CalendarEvent.query.filter(
        CalendarEvent.user_id == uid,
        CalendarEvent.start_date >= now,
        CalendarEvent.start_date <= cutoff,
    ).order_by(CalendarEvent.start_date.asc()).all()
    return jsonify({"events": [e.to_dict() for e in events], "days": days}), 200


@calendar_bp.route("/api/calendar/health", methods=["GET"])
def health():
    return jsonify({"module": "Calendar", "status": "operational"}), 200
