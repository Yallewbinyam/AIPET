import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from dashboard.backend.models import db
from dashboard.backend.siem.models import SiemEvent, SiemRule, SiemIncident

siem_bp = Blueprint("siem", __name__)

def _run_rules(event):
    rules = SiemRule.query.filter_by(enabled=True).all()
    for rule in rules:
        try:
            cond = json.loads(rule.condition)
            field, op, value = cond.get("field"), cond.get("op"), cond.get("value")
            ev_val = getattr(event, field, None)
            if ev_val is None:
                continue
            matched = False
            if op == "eq":
                matched = str(ev_val).lower() == str(value).lower()
            elif op == "contains":
                matched = str(value).lower() in str(ev_val).lower()
            elif op == "in":
                matched = str(ev_val).lower() in [v.lower() for v in value]
            if matched:
                rule.trigger_count += 1
                if rule.action == "incident":
                    inc = SiemIncident(
                        title=f"[Auto] {rule.name}",
                        description=f"Rule triggered by: {event.title}",
                        severity=rule.severity, status="open", event_count=1)
                    db.session.add(inc)
                    db.session.flush()
                    event.incident_id = inc.id
        except Exception:
            pass

@siem_bp.route("/api/siem/ingest", methods=["POST"])
def siem_ingest():
    data = request.get_json(silent=True) or {}
    required = ["event_type", "source", "severity", "title"]
    if not all(k in data for k in required):
        return jsonify({"error": f"Required fields: {required}"}), 400
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        uid = get_jwt_identity()
        if uid:
            user_id = int(uid)
    except Exception:
        pass
    event = SiemEvent(
        event_type=data["event_type"], source=data["source"],
        severity=data["severity"], title=data["title"],
        description=data.get("description"),
        raw_payload=json.dumps(data.get("raw_payload", {})),
        mitre_id=data.get("mitre_id"), user_id=user_id)
    db.session.add(event)
    db.session.flush()
    _run_rules(event)
    db.session.commit()

    # Cycle prevention: skip emit if this event came from the central_events pipeline
    if not (data.get("node_meta") or {}).get("from_central_emit"):
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module = "siem",
                source_table  = "siem_events",
                source_row_id = event.id,
                event_type    = event.event_type,
                severity      = event.severity.lower(),
                user_id       = event.user_id,
                entity        = event.source,
                entity_type   = None,
                title         = event.title,
                mitre_techniques = [{"technique_id": event.mitre_id, "confidence": 1.0}] if event.mitre_id else None,
                payload       = {"original_siem_event_id": event.id},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in siem (ingest)")

    return jsonify({"success": True, "event_id": event.id}), 201

@siem_bp.route("/api/siem/events", methods=["GET"])
@jwt_required()
def siem_events():
    severity = request.args.get("severity")
    source   = request.args.get("source")
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    q = SiemEvent.query.order_by(SiemEvent.created_at.desc())
    if severity:
        q = q.filter_by(severity=severity)
    if source:
        q = q.filter(SiemEvent.source.ilike(f"%{source}%"))
    total  = q.count()
    events = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({"events": [e.to_dict() for e in events],
                    "total": total, "page": page,
                    "pages": (total + per_page - 1) // per_page})

@siem_bp.route("/api/siem/events/<int:event_id>/acknowledge", methods=["POST"])
@jwt_required()
def siem_ack(event_id):
    event = SiemEvent.query.get_or_404(event_id)
    event.acknowledged = True
    db.session.commit()
    return jsonify({"success": True})

@siem_bp.route("/api/siem/rules", methods=["GET"])
@jwt_required()
def siem_rules_list():
    rules = SiemRule.query.order_by(SiemRule.created_at.desc()).all()
    return jsonify({"rules": [r.to_dict() for r in rules]})

@siem_bp.route("/api/siem/rules", methods=["POST"])
@jwt_required()
def siem_rules_create():
    data = request.get_json(silent=True) or {}
    if not data.get("name") or not data.get("condition"):
        return jsonify({"error": "name and condition required"}), 400
    try:
        json.loads(data["condition"])
    except Exception:
        return jsonify({"error": "condition must be valid JSON"}), 400
    rule = SiemRule(
        name=data["name"], description=data.get("description"),
        condition=data["condition"], action=data.get("action", "alert"),
        severity=data.get("severity", "High"), enabled=data.get("enabled", True),
        created_by=int(get_jwt_identity()))
    db.session.add(rule)
    db.session.commit()
    return jsonify({"success": True, "rule": rule.to_dict()}), 201

@siem_bp.route("/api/siem/rules/<int:rule_id>", methods=["PUT"])
@jwt_required()
def siem_rules_update(rule_id):
    rule = SiemRule.query.get_or_404(rule_id)
    data = request.get_json(silent=True) or {}
    for field in ["name", "description", "condition", "action", "severity", "enabled"]:
        if field in data:
            setattr(rule, field, data[field])
    db.session.commit()
    return jsonify({"success": True, "rule": rule.to_dict()})

@siem_bp.route("/api/siem/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required()
def siem_rules_delete(rule_id):
    rule = SiemRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"success": True})

@siem_bp.route("/api/siem/incidents", methods=["GET"])
@jwt_required()
def siem_incidents_list():
    status = request.args.get("status")
    q = SiemIncident.query.order_by(SiemIncident.created_at.desc())
    if status:
        q = q.filter_by(status=status)
    incidents = q.limit(100).all()
    return jsonify({"incidents": [i.to_dict() for i in incidents]})

@siem_bp.route("/api/siem/incidents", methods=["POST"])
@jwt_required()
def siem_incidents_create():
    data = request.get_json(silent=True) or {}
    if not data.get("title") or not data.get("severity"):
        return jsonify({"error": "title and severity required"}), 400
    inc = SiemIncident(
        title=data["title"], description=data.get("description"),
        severity=data["severity"], status=data.get("status", "open"),
        created_by=int(get_jwt_identity()))
    db.session.add(inc)
    db.session.commit()
    return jsonify({"success": True, "incident": inc.to_dict()}), 201

@siem_bp.route("/api/siem/incidents/<int:inc_id>", methods=["PUT"])
@jwt_required()
def siem_incidents_update(inc_id):
    inc = SiemIncident.query.get_or_404(inc_id)
    data = request.get_json(silent=True) or {}
    for field in ["title", "description", "severity", "status", "assigned_to"]:
        if field in data:
            setattr(inc, field, data[field])
    inc.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "incident": inc.to_dict()})

@siem_bp.route("/api/siem/stats", methods=["GET"])
@jwt_required()
def siem_stats():
    now   = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total_today    = SiemEvent.query.filter(SiemEvent.created_at >= today).count()
    critical_today = SiemEvent.query.filter(SiemEvent.created_at >= today, SiemEvent.severity == "Critical").count()
    open_incidents = SiemIncident.query.filter_by(status="open").count()
    active_rules   = SiemRule.query.filter_by(enabled=True).count()
    unacked        = SiemEvent.query.filter_by(acknowledged=False).count()
    severity_counts = {}
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        severity_counts[s] = SiemEvent.query.filter(SiemEvent.created_at >= today, SiemEvent.severity == s).count()
    timeline = []
    for i in range(6, -1, -1):
        day      = today - timedelta(days=i)
        next_day = day + timedelta(days=1)
        count    = SiemEvent.query.filter(SiemEvent.created_at >= day, SiemEvent.created_at < next_day).count()
        timeline.append({"date": day.strftime("%b %d"), "count": count})
    return jsonify({
        "total_today": total_today, "critical_today": critical_today,
        "open_incidents": open_incidents, "active_rules": active_rules,
        "unacknowledged": unacked, "severity_counts": severity_counts,
        "timeline": timeline})
