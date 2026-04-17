"""
AIPET X — Incident Response Routes

Endpoints:
  GET  /api/incidents              — list incidents
  POST /api/incidents              — create incident
  GET  /api/incidents/<id>         — incident detail + tasks
  PUT  /api/incidents/<id>         — update incident
  DEL  /api/incidents/<id>         — delete incident
  POST /api/incidents/<id>/tasks   — add task
  PUT  /api/incidents/<id>/tasks/<tid> — update task
  GET  /api/incidents/stats        — metrics
  POST /api/incidents/<id>/report  — AI post-mortem report
"""
import json, os, urllib.request
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.incidents.models import IrIncident, IrTask

incidents_bp = Blueprint("incidents_ir", __name__)

PRIORITY_SLA = { "P1": 4, "P2": 24, "P3": 72, "P4": 168 }


@incidents_bp.route("/api/incidents", methods=["GET"])
@jwt_required()
def list_incidents():
    status   = request.args.get("status")
    priority = request.args.get("priority")
    q = IrIncident.query
    if status:   q = q.filter_by(status=status)
    if priority: q = q.filter_by(priority=priority)
    incidents = q.order_by(IrIncident.created_at.desc()).all()
    return jsonify({"incidents": [i.to_dict() for i in incidents]})


@incidents_bp.route("/api/incidents", methods=["POST"])
@jwt_required()
def create_incident():
    data = request.get_json(silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title required"}), 400
    priority = data.get("priority", "P2")
    incident = IrIncident(
        title         = data["title"],
        description   = data.get("description"),
        status        = "open",
        priority      = priority,
        affected      = data.get("affected"),
        attack_vector = data.get("attack_vector"),
        mitre_id      = data.get("mitre_id"),
        assigned_to   = data.get("assigned_to"),
        sla_hours     = PRIORITY_SLA.get(priority, 24),
        created_by    = int(get_jwt_identity()),
    )
    db.session.add(incident)

    # Auto-create standard response tasks
    standard_tasks = [
        "Identify and confirm the incident scope",
        "Isolate affected systems",
        "Collect evidence and logs",
        "Identify attack vector and root cause",
        "Apply containment measures",
        "Eradicate threat",
        "Restore affected systems",
        "Document lessons learned",
    ]
    db.session.flush()
    for t in standard_tasks:
        db.session.add(IrTask(incident_id=incident.id, title=t))

    db.session.commit()
    return jsonify({"success": True,
                    "incident": incident.to_dict()}), 201


@incidents_bp.route("/api/incidents/<int:iid>", methods=["GET"])
@jwt_required()
def get_incident(iid):
    incident = IrIncident.query.get_or_404(iid)
    tasks    = IrTask.query.filter_by(incident_id=iid).all()
    data     = incident.to_dict()
    data["tasks"] = [t.to_dict() for t in tasks]
    return jsonify(data)


@incidents_bp.route("/api/incidents/<int:iid>", methods=["PUT"])
@jwt_required()
def update_incident(iid):
    incident = IrIncident.query.get_or_404(iid)
    data     = request.get_json(silent=True) or {}
    for field in ["title","description","status","priority",
                  "affected","attack_vector","mitre_id",
                  "assigned_to","resolution","lessons"]:
        if field in data:
            setattr(incident, field, data[field])
    if data.get("status") in ("resolved","closed") and not incident.resolved_at:
        incident.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "incident": incident.to_dict()})


@incidents_bp.route("/api/incidents/<int:iid>", methods=["DELETE"])
@jwt_required()
def delete_incident(iid):
    incident = IrIncident.query.get_or_404(iid)
    IrTask.query.filter_by(incident_id=iid).delete()
    db.session.delete(incident)
    db.session.commit()
    return jsonify({"success": True})


@incidents_bp.route("/api/incidents/<int:iid>/tasks", methods=["POST"])
@jwt_required()
def add_task(iid):
    IrIncident.query.get_or_404(iid)
    data = request.get_json(silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title required"}), 400
    task = IrTask(
        incident_id = iid,
        title       = data["title"],
        description = data.get("description"),
        assigned_to = data.get("assigned_to"),
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({"success": True, "task": task.to_dict()}), 201


@incidents_bp.route("/api/incidents/<int:iid>/tasks/<int:tid>",
                    methods=["PUT"])
@jwt_required()
def update_task(iid, tid):
    task = IrTask.query.filter_by(id=tid, incident_id=iid).first_or_404()
    data = request.get_json(silent=True) or {}
    for field in ["title","description","status","assigned_to"]:
        if field in data:
            setattr(task, field, data[field])
    if data.get("status") == "completed" and not task.completed_at:
        task.completed_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "task": task.to_dict()})


@incidents_bp.route("/api/incidents/stats", methods=["GET"])
@jwt_required()
def incident_stats():
    all_inc   = IrIncident.query.all()
    by_status = {}
    by_priority = {}
    sla_breached = 0
    for inc in all_inc:
        d = inc.to_dict()
        by_status[inc.status]     = by_status.get(inc.status, 0) + 1
        by_priority[inc.priority] = by_priority.get(inc.priority, 0) + 1
        if d.get("sla_breached"):
            sla_breached += 1
    open_inc  = [i for i in all_inc if i.status not in ("resolved","closed")]
    avg_res   = 0
    resolved  = [i for i in all_inc if i.resolved_at]
    if resolved:
        times = [(i.resolved_at.replace(tzinfo=timezone.utc) -
                  i.created_at.replace(tzinfo=timezone.utc)
                  ).total_seconds()/3600 for i in resolved]
        avg_res = round(sum(times)/len(times), 1)
    return jsonify({
        "total":        len(all_inc),
        "open":         len(open_inc),
        "sla_breached": sla_breached,
        "avg_resolution_hours": avg_res,
        "by_status":    by_status,
        "by_priority":  by_priority,
    })


@incidents_bp.route("/api/incidents/<int:iid>/report", methods=["POST"])
@jwt_required()
def generate_report(iid):
    """Generate AI post-mortem report using Claude."""
    incident = IrIncident.query.get_or_404(iid)
    tasks    = IrTask.query.filter_by(incident_id=iid).all()
    completed = sum(1 for t in tasks if t.status == "completed")

    prompt = f"""You are a senior incident response analyst writing a post-mortem report.

Incident: {incident.title}
Priority: {incident.priority}
Status: {incident.status}
Affected Systems: {incident.affected or "Unknown"}
Attack Vector: {incident.attack_vector or "Unknown"}
MITRE ATT&CK: {incident.mitre_id or "N/A"}
Duration: {incident.to_dict().get("age_hours", 0)} hours
Tasks completed: {completed}/{len(tasks)}
Resolution: {incident.resolution or "Pending"}

Write a professional incident post-mortem report with these sections:
1. EXECUTIVE SUMMARY — what happened, business impact, 2-3 sentences
2. INCIDENT TIMELINE — key events in chronological order
3. ROOT CAUSE ANALYSIS — what caused this incident
4. IMPACT ASSESSMENT — systems affected, data at risk, business impact
5. RESPONSE ACTIONS — what was done to contain and resolve
6. LESSONS LEARNED — what can be improved
7. RECOMMENDATIONS — top 5 specific actions to prevent recurrence

Be specific, actionable, and professional."""

    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        payload = json.dumps({
            "model": "claude-opus-4-5",
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data    = json.loads(resp.read().decode("utf-8"))
            report  = data["content"][0]["text"]
        return jsonify({"success": True, "report": report,
                        "incident": incident.to_dict()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
