"""
AIPET X — Autonomous Defense Routes

Endpoints:
  GET    /api/defense/playbooks         — list all playbooks
  POST   /api/defense/playbooks         — create playbook
  PUT    /api/defense/playbooks/<id>    — update playbook
  DELETE /api/defense/playbooks/<id>    — delete playbook
  POST   /api/defense/trigger/<id>      — manually trigger a playbook
  POST   /api/defense/respond           — auto-respond to a SIEM event
  GET    /api/defense/actions           — full action log
  GET    /api/defense/stats             — dashboard metrics
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.defense.models import DefensePlaybook, DefenseAction
from dashboard.backend.siem.models import SiemEvent, SiemIncident
from dashboard.backend.zerotrust.models import ZtDeviceTrust

defense_bp = Blueprint("defense", __name__)


# ── Action executor ──────────────────────────────────────────

def _execute_action(action_type, target, reason, playbook=None):
    """
    Execute a single defense action and log the outcome.

    Supported action_type values:
      quarantine_device  — set device status to quarantined in Zero-Trust
      create_incident    — create a SIEM incident
      block_ip           — mark IP as blocked in SIEM event feed
      send_alert         — push Critical SIEM event (hooks into Slack/Teams via existing settings)
      reassess_trust     — trigger trust score recalculation for device

    Returns a DefenseAction record (not yet committed — caller commits).
    """
    outcome = "unknown"
    status  = "executed"

    try:
        if action_type == "quarantine_device":
            # Find device in Zero-Trust and quarantine it
            device = ZtDeviceTrust.query.filter_by(device_ip=target).first()
            if device:
                device.status     = "quarantined"
                device.updated_at = datetime.now(timezone.utc)
                outcome = f"Device {target} quarantined in Zero-Trust"
            else:
                # Create a quarantined record for this device
                device = ZtDeviceTrust(
                    device_ip   = target,
                    trust_score = 0,
                    status      = "quarantined",
                    risk_factors= json.dumps([f"Auto-quarantined: {reason}"]),
                )
                db.session.add(device)
                outcome = f"Device {target} auto-registered and quarantined"

        elif action_type == "create_incident":
            # Create a SIEM incident for this threat
            inc = SiemIncident(
                title       = f"[AUTO] Autonomous Defense: {target}",
                description = reason,
                severity    = "Critical",
                status      = "open",
                event_count = 1,
            )
            db.session.add(inc)
            outcome = f"SIEM incident created for {target}"

        elif action_type == "block_ip":
            # Push a SIEM event marking this IP as blocked
            event = SiemEvent(
                event_type  = "defense_action",
                source      = "AIPET Autonomous Defense",
                severity    = "High",
                title       = f"IP blocked by Autonomous Defense: {target}",
                description = reason,
                mitre_id    = "T1071",
            )
            db.session.add(event)
            outcome = f"Block event logged for IP {target}"

        elif action_type == "send_alert":
            # Push Critical SIEM alert — existing Slack/Teams webhook
            # picks this up via the watch/alert system
            event = SiemEvent(
                event_type  = "defense_action",
                source      = "AIPET Autonomous Defense",
                severity    = "Critical",
                title       = f"[AUTONOMOUS DEFENSE ALERT] {target}",
                description = reason,
                mitre_id    = "T1078",
            )
            db.session.add(event)
            outcome = f"Critical alert pushed to SIEM for {target}"

        elif action_type == "reassess_trust":
            # Recalculate trust score for this device
            from dashboard.backend.zerotrust.routes import _calculate_trust_score
            score, status_zt, factors = _calculate_trust_score(target)
            device = ZtDeviceTrust.query.filter_by(device_ip=target).first()
            if device:
                device.trust_score   = score
                device.status        = status_zt
                device.risk_factors  = json.dumps(factors)
                device.updated_at    = datetime.now(timezone.utc)
                outcome = f"Trust reassessed: {target} score={score} status={status_zt}"
            else:
                outcome = f"Device {target} not found for reassessment"

        else:
            status  = "failed"
            outcome = f"Unknown action type: {action_type}"

    except Exception as e:
        status  = "failed"
        outcome = f"Action failed: {str(e)}"

    # Build the log record
    log = DefenseAction(
        playbook_id   = playbook.id   if playbook else None,
        playbook_name = playbook.name if playbook else "Manual",
        action_type   = action_type,
        target        = target,
        status        = status,
        reason        = reason,
        outcome       = outcome,
    )
    return log


def _match_playbook(playbook, event):
    """
    Check if a SIEM event matches a playbook trigger condition.
    Returns True if matched, False otherwise.
    """
    field = playbook.trigger_field
    op    = playbook.trigger_op
    value = playbook.trigger_value

    # Get the field value from the event
    ev_val = getattr(event, field, None)
    if ev_val is None:
        return False

    ev_val = str(ev_val).lower()
    value  = str(value).lower()

    if op == "eq":
        return ev_val == value
    elif op == "contains":
        return value in ev_val
    elif op == "in":
        return ev_val in [v.strip().lower() for v in value.split(",")]
    return False


# ── Playbook endpoints ───────────────────────────────────────

@defense_bp.route("/api/defense/playbooks", methods=["GET"])
@jwt_required()
def list_playbooks():
    """List all playbooks ordered by creation date."""
    playbooks = DefensePlaybook.query.order_by(
        DefensePlaybook.created_at.desc()).all()
    return jsonify({"playbooks": [p.to_dict() for p in playbooks]})


@defense_bp.route("/api/defense/playbooks", methods=["POST"])
@jwt_required()
def create_playbook():
    """Create a new defense playbook."""
    data = request.get_json(silent=True) or {}
    required = ["name", "trigger_field", "trigger_op", "trigger_value", "actions"]
    if not all(k in data for k in required):
        return jsonify({"error": f"Required: {required}"}), 400

    # Validate actions JSON
    try:
        actions = data["actions"]
        if isinstance(actions, list):
            actions = json.dumps(actions)
        json.loads(actions)  # validate
    except Exception:
        return jsonify({"error": "actions must be a valid JSON list"}), 400

    playbook = DefensePlaybook(
        name             = data["name"],
        description      = data.get("description"),
        enabled          = data.get("enabled", True),
        trigger_field    = data["trigger_field"],
        trigger_op       = data["trigger_op"],
        trigger_value    = data["trigger_value"],
        actions          = actions if isinstance(actions, str) else json.dumps(actions),
        cooldown_minutes = data.get("cooldown_minutes", 5),
        created_by       = int(get_jwt_identity()),
    )
    db.session.add(playbook)
    db.session.commit()
    return jsonify({"success": True, "playbook": playbook.to_dict()}), 201


@defense_bp.route("/api/defense/playbooks/<int:pb_id>", methods=["PUT"])
@jwt_required()
def update_playbook(pb_id):
    """Update an existing playbook."""
    pb   = DefensePlaybook.query.get_or_404(pb_id)
    data = request.get_json(silent=True) or {}
    for field in ["name","description","enabled","trigger_field",
                  "trigger_op","trigger_value","actions","cooldown_minutes"]:
        if field in data:
            setattr(pb, field, data[field])
    db.session.commit()
    return jsonify({"success": True, "playbook": pb.to_dict()})


@defense_bp.route("/api/defense/playbooks/<int:pb_id>", methods=["DELETE"])
@jwt_required()
def delete_playbook(pb_id):
    """Delete a playbook."""
    pb = DefensePlaybook.query.get_or_404(pb_id)
    db.session.delete(pb)
    db.session.commit()
    return jsonify({"success": True})


# ── Manual trigger ───────────────────────────────────────────

@defense_bp.route("/api/defense/trigger/<int:pb_id>", methods=["POST"])
@jwt_required()
def trigger_playbook(pb_id):
    """
    Manually trigger a playbook against a specific target.
    Used by analysts from the UI to run a response immediately.
    """
    pb   = DefensePlaybook.query.get_or_404(pb_id)
    data = request.get_json(silent=True) or {}
    target = data.get("target", "manual-trigger")

    try:
        actions = json.loads(pb.actions)
    except Exception:
        return jsonify({"error": "Invalid actions JSON in playbook"}), 400

    executed = []
    for action_type in actions:
        log = _execute_action(
            action_type = action_type,
            target      = target,
            reason      = f"Manual trigger of playbook: {pb.name}",
            playbook    = pb,
        )
        log.triggered_by = f"manual:user:{get_jwt_identity()}"
        db.session.add(log)
        executed.append({"action": action_type, "outcome": log.outcome})

    # Update playbook stats
    pb.trigger_count  += 1
    pb.last_triggered  = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "success":  True,
        "playbook": pb.name,
        "target":   target,
        "executed": executed,
    })


# ── Auto-respond endpoint ────────────────────────────────────

@defense_bp.route("/api/defense/respond", methods=["POST"])
@jwt_required()
def auto_respond():
    """
    Evaluate a SIEM event against all enabled playbooks
    and execute matching ones automatically.

    Called by:
      - Scan completion handler (future)
      - Manual evaluation from UI
      - Can be wired to /api/siem/ingest post-processing

    Cooldown: if a playbook was triggered within cooldown_minutes,
    it is skipped to prevent response storms.
    """
    data     = request.get_json(silent=True) or {}
    event_id = data.get("event_id")

    if not event_id:
        return jsonify({"error": "event_id required"}), 400

    event = SiemEvent.query.get_or_404(event_id)

    # Get all enabled playbooks
    playbooks = DefensePlaybook.query.filter_by(enabled=True).all()
    responses = []
    now       = datetime.now(timezone.utc)

    for pb in playbooks:
        # Check cooldown — skip if triggered too recently
        if pb.last_triggered:
            elapsed = (now - pb.last_triggered).total_seconds() / 60
            if elapsed < pb.cooldown_minutes:
                responses.append({
                    "playbook": pb.name,
                    "status":   "skipped",
                    "reason":   f"Cooldown active ({pb.cooldown_minutes}m)"
                })
                continue

        # Check if event matches this playbook
        if not _match_playbook(pb, event):
            continue

        # Execute all actions in the playbook
        try:
            actions = json.loads(pb.actions)
        except Exception:
            continue

        # Extract target IP from event source or title
        target = event.source
        for part in (event.title or "").split():
            if part.count(".") == 3:  # looks like an IP
                target = part
                break

        executed = []
        for action_type in actions:
            log = _execute_action(
                action_type = action_type,
                target      = target,
                reason      = f"Auto-response to event {event_id}: {event.title}",
                playbook    = pb,
            )
            log.triggered_by = f"event:{event_id}"
            db.session.add(log)
            executed.append({"action": action_type, "outcome": log.outcome})

        pb.trigger_count  += 1
        pb.last_triggered  = now
        responses.append({
            "playbook": pb.name,
            "status":   "executed",
            "actions":  executed,
        })

    db.session.commit()
    return jsonify({
        "event_id":  event_id,
        "evaluated": len(playbooks),
        "responses": responses,
    })


# ── Action log ───────────────────────────────────────────────

@defense_bp.route("/api/defense/actions", methods=["GET"])
@jwt_required()
def action_log():
    """Full action log — newest first, paginated."""
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))

    q     = DefenseAction.query.order_by(DefenseAction.created_at.desc())
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        "actions": [a.to_dict() for a in items],
        "total":   total, "page": page,
        "pages":   (total + per_page - 1) // per_page,
    })


# ── Stats ────────────────────────────────────────────────────

@defense_bp.route("/api/defense/stats", methods=["GET"])
@jwt_required()
def defense_stats():
    """Dashboard metrics."""
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)

    total_playbooks   = DefensePlaybook.query.count()
    active_playbooks  = DefensePlaybook.query.filter_by(enabled=True).count()
    actions_today     = DefenseAction.query.filter(
        DefenseAction.created_at >= today).count()
    quarantines_today = DefenseAction.query.filter(
        DefenseAction.created_at >= today,
        DefenseAction.action_type == "quarantine_device").count()
    total_actions     = DefenseAction.query.count()
    failed_actions    = DefenseAction.query.filter_by(status="failed").count()

    # Most triggered playbook
    top = DefensePlaybook.query.order_by(
        DefensePlaybook.trigger_count.desc()).first()

    return jsonify({
        "total_playbooks":   total_playbooks,
        "active_playbooks":  active_playbooks,
        "actions_today":     actions_today,
        "quarantines_today": quarantines_today,
        "total_actions":     total_actions,
        "failed_actions":    failed_actions,
        "top_playbook":      top.name if top else None,
        "top_triggers":      top.trigger_count if top else 0,
    })
