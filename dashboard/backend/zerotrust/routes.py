"""
AIPET X — Zero-Trust Routes

Endpoints:
  GET  /api/zerotrust/devices           — all device trust profiles
  POST /api/zerotrust/devices/assess    — recalculate trust scores from scan data
  PUT  /api/zerotrust/devices/<ip>      — manually override trust status
  GET  /api/zerotrust/policies          — list all policies
  POST /api/zerotrust/policies          — create policy
  PUT  /api/zerotrust/policies/<id>     — update policy
  DEL  /api/zerotrust/policies/<id>     — delete policy
  POST /api/zerotrust/evaluate          — evaluate access request against policies
  GET  /api/zerotrust/log               — access decision log
  GET  /api/zerotrust/stats             — dashboard metrics
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Scan, Finding
from dashboard.backend.zerotrust.models import ZtDeviceTrust, ZtPolicy, ZtAccessLog
from dashboard.backend.siem.models import SiemEvent

zerotrust_bp = Blueprint("zerotrust", __name__)


# ── Trust score calculation ──────────────────────────────────

def _calculate_trust_score(device_ip, scan_id=None):
    """
    Calculate a device trust score from its most recent scan findings.

    Scoring logic (starts at 100, deductions applied):
      Critical finding: -25 points each (max -50)
      High finding:     -15 points each (max -30)
      Medium finding:   -8  points each (max -16)
      Low finding:      -3  points each (max -9)

    Status thresholds:
      90-100: trusted
      70-89:  monitored
      40-69:  restricted
      0-39:   quarantined
    """
    score        = 100
    risk_factors = []

    # Get findings for this device from most recent scan
    query = Finding.query.filter_by(target=device_ip)
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    findings = query.all()

    # Count findings by severity
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.severity or "Low"
        if sev in counts:
            counts[sev] += 1

    # Apply deductions with caps
    if counts["Critical"] > 0:
        deduction = min(counts["Critical"] * 25, 50)
        score -= deduction
        risk_factors.append(f"{counts['Critical']} Critical finding(s) — -{deduction} pts")

    if counts["High"] > 0:
        deduction = min(counts["High"] * 15, 30)
        score -= deduction
        risk_factors.append(f"{counts['High']} High finding(s) — -{deduction} pts")

    if counts["Medium"] > 0:
        deduction = min(counts["Medium"] * 8, 16)
        score -= deduction
        risk_factors.append(f"{counts['Medium']} Medium finding(s) — -{deduction} pts")

    if counts["Low"] > 0:
        deduction = min(counts["Low"] * 3, 9)
        score -= deduction
        risk_factors.append(f"{counts['Low']} Low finding(s) — -{deduction} pts")

    score = max(0, score)  # Never go below 0

    # Derive status from score
    if score >= 90:
        status = "trusted"
    elif score >= 70:
        status = "monitored"
    elif score >= 40:
        status = "restricted"
    else:
        status = "quarantined"

    return score, status, risk_factors


def _ingest_siem_zt(source_ip, action, reason, trust_score):
    """
    Push Zero-Trust events into the SIEM feed.
    Only pushes block/quarantine decisions — not allow (too noisy).
    Returns the SiemEvent object (or None) — caller must commit then emit.
    """
    if action not in ("block", "quarantine"):
        return None
    try:
        severity = "Critical" if action == "quarantine" else "High"
        event = SiemEvent(
            event_type  = "zero_trust",
            source      = "AIPET Zero-Trust",
            severity    = severity,
            title       = f"Zero-Trust {action.upper()}: {source_ip}",
            description = reason,
            mitre_id    = "T1078",
        )
        db.session.add(event)
        return event
    except Exception:
        return None


# ── Device trust endpoints ───────────────────────────────────

@zerotrust_bp.route("/api/zerotrust/devices", methods=["GET"])
@jwt_required()
def list_devices():
    """Return all device trust profiles ordered by trust score ascending (worst first)."""
    devices = ZtDeviceTrust.query.order_by(ZtDeviceTrust.trust_score.asc()).all()
    return jsonify({"devices": [d.to_dict() for d in devices]})


@zerotrust_bp.route("/api/zerotrust/devices/assess", methods=["POST"])
@jwt_required()
def assess_devices():
    """
    Recalculate trust scores for all devices using latest scan data.
    Called after every scan completes, or manually from the UI.
    Creates ZtDeviceTrust records for new devices, updates existing ones.
    """
    # Get all unique device IPs from findings
    from sqlalchemy import distinct
    ips = [row[0] for row in db.session.query(
        distinct(Finding.target)).filter(Finding.target.isnot(None)).all()]

    if not ips:
        return jsonify({"message": "No devices found in scan data", "assessed": 0})

    assessed = []
    now = datetime.now(timezone.utc)

    for ip in ips:
        score, status, risk_factors = _calculate_trust_score(ip)

        # Upsert — update if exists, create if not
        device = ZtDeviceTrust.query.filter_by(device_ip=ip).first()
        if device:
            prev_status = device.status
            device.trust_score   = score
            device.status        = status
            device.risk_factors  = json.dumps(risk_factors)
            device.last_assessed = now
            device.updated_at    = now
        else:
            prev_status = None
            device = ZtDeviceTrust(
                device_ip    = ip,
                trust_score  = score,
                status       = status,
                risk_factors = json.dumps(risk_factors),
                last_assessed= now,
            )
            db.session.add(device)

        # Push to SIEM if device newly quarantined or restricted
        zt_ev = None
        if status in ("quarantined", "restricted") and prev_status != status:
            zt_ev = _ingest_siem_zt(
                ip, "quarantine" if status == "quarantined" else "block",
                f"Trust score dropped to {score}. Factors: {'; '.join(risk_factors)}",
                score
            )

        assessed.append({"ip": ip, "score": score, "status": status, "_zt_ev": zt_ev})

    db.session.commit()

    for item in assessed:
        sev_event = item.pop("_zt_ev", None)
        if sev_event:
            try:
                from dashboard.backend.central_events.adapter import emit_event
                emit_event(
                    source_module    = "zerotrust",
                    source_table     = "siem_events",
                    source_row_id    = sev_event.id,
                    event_type       = sev_event.event_type,
                    severity         = sev_event.severity.lower(),
                    user_id          = None,
                    entity           = item["ip"],
                    entity_type      = "device",
                    title            = sev_event.title,
                    mitre_techniques = [{"technique_id": sev_event.mitre_id, "confidence": 1.0}] if sev_event.mitre_id else None,
                    payload          = {"original_siem_event_id": sev_event.id, "trust_score": item["score"]},
                )
            except Exception:
                current_app.logger.exception("emit_event call site error in zerotrust (assess_devices)")

    return jsonify({"assessed": len(assessed), "devices": assessed})


@zerotrust_bp.route("/api/zerotrust/devices/<device_ip>", methods=["PUT"])
@jwt_required()
def update_device(device_ip):
    """
    Manually override a device trust status.
    Used by security analysts to quarantine a device immediately
    or to restore a device after remediation.
    """
    device = ZtDeviceTrust.query.filter_by(device_ip=device_ip).first_or_404()
    data   = request.get_json(silent=True) or {}

    zt_ev = None
    if "status" in data:
        device.status     = data["status"]
        device.updated_at = datetime.now(timezone.utc)
        # Log override to SIEM
        zt_ev = _ingest_siem_zt(
            device_ip, data["status"],
            f"Manual override by analyst (user {get_jwt_identity()})",
            device.trust_score
        )

    if "trust_score" in data:
        device.trust_score = data["trust_score"]

    db.session.commit()

    if zt_ev:
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module    = "zerotrust",
                source_table     = "siem_events",
                source_row_id    = zt_ev.id,
                event_type       = zt_ev.event_type,
                severity         = zt_ev.severity.lower(),
                user_id          = None,
                entity           = device_ip,
                entity_type      = "device",
                title            = zt_ev.title,
                mitre_techniques = [{"technique_id": zt_ev.mitre_id, "confidence": 1.0}] if zt_ev.mitre_id else None,
                payload          = {"original_siem_event_id": zt_ev.id},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in zerotrust (update_device)")

    return jsonify({"success": True, "device": device.to_dict()})


# ── Policy endpoints ─────────────────────────────────────────

@zerotrust_bp.route("/api/zerotrust/policies", methods=["GET"])
@jwt_required()
def list_policies():
    """List all policies ordered by priority (lowest number first)."""
    policies = ZtPolicy.query.order_by(ZtPolicy.priority.asc()).all()
    return jsonify({"policies": [p.to_dict() for p in policies]})


@zerotrust_bp.route("/api/zerotrust/policies", methods=["POST"])
@jwt_required()
def create_policy():
    """Create a new Zero-Trust access policy."""
    data = request.get_json(silent=True) or {}
    required = ["name", "source", "destination", "action"]
    if not all(k in data for k in required):
        return jsonify({"error": f"Required: {required}"}), 400

    policy = ZtPolicy(
        name        = data["name"],
        description = data.get("description"),
        source      = data["source"],
        destination = data["destination"],
        port        = data.get("port", "*"),
        protocol    = data.get("protocol", "any"),
        action      = data["action"],
        priority    = data.get("priority", 100),
        enabled     = data.get("enabled", True),
        created_by  = int(get_jwt_identity()),
    )
    db.session.add(policy)
    db.session.commit()
    return jsonify({"success": True, "policy": policy.to_dict()}), 201


@zerotrust_bp.route("/api/zerotrust/policies/<int:policy_id>", methods=["PUT"])
@jwt_required()
def update_policy(policy_id):
    """Update an existing policy."""
    policy = ZtPolicy.query.get_or_404(policy_id)
    data   = request.get_json(silent=True) or {}
    for field in ["name","description","source","destination",
                  "port","protocol","action","priority","enabled"]:
        if field in data:
            setattr(policy, field, data[field])
    db.session.commit()
    return jsonify({"success": True, "policy": policy.to_dict()})


@zerotrust_bp.route("/api/zerotrust/policies/<int:policy_id>", methods=["DELETE"])
@jwt_required()
def delete_policy(policy_id):
    """Delete a policy."""
    policy = ZtPolicy.query.get_or_404(policy_id)
    db.session.delete(policy)
    db.session.commit()
    return jsonify({"success": True})


# ── Access evaluation endpoint ───────────────────────────────

@zerotrust_bp.route("/api/zerotrust/evaluate", methods=["POST"])
@jwt_required()
def evaluate_access():
    """
    Evaluate whether a source device should be allowed to reach a destination.

    Policy matching order:
      1. Check device trust score — quarantined devices are always blocked
      2. Match policies by priority (lowest first)
      3. First match wins
      4. Default action: allow (fail-open for IoT compatibility)

    Logs every decision to zt_access_log and pushes blocks to SIEM.
    """
    data      = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip", "")
    dest_ip   = data.get("dest_ip", "")
    port      = data.get("port", "*")
    protocol  = data.get("protocol", "any")

    if not source_ip:
        return jsonify({"error": "source_ip required"}), 400

    # Step 1 — check device trust score
    device      = ZtDeviceTrust.query.filter_by(device_ip=source_ip).first()
    trust_score = device.trust_score if device else 100

    if device and device.status == "quarantined":
        # Quarantined devices are always blocked regardless of policies
        log = ZtAccessLog(
            source_ip   = source_ip,
            dest_ip     = dest_ip,
            port        = port,
            protocol    = protocol,
            action      = "block",
            policy_name = "Quarantine Override",
            reason      = f"Device quarantined (trust score: {trust_score})",
            trust_score = trust_score,
        )
        db.session.add(log)
        zt_ev = _ingest_siem_zt(source_ip, "quarantine",
            f"Quarantined device attempted access to {dest_ip}:{port}", trust_score)
        db.session.commit()
        if zt_ev:
            try:
                from dashboard.backend.central_events.adapter import emit_event
                emit_event(
                    source_module    = "zerotrust",
                    source_table     = "siem_events",
                    source_row_id    = zt_ev.id,
                    event_type       = zt_ev.event_type,
                    severity         = zt_ev.severity.lower(),
                    user_id          = None,
                    entity           = source_ip,
                    entity_type      = "device",
                    title            = zt_ev.title,
                    mitre_techniques = [{"technique_id": zt_ev.mitre_id, "confidence": 1.0}] if zt_ev.mitre_id else None,
                    payload          = {"original_siem_event_id": zt_ev.id, "dest_ip": dest_ip},
                )
            except Exception:
                current_app.logger.exception("emit_event call site error in zerotrust (evaluate_access quarantine)")
        return jsonify({
            "action":      "block",
            "reason":      f"Device is quarantined (trust score: {trust_score})",
            "trust_score": trust_score,
            "policy":      "Quarantine Override",
        })

    # Step 2 — evaluate policies in priority order
    policies = ZtPolicy.query.filter_by(enabled=True).order_by(
        ZtPolicy.priority.asc()).all()

    matched_policy = None
    for policy in policies:
        # Simple match: exact IP or wildcard *
        src_match  = policy.source      in (source_ip, "*")
        dest_match = policy.destination in (dest_ip,   "*")
        port_match = policy.port        in (port,      "*", None)
        if src_match and dest_match and port_match:
            matched_policy = policy
            break

    # Step 3 — determine action
    if matched_policy:
        action      = matched_policy.action
        policy_name = matched_policy.name
        reason      = f"Matched policy: {matched_policy.name}"
        matched_policy.hit_count += 1
    else:
        # Default: allow (fail-open)
        action      = "allow"
        policy_name = "Default Allow"
        reason      = "No matching policy — default allow"

    # Step 4 — log decision
    log = ZtAccessLog(
        source_ip   = source_ip,
        dest_ip     = dest_ip,
        port        = port,
        protocol    = protocol,
        action      = action,
        policy_id   = matched_policy.id if matched_policy else None,
        policy_name = policy_name,
        reason      = reason,
        trust_score = trust_score,
    )
    db.session.add(log)
    zt_ev = None
    if action in ("block", "quarantine"):
        zt_ev = _ingest_siem_zt(source_ip, action, reason, trust_score)

    db.session.commit()

    if zt_ev:
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module    = "zerotrust",
                source_table     = "siem_events",
                source_row_id    = zt_ev.id,
                event_type       = zt_ev.event_type,
                severity         = zt_ev.severity.lower(),
                user_id          = None,
                entity           = source_ip,
                entity_type      = "device",
                title            = zt_ev.title,
                mitre_techniques = [{"technique_id": zt_ev.mitre_id, "confidence": 1.0}] if zt_ev.mitre_id else None,
                payload          = {"original_siem_event_id": zt_ev.id, "dest_ip": dest_ip, "action": action},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in zerotrust (evaluate_access policy)")

    return jsonify({
        "action":      action,
        "reason":      reason,
        "trust_score": trust_score,
        "policy":      policy_name,
    })


# ── Access log ───────────────────────────────────────────────

@zerotrust_bp.route("/api/zerotrust/log", methods=["GET"])
@jwt_required()
def access_log():
    """Paginated access decision log — newest first."""
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    action   = request.args.get("action")

    q = ZtAccessLog.query.order_by(ZtAccessLog.created_at.desc())
    if action:
        q = q.filter_by(action=action)

    total   = q.count()
    entries = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        "log":   [e.to_dict() for e in entries],
        "total": total, "page": page,
        "pages": (total + per_page - 1) // per_page,
    })


# ── Stats ────────────────────────────────────────────────────

@zerotrust_bp.route("/api/zerotrust/stats", methods=["GET"])
@jwt_required()
def zt_stats():
    """Dashboard metrics for the Zero-Trust page."""
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)

    trusted      = ZtDeviceTrust.query.filter_by(status="trusted").count()
    monitored    = ZtDeviceTrust.query.filter_by(status="monitored").count()
    restricted   = ZtDeviceTrust.query.filter_by(status="restricted").count()
    quarantined  = ZtDeviceTrust.query.filter_by(status="quarantined").count()
    total_devices= ZtDeviceTrust.query.count()
    total_policies = ZtPolicy.query.filter_by(enabled=True).count()
    blocks_today = ZtAccessLog.query.filter(
        ZtAccessLog.created_at >= today,
        ZtAccessLog.action == "block").count()
    allows_today = ZtAccessLog.query.filter(
        ZtAccessLog.created_at >= today,
        ZtAccessLog.action == "allow").count()

    return jsonify({
        "trusted":       trusted,
        "monitored":     monitored,
        "restricted":    restricted,
        "quarantined":   quarantined,
        "total_devices": total_devices,
        "total_policies":total_policies,
        "blocks_today":  blocks_today,
        "allows_today":  allows_today,
    })
