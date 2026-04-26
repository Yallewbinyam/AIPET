"""
AIPET X — Automated Response Engine (Capability 8)

Runs inside the same Celery task as the risk score recompute.
After scores are refreshed, this module evaluates per-user thresholds
and fires playbooks when a device crosses a threshold.

Cooldown: per-entity-per-playbook, tracked in response_history.
Default thresholds (seeded once per user): notify ≥60, high_alert ≥80, emergency ≥95.
"""
from __future__ import annotations

import logging
import time as _time
from datetime import datetime, timezone, timedelta

_LOG = logging.getLogger("aipet.automated_response")

# ── Default thresholds seeded for new users ───────────────────────────────────

DEFAULT_THRESHOLDS = [
    {
        "name":        "notify",
        "min_score":   60,
        "description": "Notify IT team — device elevated risk",
        "playbook_name": "Block malicious IP on detection",
        "cooldown_hours": 4,
    },
    {
        "name":        "high_alert",
        "min_score":   80,
        "description": "High alert — notify and create incident",
        "playbook_name": "Auto-quarantine critical devices",
        "cooldown_hours": 4,
    },
    {
        "name":        "emergency",
        "min_score":   95,
        "description": "Emergency — notify, create incident, isolate device",
        "playbook_name": "Auto-quarantine critical devices",
        "cooldown_hours": 4,
    },
]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def seed_default_thresholds_for_user(user_id: int) -> int:
    """
    Idempotent. Creates the 3 default ResponseThreshold rows for this user
    if they don't already exist. Returns count of newly-created rows.
    """
    from dashboard.backend.models import db
    from dashboard.backend.automated_response.models import ResponseThreshold
    from dashboard.backend.defense.models import DefensePlaybook

    created = 0
    for tdef in DEFAULT_THRESHOLDS:
        existing = ResponseThreshold.query.filter_by(
            user_id=user_id, name=tdef["name"]
        ).first()
        if existing:
            continue

        # Soft-link to playbook by name — None if playbook doesn't exist yet
        pb = DefensePlaybook.query.filter_by(name=tdef["playbook_name"]).first()

        threshold = ResponseThreshold(
            user_id        = user_id,
            name           = tdef["name"],
            description    = tdef["description"],
            min_score      = tdef["min_score"],
            playbook_id    = pb.id if pb else None,
            enabled        = True,
            cooldown_hours = tdef["cooldown_hours"],
        )
        db.session.add(threshold)
        created += 1

    if created:
        db.session.commit()
    return created


def get_active_thresholds(user_id: int) -> list:
    """
    Returns enabled ResponseThreshold rows for user_id,
    sorted by min_score DESCENDING so the most severe fires first.
    """
    from dashboard.backend.automated_response.models import ResponseThreshold
    return (
        ResponseThreshold.query
        .filter_by(user_id=user_id, enabled=True)
        .order_by(ResponseThreshold.min_score.desc())
        .all()
    )


def has_recent_response(user_id: int, entity: str, playbook_id: int,
                        cooldown_hours: int) -> bool:
    """
    True if (user_id, entity, playbook_id) has a ResponseHistory row
    with fired_at > now - cooldown_hours.  Per-entity-per-playbook.
    """
    from dashboard.backend.automated_response.models import ResponseHistory
    cutoff = _now_utc() - timedelta(hours=cooldown_hours)
    return ResponseHistory.query.filter(
        ResponseHistory.user_id    == user_id,
        ResponseHistory.entity     == entity,
        ResponseHistory.playbook_id == playbook_id,
        ResponseHistory.fired_at   >= cutoff,
    ).first() is not None


def fire_response(
    user_id:    int,
    entity:     str,
    entity_type: str | None,
    score:      int,
    threshold,           # ResponseThreshold instance
) -> dict:
    """
    Execute the playbook tied to this threshold against the given entity.

    1. Run each playbook action via defense._execute_action (reuse; don't reimplement).
    2. For send_alert actions, Slack/Teams calls happen inside _execute_action.
    3. Insert ResponseHistory row.
    4. Emit central_event "automated_response_triggered".

    Returns a summary dict. Never raises.
    """
    from dashboard.backend.models import db, UserSettings
    from dashboard.backend.defense.models import DefensePlaybook
    from dashboard.backend.automated_response.models import ResponseHistory

    now = _now_utc()
    result: dict = {
        "fired":             False,
        "history_id":        None,
        "actions_executed":  [],
        "slack_sent":        False,
        "teams_sent":        False,
        "web_push_sent":     False,
        "central_event_id":  None,
        "error":             None,
    }

    if threshold.playbook_id is None:
        _LOG.warning(
            "fire_response: threshold '%s' has no playbook_id; skipping entity=%s",
            threshold.name, entity,
        )
        result["error"] = "no_playbook_configured"
        return result

    try:
        pb = DefensePlaybook.query.get(threshold.playbook_id)
        if not pb or not pb.enabled:
            result["error"] = "playbook_not_found_or_disabled"
            return result

        actions = []
        try:
            actions = __import__("json").loads(pb.actions)
        except Exception:
            result["error"] = "invalid_playbook_actions_json"
            return result

        reason = (
            f"Automated response: device risk score {score} ≥ "
            f"threshold '{threshold.name}' (≥{threshold.min_score}). "
            f"Playbook: {pb.name}."
        )

        executed_actions = []
        overall_status   = "executed"
        slack_sent       = False
        teams_sent       = False
        notif_error      = None

        from dashboard.backend.defense.routes import _execute_action

        for action_type in actions:
            try:
                log, siem_ev, notif = _execute_action(
                    action_type, entity, reason, playbook=pb, user_id=user_id
                )
                db.session.add(log)
                executed_actions.append({"action": action_type, "status": log.status, "outcome": log.outcome})

                # Collect notification results from send_alert
                if notif:
                    slack_sent  = slack_sent  or notif.get("slack_sent", False)
                    teams_sent  = teams_sent  or notif.get("teams_sent", False)
                    if notif.get("error"):
                        notif_error = notif["error"]
            except Exception as act_exc:
                _LOG.exception("fire_response: action %s failed for %s", action_type, entity)
                executed_actions.append({"action": action_type, "status": "failed", "outcome": str(act_exc)})
                overall_status = "partial"

        db.session.commit()

        # Tier 1 web push: emergency threshold only (score >= 95)
        web_push_sent = False
        if threshold.name == "emergency":
            try:
                from dashboard.backend.push_notifications.dispatcher import send_web_push
                push_result = send_web_push(
                    user_id  = user_id,
                    title    = f"AIPET X Emergency: {entity}",
                    body     = (
                        f"Risk score {score} crossed emergency threshold. "
                        f"Actions: {', '.join(a['action'] for a in executed_actions)}"
                    ),
                    severity = "critical",
                    tag      = f"emergency-{entity}",
                    url      = "/",
                )
                web_push_sent = push_result.get("succeeded", 0) > 0
            except Exception:
                _LOG.exception("fire_response: web push dispatch failed (non-fatal) entity=%s", entity)
                web_push_sent = False

        # Insert ResponseHistory
        hist = ResponseHistory(
            user_id             = user_id,
            entity              = entity,
            entity_type         = entity_type,
            playbook_id         = pb.id,
            threshold_id        = threshold.id,
            threshold_name      = threshold.name,
            triggering_score    = score,
            threshold_min_score = threshold.min_score,
            actions_executed    = executed_actions,
            status              = overall_status,
            slack_sent          = slack_sent,
            teams_sent          = teams_sent,
            notification_error  = notif_error,
            fired_at            = now,
            node_meta           = {"web_push_sent": web_push_sent},
        )
        db.session.add(hist)
        db.session.flush()
        hist_id = hist.id

        # Emit central_event
        central_ev_id = None
        try:
            from dashboard.backend.central_events.adapter import emit_event
            central_ev_id = emit_event(
                source_module    = "automated_response",
                source_table     = "response_history",
                source_row_id    = hist_id,
                event_type       = "automated_response_triggered",
                severity         = "high" if threshold.name != "emergency" else "critical",
                user_id          = user_id,
                entity           = entity,
                entity_type      = entity_type or "device",
                title            = (
                    f"Automated response fired: {threshold.name} threshold "
                    f"crossed (score {score} ≥ {threshold.min_score})"
                ),
                payload          = {
                    "threshold_name":    threshold.name,
                    "triggering_score":  score,
                    "threshold_min":     threshold.min_score,
                    "playbook":          pb.name,
                    "actions_executed":  [a["action"] for a in executed_actions],
                    "slack_sent":        slack_sent,
                    "teams_sent":        teams_sent,
                },
            )
            hist.central_event_id = central_ev_id
        except Exception:
            _LOG.exception("fire_response: emit_event failed for entity=%s", entity)

        db.session.commit()

        result.update({
            "fired":            True,
            "history_id":       hist_id,
            "actions_executed": executed_actions,
            "slack_sent":       slack_sent,
            "teams_sent":       teams_sent,
            "web_push_sent":    web_push_sent,
            "central_event_id": central_ev_id,
        })
        _LOG.info(
            "fire_response: entity=%s score=%d threshold=%s playbook=%s slack=%s",
            entity, score, threshold.name, pb.name, slack_sent,
        )

    except Exception:
        _LOG.exception("fire_response: unexpected error for entity=%s threshold=%s", entity, threshold.name)
        result["error"] = "unexpected_error"
        try:
            db.session.rollback()
        except Exception:
            pass

    return result


def check_thresholds_and_respond(user_id: int | None = None) -> dict:
    """
    Main entry point. Called from inside recompute_device_risk_scores task
    AFTER scores are refreshed.

    For each user (or just user_id if specified):
      1. seed_default_thresholds_for_user (idempotent)
      2. get_active_thresholds sorted by min_score DESC
      3. Query device_risk_scores WHERE score >= lowest threshold
      4. For each entity: fire the HIGHEST applicable threshold only (break after first fire)
         unless a per-entity cooldown is active

    Returns a summary dict. Never raises.
    """
    from dashboard.backend.models import db
    from dashboard.backend.risk_engine.models import DeviceRiskScore

    t0 = _time.time()
    users_processed     = 0
    entities_evaluated  = 0
    responses_fired     = 0
    skipped_cooldown    = 0
    errors              = 0

    try:
        # Determine which users to process
        if user_id is not None:
            user_ids = [user_id]
        else:
            rows = db.session.query(DeviceRiskScore.user_id).distinct().all()
            user_ids = [r[0] for r in rows]
    except Exception:
        _LOG.exception("check_thresholds_and_respond: failed to query user_ids")
        return {"status": "error", "users_processed": 0, "entities_evaluated": 0,
                "responses_fired": 0, "skipped_cooldown": 0, "errors": 1,
                "runtime_seconds": round(_time.time() - t0, 2)}

    for uid in user_ids:
        try:
            seed_default_thresholds_for_user(uid)
            thresholds = get_active_thresholds(uid)
            if not thresholds:
                continue

            min_threshold = min(t.min_score for t in thresholds)
            high_score_entities = DeviceRiskScore.query.filter(
                DeviceRiskScore.user_id == uid,
                DeviceRiskScore.score   >= min_threshold,
            ).all()

            users_processed += 1

            for row in high_score_entities:
                entities_evaluated += 1
                entity     = row.entity
                ent_score  = row.score
                ent_type   = row.entity_type

                # Try thresholds from highest (most severe) to lowest
                for threshold in thresholds:
                    if ent_score < threshold.min_score:
                        continue
                    if threshold.playbook_id is None:
                        continue

                    try:
                        in_cooldown = has_recent_response(
                            uid, entity, threshold.playbook_id, threshold.cooldown_hours
                        )
                    except Exception:
                        _LOG.exception(
                            "check_thresholds: cooldown check failed uid=%s entity=%s", uid, entity
                        )
                        errors += 1
                        break

                    if in_cooldown:
                        skipped_cooldown += 1
                        break  # highest applicable threshold is cooling; don't fire lower ones

                    try:
                        fire_result = fire_response(uid, entity, ent_type, ent_score, threshold)
                        if fire_result.get("fired"):
                            responses_fired += 1
                    except Exception:
                        _LOG.exception(
                            "check_thresholds: fire_response failed uid=%s entity=%s", uid, entity
                        )
                        errors += 1

                    break  # fired the highest applicable threshold; stop checking lower ones

        except Exception:
            _LOG.exception("check_thresholds_and_respond: user loop error uid=%s", uid)
            errors += 1

    runtime = round(_time.time() - t0, 2)
    _LOG.info(
        "check_thresholds_and_respond: users=%d entities=%d fired=%d cooldown=%d errors=%d %.2fs",
        users_processed, entities_evaluated, responses_fired,
        skipped_cooldown, errors, runtime,
    )
    return {
        "status":            "ok",
        "users_processed":   users_processed,
        "entities_evaluated":entities_evaluated,
        "responses_fired":   responses_fired,
        "skipped_cooldown":  skipped_cooldown,
        "errors":            errors,
        "runtime_seconds":   runtime,
    }
