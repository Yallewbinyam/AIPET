"""
AIPET X — Central Event Pipeline Adapter

Public API: one function — emit_event().

Design rules:
- NEVER raises. Wraps everything in try/except. Returns None on failure.
- One INSERT per call. No external calls, no extra queries.
- <10ms wall time budget. Performance-safe for inline use inside Flask routes.
- Callers pass user_id explicitly — no implicit request-context lookups.
- API keys and PII must never appear in payload.

Usage:
    from dashboard.backend.central_events.adapter import emit_event
    emit_event(
        source_module="ml_anomaly",
        source_table="ml_anomaly_detections",
        source_row_id=detection.id,
        event_type="isolation_forest_anomaly_detected",
        severity="high",
        user_id=user_id,
        entity="10.0.3.11",
        entity_type="device",
        title="Isolation Forest flagged 10.0.3.11 at score 0.71",
        payload={"anomaly_score": 0.71},
    )
"""
from __future__ import annotations

import logging

from dashboard.backend.central_events.models import CentralEvent
from dashboard.backend.models import db

_LOG = logging.getLogger("aipet.central_events")

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def emit_event(
    *,
    source_module:    str,
    source_table:     str,
    source_row_id,              # int | str | uuid — coerced to str
    event_type:       str,
    severity:         str,      # info | low | medium | high | critical
    user_id:          int | None = None,
    entity:           str | None = None,
    entity_type:      str | None = None,
    title:            str | None = None,
    description:      str | None = None,
    mitre_techniques: list[dict] | None = None,
    risk_score:       int | None = None,
    payload:          dict | None = None,
) -> int | None:
    """
    Insert one row into central_events. Best-effort — never raises.
    Returns the new event id on success, None on any failure.
    """
    try:
        # Coerce severity — warn and default to "info" if invalid
        sev = severity.lower() if severity else "info"
        if sev not in _VALID_SEVERITIES:
            _LOG.warning("emit_event: invalid severity %r for %s:%s — coercing to 'info'",
                         severity, source_module, event_type)
            sev = "info"

        ev = CentralEvent(
            source_module    = str(source_module)[:64],
            source_table     = str(source_table)[:64],
            source_row_id    = str(source_row_id)[:64],
            event_type       = str(event_type)[:128],
            severity         = sev,
            user_id          = user_id,
            entity           = (str(entity)[:256] if entity else None),
            entity_type      = (str(entity_type)[:32] if entity_type else None),
            title            = (str(title)[:512] if title else None),
            description      = description,
            mitre_techniques = mitre_techniques,
            risk_score       = (max(0, min(100, int(risk_score))) if risk_score is not None else None),
            payload          = payload or {},
            node_meta        = {},
        )
        db.session.add(ev)
        db.session.commit()
        return ev.id

    except Exception:
        _LOG.exception(
            "emit_event failed (best-effort): source=%s table=%s row=%s event=%s",
            source_module, source_table, source_row_id, event_type,
        )
        try:
            db.session.rollback()
        except Exception:
            pass
        return None
