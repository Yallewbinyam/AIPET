"""
AIPET X — Device Risk Score Engine

Formula
-------
    score = min(100, Σ [ contribution(event) × time_decay(event) ])

    contribution(event) =
        (event.risk_score  if set  else  SEVERITY_POINTS[event.severity])
        × SOURCE_MULTIPLIERS[event.source_module]

    time_decay(event) = 2 ^ (-age_hours / HALF_LIFE_HOURS)

All events older than LOOKBACK_HOURS are excluded entirely.
Score is clamped to [0, 100] and stored as an integer.

Tuning
------
SEVERITY_POINTS and SOURCE_MULTIPLIERS are module-level constants so they
can be reviewed, adjusted, and tested without touching the computation logic.
"""
from __future__ import annotations

import logging
import time as _time
from datetime import datetime, timezone, timedelta

_LOG = logging.getLogger("aipet.risk_engine")

# ── Formula constants ─────────────────────────────────────────────────────────

SEVERITY_POINTS: dict[str, float] = {
    "critical": 60.0,
    "high":     35.0,
    "medium":   15.0,
    "low":       8.0,
    "info":      2.0,
}

SOURCE_MULTIPLIERS: dict[str, float] = {
    "ml_anomaly":       1.0,   # uses risk_score directly; Isolation Forest verdict
    "live_cves":        1.2,   # KEV = actively exploited, highest signal
    "threatintel":      1.1,   # OTX IOC match
    "behavioral":       0.9,   # Z-score deviation
    "mitre_attack":     0.7,   # technique annotation; not a primary threat signal
    "real_scanner":     0.8,   # nmap findings
    "redteam":          1.0,   # successful adversarial action = real signal
    "defense":          0.6,   # defensive action implies upstream signal already counted
    "auth":             0.6,
    "siem":             0.7,
    "multicloud":       0.9,
    "otics":            1.0,
    "zerotrust":        0.9,
    "identity_guardian":1.0,
    "digitaltwin":      0.5,   # simulation output; lower weight than real-world signals
}
DEFAULT_SOURCE_MULTIPLIER: float = 0.7

HALF_LIFE_HOURS: float = 8.0    # score halves every 8 hours
LOOKBACK_HOURS:  float = 24.0   # events older than this are excluded entirely

MIN_SCORE: int = 0
MAX_SCORE: int = 100


# ── Core computation ──────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compute_event_contribution(event, now: datetime | None = None) -> float:
    """
    Time-decayed contribution of one CentralEvent row to a risk score.

    Returns a float. Caller sums contributions for all events and clamps to
    [0, 100]. This function never raises — returns 0.0 on any error.
    """
    try:
        if now is None:
            now = _now_utc()

        # Base value: prefer stored risk_score; fall back to severity string
        base: float
        if event.risk_score is not None:
            base = float(event.risk_score)
        else:
            sev = (event.severity or "low").lower()
            base = SEVERITY_POINTS.get(sev, SEVERITY_POINTS["low"])

        # Source multiplier
        src_mult = SOURCE_MULTIPLIERS.get(
            event.source_module or "", DEFAULT_SOURCE_MULTIPLIER
        )

        # Time decay: 2^(-age/half_life)
        ev_ts = event.created_at
        if ev_ts is None:
            return 0.0
        age_hours = (now - ev_ts).total_seconds() / 3600.0
        if age_hours < 0:
            age_hours = 0.0
        decay = 2.0 ** (-age_hours / HALF_LIFE_HOURS)

        return base * src_mult * decay

    except Exception:
        _LOG.exception("compute_event_contribution: unexpected error")
        return 0.0


def compute_score_for_entity(
    user_id: int,
    entity:  str,
    entity_type: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Compute the live risk score for one (user_id, entity) pair.

    Does NOT write to device_risk_scores — that is the Celery task's job.
    Always succeeds: on any DB error returns score=0, status="error".
    """
    from dashboard.backend.central_events.models import CentralEvent

    if now is None:
        now = _now_utc()

    cutoff = now - timedelta(hours=LOOKBACK_HOURS)

    try:
        q = CentralEvent.query.filter(
            CentralEvent.user_id   == user_id,
            CentralEvent.entity    == entity,
            CentralEvent.created_at >= cutoff,
        )
        if entity_type:
            q = q.filter(CentralEvent.entity_type == entity_type)
        events = q.all()
    except Exception:
        _LOG.exception("compute_score_for_entity: DB query failed for entity=%s", entity)
        return {
            "user_id": user_id, "entity": entity, "entity_type": entity_type,
            "score": 0, "status": "error", "event_count_24h": 0,
            "contributing_modules": [], "top_contributors": [],
            "computed_at": now.isoformat(),
        }

    if not events:
        return {
            "user_id": user_id, "entity": entity, "entity_type": entity_type,
            "score": 0, "status": "no_recent_events", "event_count_24h": 0,
            "contributing_modules": [], "top_contributors": [],
            "computed_at": now.isoformat(),
        }

    contributions: list[tuple] = []
    for ev in events:
        c = compute_event_contribution(ev, now)
        contributions.append((ev, c))

    total = sum(c for _, c in contributions)
    clamped = int(min(MAX_SCORE, max(MIN_SCORE, round(total))))

    # Top 5 contributors by contribution score
    top5 = sorted(contributions, key=lambda x: x[1], reverse=True)[:5]
    top_contributors = [
        {
            "event_id":     ev.id,
            "source_module": ev.source_module,
            "event_type":   ev.event_type,
            "severity":     ev.severity,
            "contribution": round(c, 2),
            "age_hours":    round((now - ev.created_at).total_seconds() / 3600, 1)
                            if ev.created_at else None,
        }
        for ev, c in top5
    ]

    contributing_modules = sorted({ev.source_module for ev in events if ev.source_module})

    return {
        "user_id":              user_id,
        "entity":               entity,
        "entity_type":          entity_type,
        "score":                clamped,
        "status":               "ok",
        "event_count_24h":      len(events),
        "contributing_modules": contributing_modules,
        "top_contributors":     top_contributors,
        "computed_at":          now.isoformat(),
    }


def upsert_score_for_entity(
    user_id: int,
    entity:  str,
    entity_type: str | None = None,
) -> dict:
    """
    Compute score for entity and UPSERT into device_risk_scores.
    Returns the computed dict plus the row id.
    """
    from dashboard.backend.models import db
    from dashboard.backend.risk_engine.models import DeviceRiskScore

    now = _now_utc()
    computed = compute_score_for_entity(user_id, entity, entity_type, now)

    try:
        existing = DeviceRiskScore.query.filter_by(
            user_id=user_id, entity=entity, entity_type=entity_type
        ).first()

        if existing:
            existing.score               = computed["score"]
            existing.event_count_24h     = computed["event_count_24h"]
            existing.contributing_modules = computed["contributing_modules"]
            existing.top_contributors    = computed["top_contributors"]
            existing.last_updated_at     = now
            existing.last_recomputed_at  = now
            row_id = existing.id
        else:
            row = DeviceRiskScore(
                user_id              = user_id,
                entity               = entity,
                entity_type          = entity_type,
                score                = computed["score"],
                event_count_24h      = computed["event_count_24h"],
                contributing_modules = computed["contributing_modules"],
                top_contributors     = computed["top_contributors"],
                last_updated_at      = now,
                last_recomputed_at   = now,
            )
            db.session.add(row)
            db.session.flush()
            row_id = row.id

        db.session.commit()
        computed["id"] = row_id
    except Exception:
        _LOG.exception(
            "upsert_score_for_entity: DB write failed for entity=%s", entity
        )
        try:
            db.session.rollback()
        except Exception:
            pass
        computed["id"] = None

    return computed


def recompute_all_scores(user_id: int | None = None) -> dict:
    """
    Recompute risk scores for every distinct (user_id, entity, entity_type)
    that has central_events in the last LOOKBACK_HOURS window.

    If user_id is None, processes all users.
    Wraps each entity in try/except — one failure does not stop the loop.
    Idempotent: running twice on the same data produces the same score.
    """
    from dashboard.backend.central_events.models import CentralEvent

    t0 = _time.time()
    now = _now_utc()
    cutoff = now - timedelta(hours=LOOKBACK_HOURS)

    try:
        q = CentralEvent.query.with_entities(
            CentralEvent.user_id,
            CentralEvent.entity,
            CentralEvent.entity_type,
        ).filter(
            CentralEvent.created_at >= cutoff,
            CentralEvent.entity.isnot(None),
        )
        if user_id is not None:
            q = q.filter(CentralEvent.user_id == user_id)
        entities = q.distinct().all()
    except Exception:
        _LOG.exception("recompute_all_scores: failed to query distinct entities")
        return {"status": "error", "processed": 0, "updated": 0, "errors": 1,
                "runtime_seconds": round(_time.time() - t0, 2)}

    processed = 0
    updated = 0
    errors = 0

    for uid, ent, ent_type in entities:
        if not ent:
            continue
        try:
            result = upsert_score_for_entity(uid, ent, ent_type)
            processed += 1
            if result.get("id") is not None:
                updated += 1
        except Exception:
            _LOG.exception(
                "recompute_all_scores: entity error uid=%s entity=%s", uid, ent
            )
            errors += 1

    runtime = round(_time.time() - t0, 2)
    _LOG.info(
        "recompute_all_scores: processed=%d updated=%d errors=%d %.2fs",
        processed, updated, errors, runtime,
    )
    return {
        "status":          "ok",
        "processed":       processed,
        "updated":         updated,
        "errors":          errors,
        "runtime_seconds": runtime,
    }
