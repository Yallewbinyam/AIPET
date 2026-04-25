"""
AIPET X — Risk Forecast Engine (Capability 11)

Three-tier confidence model:
  <10 history points  → insufficient_data  (no forecast produced)
  10-29 points        → low_confidence     (numpy linear regression)
  30+ points          → ok                 (statsmodels ARIMA(1,1,1))

Forecasting runs hourly via Celery. Does NOT trigger Capability 8 automated
responses — that is an explicit design decision. Forecasts raise analyst alerts
only; automation acts on current scores, not predicted ones.
"""
from __future__ import annotations

import logging
import time as _time
from datetime import datetime, timezone, timedelta, date

import numpy as np

_LOG = logging.getLogger("aipet.risk_forecast")

# ── Constants ──────────────────────────────────────────────────────────────────

INSUFFICIENT_DATA_THRESHOLD = 10
ARIMA_MIN_OBSERVATIONS      = 30
DEFAULT_HORIZON_DAYS        = 7
SNAPSHOT_INTERVAL_MINUTES   = 5    # must match capability 9's recompute schedule
RETENTION_DAYS              = 30

ARIMA_ORDER = (1, 1, 1)

# Default threshold levels — mirrors capability 8's defaults.
# Capitalisation matches ForecastAlert.threshold_name values.
THRESHOLD_LEVELS = [
    ("notify",     60),
    ("high_alert", 80),
    ("emergency",  95),
]

# Crossing must be predicted within this many hours to create a ForecastAlert.
ALERT_HORIZON_HOURS = 48


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── History query ──────────────────────────────────────────────────────────────

def get_history_for_entity(
    user_id:     int,
    entity:      str,
    entity_type: str | None = None,
    limit:       int = 2016,
) -> list[tuple[datetime, int]]:
    """
    Returns (snapshot_at, score) tuples sorted ASC (oldest first).
    2016 = 7 days × 24h × 12 five-min intervals.
    """
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory
    q = DeviceRiskScoreHistory.query.filter_by(user_id=user_id, entity=entity)
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    rows = q.order_by(DeviceRiskScoreHistory.snapshot_at.desc()).limit(limit).all()
    rows.reverse()  # oldest first for model fitting
    return [(r.snapshot_at, r.score) for r in rows]


# ── Trend helper ───────────────────────────────────────────────────────────────

def _compute_trend(scores: list[int], window: int = 7) -> str:
    """Returns "increasing" / "decreasing" / "stable" from the last `window` values."""
    recent = scores[-window:] if len(scores) >= window else scores
    if len(recent) < 2:
        return "stable"
    slope = np.polyfit(range(len(recent)), recent, 1)[0]
    if slope > 1.0:
        return "increasing"
    if slope < -1.0:
        return "decreasing"
    return "stable"


# ── Threshold crossing detector ───────────────────────────────────────────────

def _detect_threshold_crossing(predicted_scores: list[dict]) -> dict | None:
    """
    Returns the highest threshold crossed within the predicted window.
    Probability = fraction of CI above threshold = (upper_95 - threshold) / (upper_95 - lower_95).
    Returns None when no crossing is predicted or CI is degenerate.
    """
    best: dict | None = None

    for pred in predicted_scores:
        point    = pred.get("point", 0)
        lower    = pred.get("lower_95", point)
        upper    = pred.get("upper_95", point)
        pred_date = pred.get("date")

        for tname, tvalue in sorted(THRESHOLD_LEVELS, key=lambda x: x[1], reverse=True):
            if point >= tvalue:
                ci_range = upper - lower
                prob = ((upper - tvalue) / ci_range) if ci_range > 0 else 1.0
                prob = max(0.0, min(1.0, prob))
                if best is None or tvalue > best["threshold_value"]:
                    best = {
                        "threshold_name":  tname,
                        "threshold_value": tvalue,
                        "crossing_date":   pred_date,
                        "probability":     round(prob, 3),
                    }
                break  # highest threshold crossed for this day

    return best


# ── Tier 0: insufficient ──────────────────────────────────────────────────────

def _forecast_insufficient(history: list) -> dict:
    return {
        "status":                       "insufficient_data",
        "history_points":               len(history),
        "model_used":                   "none",
        "trend":                        "unknown",
        "predicted_scores":             [],
        "predicted_threshold_crossing": None,
    }


# ── Tier 1: linear (10-29 points) ────────────────────────────────────────────

def _forecast_linear(history: list, horizon_days: int = DEFAULT_HORIZON_DAYS) -> dict:
    """numpy.polyfit linear regression. CI = ±1 stddev of residuals."""
    times  = np.arange(len(history), dtype=float)
    scores = np.array([s for _, s in history], dtype=float)

    coeffs   = np.polyfit(times, scores, 1)
    slope    = coeffs[0]
    residuals = scores - np.polyval(coeffs, times)
    stddev   = float(np.std(residuals)) if len(residuals) > 1 else 5.0

    last_t = float(len(history) - 1)
    # Step forward one day at a time (288 intervals of 5 min = 1 day)
    steps_per_day = int(60 / SNAPSHOT_INTERVAL_MINUTES * 24)

    predicted_scores = []
    base_date = _now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    for day in range(1, horizon_days + 1):
        t_pred = last_t + day * steps_per_day
        point  = float(np.polyval(coeffs, t_pred))
        point  = max(0.0, min(100.0, point))
        lower  = max(0.0, point - stddev)
        upper  = min(100.0, point + stddev)
        pred_dt = (base_date + timedelta(days=day)).strftime("%Y-%m-%d")
        predicted_scores.append({
            "date":      pred_dt,
            "point":     round(point, 1),
            "lower_95":  round(lower, 1),
            "upper_95":  round(upper, 1),
        })

    return {
        "model_used":      "linear",
        "trend":           _compute_trend([s for _, s in history]),
        "predicted_scores": predicted_scores,
    }


# ── Tier 2: ARIMA (30+ points) ───────────────────────────────────────────────

def _forecast_arima(history: list, horizon_days: int = DEFAULT_HORIZON_DAYS) -> dict:
    """
    statsmodels ARIMA(1,1,1) fitted on daily medians.
    Falls back to linear on any convergence failure.
    """
    try:
        from statsmodels.tsa.arima.model import ARIMA as _ARIMA
        import warnings

        # Resample to daily medians (5-min data is too granular for 7-day forecasts)
        day_map: dict[str, list[float]] = {}
        for ts, score in history:
            day_key = ts.strftime("%Y-%m-%d") if hasattr(ts, "strftime") else str(ts)[:10]
            day_map.setdefault(day_key, []).append(float(score))

        if len(day_map) < 2:
            return _forecast_linear(history, horizon_days)

        sorted_days = sorted(day_map.keys())
        daily_scores = np.array([np.median(day_map[d]) for d in sorted_days], dtype=float)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = _ARIMA(daily_scores, order=ARIMA_ORDER)
            fit   = model.fit()

        forecast   = fit.get_forecast(steps=horizon_days)
        pred_mean  = forecast.predicted_mean
        conf_int   = forecast.conf_int(alpha=0.05)

        predicted_scores = []
        base_date = _now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
        for day in range(horizon_days):
            point = float(np.clip(pred_mean[day], 0, 100))
            lower = float(np.clip(conf_int[day, 0], 0, 100))
            upper = float(np.clip(conf_int[day, 1], 0, 100))
            pred_dt = (base_date + timedelta(days=day + 1)).strftime("%Y-%m-%d")
            predicted_scores.append({
                "date":     pred_dt,
                "point":    round(point, 1),
                "lower_95": round(lower, 1),
                "upper_95": round(upper, 1),
            })

        return {
            "model_used":       f"ARIMA{ARIMA_ORDER}",
            "trend":            _compute_trend([s for _, s in history]),
            "predicted_scores": predicted_scores,
        }

    except Exception:
        _LOG.warning("ARIMA fit failed for history len=%d — falling back to linear", len(history))
        result = _forecast_linear(history, horizon_days)
        result["model_used"] = "linear"   # note fallback
        return result


# ── Main forecast entry point ─────────────────────────────────────────────────

def forecast_for_entity(
    user_id:      int,
    entity:       str,
    entity_type:  str | None = None,
    horizon_days: int = DEFAULT_HORIZON_DAYS,
) -> dict:
    """
    Returns the full forecast dict. Never raises.
    """
    now     = _now_utc()
    history = get_history_for_entity(user_id, entity, entity_type)
    n       = len(history)
    current_score = history[-1][1] if history else 0

    base = {
        "entity":       entity,
        "entity_type":  entity_type,
        "user_id":      user_id,
        "forecast_date": now.isoformat(),
        "horizon_days": horizon_days,
        "current_score": current_score,
        "history_points": n,
        "computed_at":  now.isoformat(),
    }

    if n < INSUFFICIENT_DATA_THRESHOLD:
        return {**base, **_forecast_insufficient(history)}

    if n < ARIMA_MIN_OBSERVATIONS:
        result = _forecast_linear(history, horizon_days)
        status = "low_confidence"
    else:
        result = _forecast_arima(history, horizon_days)
        status = "ok"

    crossing = _detect_threshold_crossing(result.get("predicted_scores", []))

    return {
        **base,
        "status":                       status,
        "model_used":                   result["model_used"],
        "trend":                        result["trend"],
        "predicted_scores":             result["predicted_scores"],
        "predicted_threshold_crossing": crossing,
    }


# ── ForecastAlert upsert ──────────────────────────────────────────────────────

def upsert_forecast_alert(
    user_id:         int,
    entity:          str,
    entity_type:     str | None,
    forecast_result: dict,
) -> int | None:
    """
    Creates or updates a ForecastAlert when a threshold crossing is predicted
    within ALERT_HORIZON_HOURS. Returns the alert id or None.
    Does NOT interact with Capability 8 — forecast alerts are analyst-only.
    """
    from dashboard.backend.models import db
    from dashboard.backend.risk_forecast.models import ForecastAlert

    crossing = forecast_result.get("predicted_threshold_crossing")
    if not crossing:
        return None

    # Only alert if crossing is within the alert horizon
    try:
        crossing_dt = datetime.strptime(crossing["crossing_date"], "%Y-%m-%d")
        now         = _now_utc()
        hours_away  = (crossing_dt - now).total_seconds() / 3600
        if hours_away > ALERT_HORIZON_HOURS:
            return None
    except Exception:
        return None

    try:
        existing = ForecastAlert.query.filter_by(
            user_id        = user_id,
            entity         = entity,
            threshold_name = crossing["threshold_name"],
            status         = "active",
        ).first()

        if existing:
            existing.predicted_crossing_date = crossing_dt
            existing.probability             = crossing["probability"]
            existing.current_score           = forecast_result.get("current_score", 0)
            existing.model_used              = forecast_result.get("model_used")
            existing.history_points          = forecast_result.get("history_points", 0)
            db.session.commit()
            return existing.id
        else:
            alert = ForecastAlert(
                user_id                = user_id,
                entity                 = entity,
                entity_type            = entity_type,
                threshold_name         = crossing["threshold_name"],
                threshold_value        = crossing["threshold_value"],
                current_score          = forecast_result.get("current_score", 0),
                predicted_crossing_date = crossing_dt,
                probability            = crossing["probability"],
                model_used             = forecast_result.get("model_used"),
                history_points         = forecast_result.get("history_points", 0),
                horizon_days           = forecast_result.get("horizon_days", DEFAULT_HORIZON_DAYS),
                status                 = "active",
            )
            db.session.add(alert)
            db.session.commit()
            return alert.id
    except Exception:
        _LOG.exception("upsert_forecast_alert: DB error entity=%s", entity)
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


# ── Batch forecast ────────────────────────────────────────────────────────────

def forecast_all_entities(user_id: int | None = None) -> dict:
    """
    Iterate every distinct (user_id, entity, entity_type) in device_risk_score_history.
    Produce forecasts and upsert alerts. Per-entity try/except.
    """
    from dashboard.backend.models import db
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory

    t0 = _time.time()
    processed = ok = low_confidence = insufficient = alerts_created = errors = 0

    try:
        q = db.session.query(
            DeviceRiskScoreHistory.user_id,
            DeviceRiskScoreHistory.entity,
            DeviceRiskScoreHistory.entity_type,
        ).distinct()
        if user_id is not None:
            q = q.filter(DeviceRiskScoreHistory.user_id == user_id)
        entities = q.all()
    except Exception:
        _LOG.exception("forecast_all_entities: failed to query distinct entities")
        return {"status": "error", "processed": 0, "errors": 1,
                "runtime_seconds": round(_time.time() - t0, 2)}

    for uid, ent, ent_type in entities:
        try:
            result = forecast_for_entity(uid, ent, ent_type)
            processed += 1
            status = result.get("status", "")
            if status == "ok":
                ok += 1
            elif status == "low_confidence":
                low_confidence += 1
            else:
                insufficient += 1

            alert_id = upsert_forecast_alert(uid, ent, ent_type, result)
            if alert_id:
                alerts_created += 1
        except Exception:
            _LOG.exception("forecast_all_entities: error uid=%s entity=%s", uid, ent)
            errors += 1

    runtime = round(_time.time() - t0, 2)
    _LOG.info(
        "forecast_all_entities: processed=%d ok=%d low=%d insuf=%d alerts=%d errors=%d %.2fs",
        processed, ok, low_confidence, insufficient, alerts_created, errors, runtime,
    )
    return {
        "status":          "ok",
        "processed":       processed,
        "ok":              ok,
        "low_confidence":  low_confidence,
        "insufficient":    insufficient,
        "alerts_created":  alerts_created,
        "errors":          errors,
        "runtime_seconds": runtime,
    }


# ── Retention prune ───────────────────────────────────────────────────────────

def prune_old_history(retention_days: int = RETENTION_DAYS) -> int:
    """
    Deletes DeviceRiskScoreHistory rows older than retention_days.
    Returns count of deleted rows.
    """
    from dashboard.backend.models import db
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory

    cutoff = _now_utc() - timedelta(days=retention_days)
    try:
        count = (
            DeviceRiskScoreHistory.query
            .filter(DeviceRiskScoreHistory.snapshot_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.session.commit()
        _LOG.info("prune_old_history: deleted %d rows older than %d days", count, retention_days)
        return count
    except Exception:
        _LOG.exception("prune_old_history: failed")
        try:
            db.session.rollback()
        except Exception:
            pass
        return 0
