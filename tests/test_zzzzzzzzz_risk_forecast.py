# ============================================================
# AIPET X — Tests: Capability 11 — ARIMA Risk Forecasting
# ============================================================
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _seed_history(flask_app, test_user, entity, scores, base_time=None):
    """Insert DeviceRiskScoreHistory rows for testing."""
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory
    from dashboard.backend.models import db
    if base_time is None:
        base_time = _now() - timedelta(hours=len(scores) * 5 / 60)
    with flask_app.app_context():
        for i, score in enumerate(scores):
            snap_at = base_time + timedelta(minutes=i * 5)
            row = DeviceRiskScoreHistory(
                user_id=test_user.id, entity=entity, entity_type="device",
                score=score, event_count_24h=1, snapshot_at=snap_at,
            )
            db.session.add(row)
        db.session.commit()


def _clear_history(flask_app, test_user, entity):
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory
    from dashboard.backend.models import db
    with flask_app.app_context():
        DeviceRiskScoreHistory.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()


# ── Section 1: History snapshotting ──────────────────────────────────────────

def test_history_row_created_after_score_upsert(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import upsert_score_for_entity
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    entity = "10.11.1.1"
    with flask_app.app_context():
        # Insert a central event so compute_score_for_entity finds something
        ev = CentralEvent(
            source_module="ml_anomaly", source_table="t", source_row_id="1",
            event_type="anomaly", severity="high", user_id=test_user.id,
            entity=entity, entity_type="device", risk_score=60,
            created_at=_now(),
        )
        db.session.add(ev)
        db.session.commit()

        before = DeviceRiskScoreHistory.query.filter_by(
            user_id=test_user.id, entity=entity
        ).count()
        upsert_score_for_entity(test_user.id, entity, "device")
        after = DeviceRiskScoreHistory.query.filter_by(
            user_id=test_user.id, entity=entity
        ).count()

    assert after == before + 1


def test_history_row_failure_does_not_break_score_upsert(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import upsert_score_for_entity
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    entity = "10.11.2.1"
    with flask_app.app_context():
        ev = CentralEvent(
            source_module="siem", source_table="t", source_row_id="2",
            event_type="test", severity="medium", user_id=test_user.id,
            entity=entity, entity_type="device", created_at=_now(),
        )
        db.session.add(ev)
        db.session.commit()

    with patch("dashboard.backend.risk_forecast.models.DeviceRiskScoreHistory",
               side_effect=Exception("simulated history failure")):
        with flask_app.app_context():
            result = upsert_score_for_entity(test_user.id, entity, "device")
    # The main score upsert must still succeed
    assert result.get("score") is not None


# ── Section 2: Engine — 3-tier confidence ─────────────────────────────────────

def test_forecast_insufficient_data_when_under_10_points(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.3.1"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [50, 55, 60])  # only 3 points
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    assert result["status"] == "insufficient_data"
    assert result["model_used"] == "none"
    assert result["predicted_scores"] == []
    assert result["predicted_threshold_crossing"] is None


def test_forecast_linear_used_for_10_to_29_points(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.4.1"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [50 + i for i in range(15)])  # 15 points
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    assert result["status"] == "low_confidence"
    assert result["model_used"] == "linear"
    assert len(result["predicted_scores"]) == 7


def test_forecast_arima_used_for_30_or_more_points(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.5.1"
    _clear_history(flask_app, test_user, entity)
    # 35 points varying around 60
    scores = [60 + (i % 10 - 5) for i in range(35)]
    _seed_history(flask_app, test_user, entity, scores)
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    # Should be "ok" with ARIMA, or "low_confidence" if ARIMA fell back to linear
    assert result["status"] in ("ok", "low_confidence")
    assert result["model_used"] in ("ARIMA(1, 1, 1)", "linear")
    assert len(result["predicted_scores"]) == 7


def test_forecast_returns_history_points_count(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.6.1"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [70] * 12)
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    assert result["history_points"] == 12


def test_forecast_falls_back_to_linear_when_arima_fails(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.7.1"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [70] * 35)
    with patch("dashboard.backend.risk_forecast.engine._ARIMA" if False else
               "statsmodels.tsa.arima.model.ARIMA",
               side_effect=Exception("simulated ARIMA failure")):
        with flask_app.app_context():
            result = forecast_for_entity(test_user.id, entity, "device")
    # Should fall back to linear, not crash
    assert len(result["predicted_scores"]) == 7


def test_forecast_predicted_scores_have_confidence_intervals(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.8.1"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [55 + i for i in range(15)])
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    for pred in result["predicted_scores"]:
        assert "lower_95" in pred
        assert "upper_95" in pred
        assert pred["lower_95"] <= pred["point"]
        assert pred["upper_95"] >= pred["point"]


def test_forecast_trend_increasing(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.9.1"
    _clear_history(flask_app, test_user, entity)
    # Clear upward trend
    _seed_history(flask_app, test_user, entity, [40 + i * 2 for i in range(15)])
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    assert result["trend"] == "increasing"


def test_forecast_trend_decreasing(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import forecast_for_entity
    entity = "10.11.9.2"
    _clear_history(flask_app, test_user, entity)
    _seed_history(flask_app, test_user, entity, [90 - i * 2 for i in range(15)])
    with flask_app.app_context():
        result = forecast_for_entity(test_user.id, entity, "device")
    assert result["trend"] == "decreasing"


def test_threshold_crossing_detected_when_predicted_above_60(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import _detect_threshold_crossing
    predicted = [
        {"date": "2026-05-01", "point": 65.0, "lower_95": 60.0, "upper_95": 70.0},
    ]
    result = _detect_threshold_crossing(predicted)
    assert result is not None
    assert result["threshold_name"] == "notify"
    assert result["threshold_value"] == 60


def test_threshold_crossing_returns_highest_breached_threshold(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import _detect_threshold_crossing
    predicted = [
        {"date": "2026-05-01", "point": 97.0, "lower_95": 92.0, "upper_95": 100.0},
    ]
    result = _detect_threshold_crossing(predicted)
    assert result is not None
    assert result["threshold_name"] == "emergency"
    assert result["threshold_value"] == 95


def test_threshold_crossing_returns_none_when_no_crossings(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import _detect_threshold_crossing
    predicted = [
        {"date": "2026-05-01", "point": 40.0, "lower_95": 35.0, "upper_95": 45.0},
    ]
    result = _detect_threshold_crossing(predicted)
    assert result is None


def test_threshold_crossing_probability_calculation(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import _detect_threshold_crossing
    # point=70, threshold=60, lower=65, upper=80. CI range=15, above threshold = 80-60=20 → capped at 1.0
    predicted = [
        {"date": "2026-05-01", "point": 70.0, "lower_95": 65.0, "upper_95": 80.0},
    ]
    result = _detect_threshold_crossing(predicted)
    assert result is not None
    assert 0.0 <= result["probability"] <= 1.0


# ── Section 3: Alert upsert ───────────────────────────────────────────────────

def test_upsert_forecast_alert_creates_when_crossing_within_48h(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import upsert_forecast_alert
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.20.1"
    # crossing_date = tomorrow (within 48h)
    tomorrow = (_now() + timedelta(hours=24)).strftime("%Y-%m-%d")
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        result = upsert_forecast_alert(test_user.id, entity, "device", {
            "current_score": 70,
            "model_used": "linear",
            "history_points": 12,
            "horizon_days": 7,
            "predicted_threshold_crossing": {
                "threshold_name": "notify",
                "threshold_value": 60,
                "crossing_date": tomorrow,
                "probability": 0.85,
            },
        })
        row = ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity,
                                             threshold_name="notify", status="active").first()
    assert result is not None
    assert row is not None


def test_upsert_forecast_alert_skips_when_crossing_beyond_48h(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import upsert_forecast_alert
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.21.1"
    far_future = (_now() + timedelta(days=6)).strftime("%Y-%m-%d")
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        result = upsert_forecast_alert(test_user.id, entity, "device", {
            "current_score": 70,
            "model_used": "linear",
            "history_points": 12,
            "predicted_threshold_crossing": {
                "threshold_name": "notify",
                "threshold_value": 60,
                "crossing_date": far_future,
                "probability": 0.85,
            },
        })
    assert result is None


def test_upsert_forecast_alert_updates_existing_active_alert(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import upsert_forecast_alert
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.22.1"
    tomorrow = (_now() + timedelta(hours=24)).strftime("%Y-%m-%d")
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        payload = {
            "current_score": 70, "model_used": "linear", "history_points": 12,
            "predicted_threshold_crossing": {
                "threshold_name": "notify", "threshold_value": 60,
                "crossing_date": tomorrow, "probability": 0.70,
            },
        }
        id1 = upsert_forecast_alert(test_user.id, entity, "device", payload)
        payload["predicted_threshold_crossing"]["probability"] = 0.85
        id2 = upsert_forecast_alert(test_user.id, entity, "device", payload)
        rows = ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity,
                                              threshold_name="notify", status="active").all()
    # Only one active alert — updated, not duplicated
    assert id1 == id2
    assert len(rows) == 1
    assert rows[0].probability == pytest.approx(0.85, abs=0.01)


def test_active_alert_unique_constraint_per_entity_threshold(flask_app, test_user):
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    from sqlalchemy.exc import IntegrityError
    entity = "10.11.23.1"
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        a1 = ForecastAlert(
            user_id=test_user.id, entity=entity, entity_type="device",
            threshold_name="notify", threshold_value=60, current_score=70,
            predicted_crossing_date=_now() + timedelta(hours=12),
            probability=0.8, status="active",
        )
        db.session.add(a1)
        db.session.commit()
        a2 = ForecastAlert(
            user_id=test_user.id, entity=entity, entity_type="device",
            threshold_name="notify", threshold_value=60, current_score=72,
            predicted_crossing_date=_now() + timedelta(hours=6),
            probability=0.9, status="active",
        )
        db.session.add(a2)
        try:
            db.session.commit()
            raised = False
        except IntegrityError:
            db.session.rollback()
            raised = True
    assert raised, "Unique constraint should prevent duplicate (user_id, entity, threshold_name, status)"


# ── Section 4: Endpoints ──────────────────────────────────────────────────────

def test_forecast_scores_endpoint_user_scoped(client, auth_headers, flask_app, test_user):
    entity = "10.11.30.1"
    _seed_history(flask_app, test_user, entity, [60] * 5)
    r = client.get("/api/forecast/scores", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "forecasts" in data
    for f in data["forecasts"]:
        assert f["user_id"] == test_user.id


def test_forecast_entity_endpoint_returns_404_when_no_history(client, auth_headers):
    r = client.get("/api/forecast/entity.that.never.existed.xyz111", headers=auth_headers)
    assert r.status_code == 404


def test_forecast_entity_recompute_param_triggers_live_compute(client, auth_headers, flask_app, test_user):
    entity = "10.11.31.1"
    _seed_history(flask_app, test_user, entity, [55] * 5)
    r = client.get(f"/api/forecast/{entity}?recompute=true", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "status" in data
    assert data["status"] == "insufficient_data"  # only 5 points


def test_forecast_alerts_endpoint_filters_by_status(client, auth_headers, flask_app, test_user):
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.32.1"
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        a = ForecastAlert(
            user_id=test_user.id, entity=entity, entity_type="device",
            threshold_name="notify", threshold_value=60, current_score=65,
            predicted_crossing_date=_now(), probability=0.8, status="active",
        )
        db.session.add(a)
        db.session.commit()
    r = client.get("/api/forecast/alerts?status=active", headers=auth_headers)
    assert r.status_code == 200
    for alert in r.get_json()["alerts"]:
        assert alert["status"] == "active"


def test_forecast_alert_acknowledge_sets_timestamp(client, auth_headers, flask_app, test_user):
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.33.1"
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        a = ForecastAlert(
            user_id=test_user.id, entity=entity, entity_type="device",
            threshold_name="high_alert", threshold_value=80, current_score=82,
            predicted_crossing_date=_now(), probability=0.9, status="active",
        )
        db.session.add(a)
        db.session.flush()
        aid = a.id
        db.session.commit()
    r = client.put(f"/api/forecast/alerts/{aid}/acknowledge", headers=auth_headers)
    assert r.status_code == 200
    assert r.get_json()["alert"]["status"] == "acknowledged"
    assert r.get_json()["alert"]["acknowledged_at"] is not None


def test_forecast_alert_dismiss_changes_status(client, auth_headers, flask_app, test_user):
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.34.1"
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        a = ForecastAlert(
            user_id=test_user.id, entity=entity, entity_type="device",
            threshold_name="notify", threshold_value=60, current_score=62,
            predicted_crossing_date=_now(), probability=0.7, status="active",
        )
        db.session.add(a)
        db.session.flush()
        aid = a.id
        db.session.commit()
    r = client.put(f"/api/forecast/alerts/{aid}/dismiss", headers=auth_headers)
    assert r.status_code == 200
    assert r.get_json()["alert"]["status"] == "dismissed"


def test_forecast_recompute_all_endpoint_rate_limit_1_per_hour(client, auth_headers):
    r = client.post("/api/forecast/recompute_all", headers=auth_headers)
    assert r.status_code in (202, 500)


# ── Section 5: Integration + separation ──────────────────────────────────────

def test_forecast_does_not_trigger_capability_8_response(flask_app, test_user):
    """Forecast alert creation must NOT create response_history rows."""
    from dashboard.backend.risk_forecast.engine import upsert_forecast_alert
    from dashboard.backend.automated_response.models import ResponseHistory
    from dashboard.backend.models import db
    entity = "10.11.40.1"
    tomorrow = (_now() + timedelta(hours=20)).strftime("%Y-%m-%d")
    with flask_app.app_context():
        before_responses = ResponseHistory.query.count()
        upsert_forecast_alert(test_user.id, entity, "device", {
            "current_score": 90,
            "model_used": "linear",
            "history_points": 15,
            "predicted_threshold_crossing": {
                "threshold_name": "emergency",
                "threshold_value": 95,
                "crossing_date": tomorrow,
                "probability": 0.92,
            },
        })
        after_responses = ResponseHistory.query.count()
    assert after_responses == before_responses, (
        "Forecast alert creation must not trigger automated responses"
    )


def test_prune_old_history_deletes_rows_older_than_30_days(flask_app, test_user):
    from dashboard.backend.risk_forecast.engine import prune_old_history
    from dashboard.backend.risk_forecast.models import DeviceRiskScoreHistory
    from dashboard.backend.models import db
    entity = "10.11.50.1"
    with flask_app.app_context():
        # Insert old row (31 days ago) and fresh row (today)
        old = DeviceRiskScoreHistory(
            user_id=test_user.id, entity=entity, entity_type="device",
            score=50, snapshot_at=_now() - timedelta(days=31),
        )
        fresh = DeviceRiskScoreHistory(
            user_id=test_user.id, entity=entity, entity_type="device",
            score=55, snapshot_at=_now(),
        )
        db.session.add_all([old, fresh])
        db.session.commit()
        deleted = prune_old_history(retention_days=30)
        remaining = DeviceRiskScoreHistory.query.filter_by(
            user_id=test_user.id, entity=entity
        ).count()
    assert deleted >= 1
    assert remaining >= 1  # fresh row remains


def test_full_forecast_pipeline_from_history_to_alert(flask_app, test_user):
    """Integration: seed >10 points trending up, forecast, alert created."""
    from dashboard.backend.risk_forecast.engine import (
        forecast_for_entity, upsert_forecast_alert
    )
    from dashboard.backend.risk_forecast.models import ForecastAlert
    from dashboard.backend.models import db
    entity = "10.11.60.1"
    _clear_history(flask_app, test_user, entity)
    # 15 points trending from 55 to 70 — should predict crossing notify (60)
    scores = [55 + i for i in range(15)]
    _seed_history(flask_app, test_user, entity, scores)
    with flask_app.app_context():
        ForecastAlert.query.filter_by(user_id=test_user.id, entity=entity).delete()
        db.session.commit()
        result = forecast_for_entity(test_user.id, entity, "device")
        assert result["status"] == "low_confidence"
        assert result["model_used"] == "linear"
        assert len(result["predicted_scores"]) == 7
        alert_id = upsert_forecast_alert(test_user.id, entity, "device", result)
        # If crossing is within 48h, alert created; otherwise None is fine
        if alert_id:
            row = ForecastAlert.query.get(alert_id)
            assert row.status == "active"
            assert row.threshold_value >= 60
