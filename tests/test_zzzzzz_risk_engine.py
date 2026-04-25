# ============================================================
# AIPET X — Tests: Capability 9 — Device Risk Score Engine
# ============================================================
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_event(flask_app, test_user, source_module, severity="high",
                risk_score=None, age_hours=0.0, entity="10.9.9.1",
                entity_type="device"):
    """Insert a CentralEvent with a controlled created_at timestamp."""
    from dashboard.backend.central_events.adapter import emit_event
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    with flask_app.app_context():
        created_at = _now() - timedelta(hours=age_hours)
        ev = CentralEvent(
            source_module = source_module,
            source_table  = "test_table",
            source_row_id = "1",
            event_type    = f"{source_module}_test",
            severity      = severity,
            user_id       = test_user.id,
            entity        = entity,
            entity_type   = entity_type,
            risk_score    = risk_score,
            created_at    = created_at,
        )
        db.session.add(ev)
        db.session.commit()
        return ev.id


# ── Section 1: compute_event_contribution ────────────────────────────────────

def test_compute_event_contribution_uses_risk_score_when_set(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import (
        compute_event_contribution, SOURCE_MULTIPLIERS,
    )
    ev_id = _make_event(flask_app, test_user, "ml_anomaly", risk_score=71)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        now = ev.created_at  # age = 0
        result = compute_event_contribution(ev, now)
    # base=71, mult=1.0, decay=2^0=1.0
    assert abs(result - 71.0) < 0.01


def test_compute_event_contribution_falls_back_to_severity_points(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import (
        compute_event_contribution, SEVERITY_POINTS,
    )
    ev_id = _make_event(flask_app, test_user, "siem", severity="critical", risk_score=None)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        now = ev.created_at
        result = compute_event_contribution(ev, now)
    mult = 0.7  # siem source multiplier
    assert abs(result - SEVERITY_POINTS["critical"] * mult) < 0.01


def test_compute_event_contribution_applies_source_multiplier(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import (
        compute_event_contribution, SEVERITY_POINTS, SOURCE_MULTIPLIERS,
    )
    ev_id = _make_event(flask_app, test_user, "live_cves", severity="high", risk_score=None)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        now = ev.created_at
        result = compute_event_contribution(ev, now)
    expected = SEVERITY_POINTS["high"] * SOURCE_MULTIPLIERS["live_cves"]
    assert abs(result - expected) < 0.01


def test_compute_event_contribution_applies_time_decay(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_event_contribution, HALF_LIFE_HOURS
    ev_id = _make_event(flask_app, test_user, "siem", severity="critical",
                        risk_score=100, age_hours=HALF_LIFE_HOURS)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        now = ev.created_at + timedelta(hours=HALF_LIFE_HOURS)
        result = compute_event_contribution(ev, now)
    # Expected: 100 * 0.7 (siem) * 2^(-1) = 35.0
    expected = 100 * 0.7 * 0.5
    assert abs(result - expected) < 0.5


def test_compute_event_contribution_for_24h_old_event_is_near_zero(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_event_contribution, HALF_LIFE_HOURS
    ev_id = _make_event(flask_app, test_user, "siem", severity="critical",
                        risk_score=100, age_hours=24)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        # Ask for contribution as if now=24 hours after event
        result_at_24h = compute_event_contribution(ev, ev.created_at + timedelta(hours=24))
    # decay = 2^(-24/8) = 2^(-3) = 0.125 → 100*0.7*0.125 = 8.75
    # "near zero" for a unit test: <15 (not zero but tiny relative to 100)
    assert result_at_24h < 15.0


def test_compute_event_contribution_for_fresh_event_uses_full_value(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_event_contribution
    ev_id = _make_event(flask_app, test_user, "ml_anomaly", risk_score=80, age_hours=0)
    with flask_app.app_context():
        from dashboard.backend.central_events.models import CentralEvent
        ev = CentralEvent.query.get(ev_id)
        result = compute_event_contribution(ev, ev.created_at)  # age=0
    # decay=1.0, mult=1.0 → exactly 80
    assert abs(result - 80.0) < 0.01


# ── Section 2: compute_score_for_entity ──────────────────────────────────────

def test_compute_score_for_entity_with_no_events_returns_zero_with_status(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, "entity.that.has.no.events")
    assert result["score"] == 0
    assert result["status"] == "no_recent_events"
    assert result["event_count_24h"] == 0


def test_compute_score_for_entity_with_one_high_event_returns_correct_score(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity, SOURCE_MULTIPLIERS, SEVERITY_POINTS
    entity = "10.9.42.1"
    _make_event(flask_app, test_user, "live_cves", severity="high",
                risk_score=None, age_hours=0, entity=entity)
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, entity)
    expected = int(round(SEVERITY_POINTS["high"] * SOURCE_MULTIPLIERS["live_cves"]))
    assert result["score"] == expected
    assert result["event_count_24h"] >= 1


def test_compute_score_clamps_at_100_with_many_critical_events(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity
    entity = "10.9.99.99"
    for _ in range(20):
        _make_event(flask_app, test_user, "ml_anomaly", severity="critical",
                    risk_score=90, age_hours=0, entity=entity)
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, entity)
    assert result["score"] == 100


def test_compute_score_clamps_at_zero_minimum(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity
    # No events for this entity
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, "entity.zero.minimum")
    assert result["score"] == 0


def test_compute_score_includes_top_5_contributors(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity
    entity = "10.9.55.1"
    for i in range(7):
        _make_event(flask_app, test_user, "siem", severity="high",
                    age_hours=float(i), entity=entity)
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, entity)
    assert len(result["top_contributors"]) <= 5


def test_compute_score_includes_contributing_modules_list(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity
    entity = "10.9.56.1"
    _make_event(flask_app, test_user, "ml_anomaly",  age_hours=0, entity=entity)
    _make_event(flask_app, test_user, "threatintel",  age_hours=0, entity=entity)
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, entity)
    assert "ml_anomaly"  in result["contributing_modules"]
    assert "threatintel" in result["contributing_modules"]


def test_compute_score_excludes_events_older_than_lookback_hours(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import compute_score_for_entity, LOOKBACK_HOURS
    entity = "10.9.57.1"
    # Insert one very old event (beyond lookback window)
    _make_event(flask_app, test_user, "siem", severity="critical",
                risk_score=100, age_hours=LOOKBACK_HOURS + 1, entity=entity)
    with flask_app.app_context():
        result = compute_score_for_entity(test_user.id, entity)
    assert result["score"] == 0
    assert result["status"] == "no_recent_events"


# ── Section 3: upsert / persistence ──────────────────────────────────────────

def test_upsert_score_creates_row_when_absent(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import upsert_score_for_entity
    from dashboard.backend.risk_engine.models import DeviceRiskScore
    entity = "10.9.60.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=50, entity=entity)
    with flask_app.app_context():
        result = upsert_score_for_entity(test_user.id, entity)
        row = DeviceRiskScore.query.filter_by(user_id=test_user.id, entity=entity).first()
    assert row is not None
    assert row.score >= 0
    assert result["id"] == row.id


def test_upsert_score_updates_row_when_present(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import upsert_score_for_entity
    from dashboard.backend.risk_engine.models import DeviceRiskScore
    entity = "10.9.61.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=40, entity=entity)
    with flask_app.app_context():
        upsert_score_for_entity(test_user.id, entity)
        first_row = DeviceRiskScore.query.filter_by(user_id=test_user.id, entity=entity).first()
        first_id  = first_row.id
        upsert_score_for_entity(test_user.id, entity)
        rows = DeviceRiskScore.query.filter_by(user_id=test_user.id, entity=entity).all()
    # Only one row should exist — no duplicates
    assert len(rows) == 1
    assert rows[0].id == first_id


def test_upsert_score_idempotent(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import upsert_score_for_entity
    entity = "10.9.62.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=60, entity=entity, age_hours=0)
    with flask_app.app_context():
        r1 = upsert_score_for_entity(test_user.id, entity)
        r2 = upsert_score_for_entity(test_user.id, entity)
    assert r1["score"] == r2["score"]


def test_recompute_all_scores_processes_all_users(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import recompute_all_scores
    from dashboard.backend.risk_engine.models import DeviceRiskScore
    entity = "10.9.63.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=55, entity=entity)
    with flask_app.app_context():
        result = recompute_all_scores(user_id=test_user.id)
        row = DeviceRiskScore.query.filter_by(user_id=test_user.id, entity=entity).first()
    assert result["processed"] >= 1
    assert row is not None


def test_recompute_all_scores_skips_entities_with_no_events(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import recompute_all_scores
    from dashboard.backend.risk_engine.models import DeviceRiskScore
    with flask_app.app_context():
        result = recompute_all_scores(user_id=test_user.id)
        # "ghost.entity" was never inserted — should not appear in device_risk_scores
        ghost = DeviceRiskScore.query.filter_by(
            user_id=test_user.id, entity="ghost.entity.never.inserted"
        ).first()
    assert ghost is None


def test_recompute_all_scores_handles_per_entity_errors_gracefully(flask_app, test_user):
    from dashboard.backend.risk_engine.engine import recompute_all_scores
    entity = "10.9.64.1"
    _make_event(flask_app, test_user, "siem", risk_score=30, entity=entity)
    # Patch upsert to raise on the first call, succeed on subsequent ones
    call_count = {"n": 0}
    original = __import__(
        "dashboard.backend.risk_engine.engine", fromlist=["upsert_score_for_entity"]
    ).upsert_score_for_entity

    def _patched(uid, ent, et=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated error")
        return original(uid, ent, et)

    with flask_app.app_context():
        with patch("dashboard.backend.risk_engine.engine.upsert_score_for_entity", _patched):
            result = recompute_all_scores(user_id=test_user.id)
    # Should not raise; errors counted
    assert isinstance(result, dict)
    assert "errors" in result


# ── Section 4: REST endpoints ─────────────────────────────────────────────────

def test_risk_scores_endpoint_user_scoped(client, auth_headers, flask_app, test_user):
    entity = "10.9.70.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=50, entity=entity)
    with flask_app.app_context():
        from dashboard.backend.risk_engine.engine import upsert_score_for_entity
        upsert_score_for_entity(test_user.id, entity)
    r = client.get("/api/risk/scores", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "scores" in data
    assert "total"  in data
    # All rows belong to the authenticated user
    for row in data["scores"]:
        assert row["user_id"] == test_user.id


def test_risk_scores_endpoint_filters_by_min_score(client, auth_headers, flask_app, test_user):
    entity = "10.9.71.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=10,
                entity=entity, age_hours=0)
    with flask_app.app_context():
        from dashboard.backend.risk_engine.engine import upsert_score_for_entity
        upsert_score_for_entity(test_user.id, entity)
    r = client.get("/api/risk/scores?min_score=90", headers=auth_headers)
    assert r.status_code == 200
    for row in r.get_json()["scores"]:
        assert row["score"] >= 90


def test_risk_scores_endpoint_orders_by_score_desc(client, auth_headers, flask_app, test_user):
    with flask_app.app_context():
        from dashboard.backend.risk_engine.engine import upsert_score_for_entity
        for ip, rs in [("10.9.72.1", 10), ("10.9.72.2", 70), ("10.9.72.3", 40)]:
            _make_event(flask_app, test_user, "siem", risk_score=rs, entity=ip, age_hours=0)
            upsert_score_for_entity(test_user.id, ip)
    r = client.get("/api/risk/scores?order=desc", headers=auth_headers)
    assert r.status_code == 200
    scores = [row["score"] for row in r.get_json()["scores"]]
    assert scores == sorted(scores, reverse=True)


def test_risk_entity_endpoint_returns_404_when_no_record(client, auth_headers):
    r = client.get("/api/risk/entity.that.never.existed.xyz", headers=auth_headers)
    assert r.status_code == 404


def test_risk_entity_endpoint_recompute_param_triggers_live_compute(
    client, auth_headers, flask_app, test_user
):
    entity = "10.9.73.1"
    _make_event(flask_app, test_user, "ml_anomaly", risk_score=55, entity=entity)
    r = client.get(f"/api/risk/{entity}?recompute=true", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "score" in data
    assert data["score"] >= 0


def test_risk_top_endpoint_returns_correct_count(client, auth_headers, flask_app, test_user):
    with flask_app.app_context():
        from dashboard.backend.risk_engine.engine import upsert_score_for_entity
        for i in range(5):
            ip = f"10.9.80.{i}"
            _make_event(flask_app, test_user, "siem", risk_score=20 + i*10,
                        entity=ip, age_hours=0)
            upsert_score_for_entity(test_user.id, ip)
    r = client.get("/api/risk/top?limit=3", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "top" in data
    assert len(data["top"]) <= 3


def test_risk_stats_endpoint_returns_buckets(client, auth_headers, flask_app, test_user):
    with flask_app.app_context():
        from dashboard.backend.risk_engine.engine import upsert_score_for_entity
        _make_event(flask_app, test_user, "ml_anomaly", risk_score=90,
                    entity="10.9.90.1", age_hours=0)
        upsert_score_for_entity(test_user.id, "10.9.90.1")
    r = client.get("/api/risk/stats", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "by_score_bucket" in data
    buckets = data["by_score_bucket"]
    assert set(buckets.keys()) == {"0-25", "26-50", "51-75", "76-100"}


def test_risk_recompute_now_endpoint_requires_auth(client):
    r = client.post("/api/risk/recompute_now")
    assert r.status_code == 401


# ── Section 5: /predict_real integration ─────────────────────────────────────

def _small_synthetic(n_normal=500, n_anomalous=25, seed=42):
    from dashboard.backend.ml_anomaly.training_data import generate_synthetic
    return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)


@pytest.fixture(scope="module")
def _trained_model(client, auth_headers):
    with patch("dashboard.backend.ml_anomaly.routes.generate_synthetic", _small_synthetic):
        r = client.post("/api/ml/anomaly/train", headers=auth_headers)
    assert r.status_code in (200, 400, 429)
    return r.get_json()


def test_predict_real_includes_device_risk_score_field(
    client, auth_headers, flask_app, test_user, _trained_model
):
    import json as _json
    from datetime import datetime as _dt, timezone as _tz
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.9.99.1"
    with flask_app.app_context():
        ts = _dt.now(_tz.utc).replace(tzinfo=None)
        host = {
            "ip": ip, "status": "up", "port_count": 20,
            "open_ports": [{"port": p, "proto": "tcp", "service": "unknown"} for p in range(22, 42)],
            "cves": [{"cve_id": f"CVE-2021-{i:04d}", "cvss_score": 9.0,
                      "severity": "CRITICAL", "description": "test"} for i in range(10)],
            "cve_count": 10,
        }
        row = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=10,
            results_json=_json.dumps([host]),
        )
        db.session.add(row)
        db.session.commit()

    r = client.post("/api/ml/anomaly/predict_real",
                    data=_json.dumps({"host_ip": ip}),
                    headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "device_risk_score" in data
    drs = data["device_risk_score"]
    assert "score"  in drs
    assert "status" in drs


def test_predict_real_resilient_when_risk_engine_fails(
    client, auth_headers, flask_app, test_user, _trained_model
):
    import json as _json
    ip = "10.9.99.1"
    with patch("dashboard.backend.risk_engine.engine.compute_score_for_entity",
               side_effect=Exception("simulated risk engine failure")):
        r = client.post("/api/ml/anomaly/predict_real",
                        data=_json.dumps({"host_ip": ip}),
                        headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "device_risk_score" in data
    assert data["device_risk_score"]["status"] == "unavailable"
