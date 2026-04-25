# =============================================================
# AIPET X — Tests: Capability 7a — Central event pipeline
# =============================================================
import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest


# ── ML model fixture ─────────────────────────────────────────────────────────

def _small_synthetic(n_normal=5000, n_anomalous=250, seed=42):
    from dashboard.backend.ml_anomaly.training_data import generate_synthetic
    return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)


@pytest.fixture(scope="module")
def _ml_model(client, auth_headers):
    with patch("dashboard.backend.ml_anomaly.routes.generate_synthetic", _small_synthetic):
        r = client.post("/api/ml/anomaly/train", headers=auth_headers)
    assert r.status_code in (200, 400, 429)
    return r.get_json()


# ── Section 1: emit_event adapter unit tests ──────────────────────────────────

def test_emit_event_returns_id_on_success(flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    with flask_app.app_context():
        ev_id = emit_event(
            source_module="test_module",
            source_table="test_table",
            source_row_id=1,
            event_type="test_event",
            severity="info",
        )
    assert ev_id is not None
    assert isinstance(ev_id, int)


def test_emit_event_never_raises_on_bad_input(flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    with flask_app.app_context():
        # Should return None gracefully, never raise
        result = emit_event(
            source_module="x" * 500,   # too long — but should not crash
            source_table="y",
            source_row_id=None,
            event_type="z",
            severity="invalid_sev",   # invalid — coerced to "info"
        )
    # Returns None or an id — either is acceptable; must not raise
    # (May fail on DB constraints with very long string, but must return None not raise)
    assert result is None or isinstance(result, int)


def test_emit_event_coerces_invalid_severity_to_info(flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    with flask_app.app_context():
        ev_id = emit_event(
            source_module="test_coerce",
            source_table="test_table",
            source_row_id="abc",
            event_type="coerce_sev_test",
            severity="TOTALLY_WRONG",
        )
        assert ev_id is not None
        ev = db.session.get(CentralEvent, ev_id)
        assert ev.severity == "info"


def test_emit_event_stores_source_attribution(flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    with flask_app.app_context():
        ev_id = emit_event(
            source_module="my_module",
            source_table="my_table",
            source_row_id=42,
            event_type="attr_test",
            severity="medium",
            entity="192.168.1.1",
            entity_type="device",
            title="Test attribution",
        )
        ev = db.session.get(CentralEvent, ev_id)
        assert ev.source_module == "my_module"
        assert ev.source_table  == "my_table"
        assert ev.source_row_id == "42"
        assert ev.entity        == "192.168.1.1"


def test_emit_event_accepts_uuid_source_row_id(flask_app):
    import uuid
    from dashboard.backend.central_events.adapter import emit_event
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    uid = uuid.uuid4()
    with flask_app.app_context():
        ev_id = emit_event(
            source_module="uuid_test",
            source_table="some_table",
            source_row_id=uid,
            event_type="uuid_id_test",
            severity="low",
        )
        ev = db.session.get(CentralEvent, ev_id)
        assert ev.source_row_id == str(uid)


def test_emit_event_is_non_fatal_when_db_errors(flask_app):
    """If the DB raises, emit_event must return None, not propagate."""
    from dashboard.backend.central_events.adapter import emit_event

    with flask_app.app_context():
        with patch("dashboard.backend.central_events.adapter.CentralEvent",
                   side_effect=RuntimeError("simulated DB failure")):
            result = emit_event(
                source_module="fail_test",
                source_table="t",
                source_row_id=1,
                event_type="e",
                severity="high",
            )
    assert result is None


def test_emit_event_clamps_risk_score(flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    with flask_app.app_context():
        ev_id = emit_event(
            source_module="clamp_test",
            source_table="t",
            source_row_id=1,
            event_type="clamp",
            severity="info",
            risk_score=9999,
        )
        ev = db.session.get(CentralEvent, ev_id)
        assert ev.risk_score == 100


# ── Section 2: Module wiring integration tests ────────────────────────────────

def test_predict_real_emits_central_event_on_anomaly(
    client, auth_headers, flask_app, test_user, _ml_model
):
    """An anomalous detection via /predict_real must create a central_events row."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db

    ip = "10.97.10.1"
    with flask_app.app_context():
        before_count = CentralEvent.query.filter_by(
            source_module="ml_anomaly", entity=ip
        ).count()

        ts   = datetime.now(timezone.utc).replace(tzinfo=None)
        host = {
            "ip": ip, "status": "up", "port_count": 20,
            "open_ports": [{"port": p, "proto": "tcp", "service": "unknown"}
                           for p in range(22, 42)],
            "cves": [{"cve_id": f"CVE-2021-{i:04d}", "cvss_score": 9.0,
                      "severity": "CRITICAL", "description": "test"}
                     for i in range(10)],
            "cve_count": 10,
        }
        row  = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=10,
            results_json=json.dumps([host]),
        )
        db.session.add(row)
        db.session.commit()

    r = client.post("/api/ml/anomaly/predict_real",
                    data=json.dumps({"host_ip": ip}),
                    headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()

    if data.get("is_anomaly"):
        with flask_app.app_context():
            after_count = CentralEvent.query.filter_by(
                source_module="ml_anomaly", entity=ip
            ).count()
        assert after_count > before_count, "Expected central_event row after anomaly detection"


def test_behavioral_deviation_emits_central_event(flask_app, test_user):
    """A behavioral deviation above threshold must create a central_events row."""
    from dashboard.backend.behavioral.models import BaBaseline
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.behavioral.device_deviation_detector import detect_and_record_deviations
    from dashboard.backend.models import db
    import json as _json

    ip = "10.97.20.1"
    with flask_app.app_context():
        bl_data = {
            "feature_means": {f: 0.0 for f in [
                "failed_auth_rate","cve_count","rst_ratio","packet_rate","byte_rate",
                "unique_dst_ips","unique_dst_ports","night_activity","syn_ratio",
                "open_port_count","outbound_ratio","protocol_entropy",
            ]},
            "feature_stds": {f: 0.01 for f in [
                "failed_auth_rate","cve_count","rst_ratio","packet_rate","byte_rate",
                "unique_dst_ips","unique_dst_ports","night_activity","syn_ratio",
                "open_port_count","outbound_ratio","protocol_entropy",
            ]},
            "observations": 25, "confidence_level": "high",
            "synthetic_features_in_baseline": [],
        }
        bl = BaBaseline(entity_id=ip, entity_type="device",
                        entity_name=ip, confidence=90,
                        baseline=_json.dumps(bl_data))
        db.session.add(bl)
        db.session.commit()

        before = CentralEvent.query.filter_by(
            source_module="behavioral", entity=ip
        ).count()

        current = {f: 0.0 for f in [
            "cve_count","rst_ratio","packet_rate","byte_rate","unique_dst_ips",
            "unique_dst_ports","night_activity","syn_ratio","open_port_count",
            "outbound_ratio","protocol_entropy",
        ]}
        current["failed_auth_rate"] = 1.0  # 100σ above baseline

        detect_and_record_deviations(test_user.id, ip, current)

        after = CentralEvent.query.filter_by(
            source_module="behavioral", entity=ip
        ).count()

    assert after > before, "Expected central_event row after behavioral deviation"


def test_kev_cross_reference_emits_central_event_on_hits(flask_app, test_user):
    """check_host_cves_against_kev must emit when KEV hits exist."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.live_cves.kev_cross_reference import check_host_cves_against_kev
    from dashboard.backend.live_cves.models import KevCatalogEntry
    from dashboard.backend.central_events.models import CentralEvent
    from dashboard.backend.models import db
    from datetime import date

    ip = "10.97.30.1"
    with flask_app.app_context():
        # Seed a KEV entry that matches the scan CVE
        obj = KevCatalogEntry(
            cve_id="CVE-2021-99999",
            vendor_project="TestCo",
            product="TestApp",
            vulnerability_name="Test KEV Vuln",
            date_added=date(2021, 12, 1),
            known_ransomware_use="Unknown",
        )
        db.session.merge(obj)

        ts   = datetime.now(timezone.utc).replace(tzinfo=None)
        host = {"ip": ip, "cves": [{"cve_id": "CVE-2021-99999"}]}
        row  = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=1,
            results_json=json.dumps([host]),
        )
        db.session.add(row)
        db.session.commit()

        before = CentralEvent.query.filter_by(
            source_module="live_cves", entity=ip
        ).count()

        check_host_cves_against_kev(test_user.id, ip)

        after = CentralEvent.query.filter_by(
            source_module="live_cves", entity=ip
        ).count()

    assert after > before, "Expected central_event row after KEV hit"


# ── Section 3: REST endpoint tests ────────────────────────────────────────────

def test_events_feed_endpoint_requires_auth(client):
    r = client.get("/api/events/feed")
    assert r.status_code == 401


def test_events_feed_returns_list(client, auth_headers):
    r = client.get("/api/events/feed?days=30", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "events" in data
    assert "total" in data


def test_events_stats_endpoint(client, auth_headers):
    r = client.get("/api/events/stats?days=30", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "total" in data
    assert "by_severity" in data
    assert "by_module" in data


def test_events_get_single_event(client, auth_headers, flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    with flask_app.app_context():
        ev_id = emit_event(
            source_module="endpoint_test",
            source_table="t",
            source_row_id=1,
            event_type="endpoint_event",
            severity="low",
            entity="1.2.3.4",
        )

    r = client.get(f"/api/events/{ev_id}", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert data["source_module"] == "endpoint_test"
    assert data["entity"] == "1.2.3.4"


def test_events_get_single_event_404(client, auth_headers):
    r = client.get("/api/events/99999999", headers=auth_headers)
    assert r.status_code == 404


def test_events_entity_timeline_endpoint(client, auth_headers, flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    ip = "10.99.99.99"
    with flask_app.app_context():
        emit_event(source_module="timeline_test", source_table="t",
                   source_row_id=1, event_type="t", severity="info", entity=ip)

    r = client.get(f"/api/events/entity/{ip}?days=30", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert data["entity"] == ip
    assert "events" in data


def test_events_feed_filters_by_severity(client, auth_headers, flask_app):
    from dashboard.backend.central_events.adapter import emit_event
    with flask_app.app_context():
        emit_event(source_module="filter_test", source_table="t",
                   source_row_id=99, event_type="filter_sev", severity="critical")

    r = client.get("/api/events/feed?severity=critical&days=1", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    for ev in data["events"]:
        assert ev["severity"] == "critical"


def test_events_feed_filters_by_module(client, auth_headers, flask_app):
    r = client.get("/api/events/feed?source_module=ml_anomaly&days=30", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    for ev in data["events"]:
        assert ev["source_module"] == "ml_anomaly"


def test_predict_real_succeeds_when_emit_event_raises(client, auth_headers, flask_app, test_user, _ml_model):
    """Parent module route must return 200 even if emit_event raises internally."""
    import json as _json
    from datetime import datetime, timezone
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.97.99.1"
    with flask_app.app_context():
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
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

    with patch("dashboard.backend.central_events.adapter.emit_event",
               side_effect=Exception("simulated emit failure")):
        r = client.post("/api/ml/anomaly/predict_real",
                        data=_json.dumps({"host_ip": ip}),
                        headers=auth_headers)
    assert r.status_code == 200, f"Parent route must succeed even when emit_event raises; got {r.status_code}"
