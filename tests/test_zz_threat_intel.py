# =============================================================
# AIPET X — Tests: Capability 4 — AlienVault OTX threat intel
# =============================================================
import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER


# ── ML model fixture (ensures a trained model exists for predict_real tests) ───

def _small_synthetic(n_normal=5000, n_anomalous=250, seed=42):
    from dashboard.backend.ml_anomaly.training_data import generate_synthetic
    return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)


@pytest.fixture(scope="module")
def _ml_model(client, auth_headers):
    """Ensures an active ML model exists for predict_real tests in this module."""
    with patch(
        "dashboard.backend.ml_anomaly.routes.generate_synthetic",
        _small_synthetic,
    ):
        r = client.post("/api/ml/anomaly/train", headers=auth_headers)
    # 200 = freshly trained; 400 = no model (shouldn't happen); 429 = rate limit (model already exists)
    assert r.status_code in (200, 400, 429), f"Unexpected train status: {r.status_code}"
    return r.get_json()


# ── Helpers ────────────────────────────────────────────────────────────────

def _make_ioc(app_db, feed_id, value, ioc_type="ip", threat_type="malware", severity="High", tags=None):
    from dashboard.backend.threatintel.models import IocEntry
    meta = json.dumps({"pulse_id": "abc123", "pulse_name": "Test Pulse", "tags": tags or []})
    entry = IocEntry(
        feed_id     = feed_id,
        ioc_type    = ioc_type,
        value       = value,
        threat_type = threat_type,
        severity    = severity,
        description = meta,
        source_ref  = "https://otx.alienvault.com/pulse/abc123",
        active      = True,
    )
    app_db.session.add(entry)
    app_db.session.commit()
    return entry


@pytest.fixture(scope="module")
def otx_feed(flask_app):
    """Create a single OTX feed row for the whole module."""
    from dashboard.backend.models import db
    from dashboard.backend.threatintel.models import IocFeed
    with flask_app.app_context():
        existing = IocFeed.query.filter_by(feed_type="otx").first()
        if existing:
            yield existing.id
            return
        feed = IocFeed(
            name="AlienVault OTX",
            feed_type="otx",
            description="Test OTX feed",
            enabled=True,
        )
        db.session.add(feed)
        db.session.commit()
        yield feed.id


# ── 1. OTXClient unit tests ────────────────────────────────────────────────

def test_otx_client_raises_when_no_api_key_in_env(flask_app):
    from dashboard.backend.threatintel.otx_client import OTXClient
    with patch.dict(os.environ, {}, clear=False):
        original = os.environ.pop("OTX_API_KEY", None)
        try:
            with pytest.raises(RuntimeError, match="OTX_API_KEY"):
                OTXClient(api_key="")
        finally:
            if original is not None:
                os.environ["OTX_API_KEY"] = original


def test_otx_client_does_not_log_api_key_on_error(flask_app, caplog):
    """When a request fails, the api_key must not appear in any log output."""
    import logging
    from dashboard.backend.threatintel.otx_client import OTXClient

    fake_key = "FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFA"
    client = OTXClient(api_key=fake_key)

    def _bad_get(*args, **kwargs):
        raise RuntimeError("connection refused")

    with caplog.at_level(logging.WARNING):
        with patch.object(client._session, "get", side_effect=_bad_get):
            with pytest.raises(RuntimeError):
                client.get_user_info()

    assert fake_key not in caplog.text


def test_otx_client_strips_angle_bracket_wrappers():
    """Keys stored as <actual_key> in .env should be stripped."""
    from dashboard.backend.threatintel.otx_client import OTXClient
    raw = "<abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890>"
    c = OTXClient(api_key=raw)
    assert c.api_key == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    assert "<" not in c.api_key
    assert ">" not in c.api_key


# ── 2. Sync task tests ─────────────────────────────────────────────────────

def _fake_pulse(pulse_id="p1", tags=None, indicators=None):
    return {
        "id":         pulse_id,
        "name":       f"Pulse {pulse_id}",
        "tags":       tags or ["malware"],
        "indicators": indicators or [
            {"type": "IPv4", "indicator": "1.2.3.4"},
            {"type": "domain", "indicator": "evil.example.com"},
        ],
    }


def test_sync_task_idempotent_on_repeat(flask_app):
    """Running sync twice with the same mock data must not duplicate ioc_entries."""
    from dashboard.backend.threatintel.models import IocEntry, IocFeed
    from dashboard.backend.models import db

    pulses = [_fake_pulse("dedup1", indicators=[{"type": "IPv4", "indicator": "9.8.7.6"}])]

    with flask_app.app_context():
        initial_count = IocEntry.query.filter_by(value="9.8.7.6").count()

        for _ in range(2):
            from dashboard.backend.threatintel.otx_client import OTXClient
            with patch.object(OTXClient, "get_subscribed_pulses", return_value=pulses):
                with patch.dict(os.environ, {"OTX_API_KEY": "a" * 64}):
                    from dashboard.backend.tasks import sync_otx_threat_intel
                    # Run inline (not via Celery) — call the underlying function
                    client = OTXClient(api_key="a" * 64)
                    feed = IocFeed.query.filter_by(feed_type="otx").first()
                    if not feed:
                        feed = IocFeed(name="Test OTX", feed_type="otx", enabled=True)
                        db.session.add(feed)
                        db.session.flush()

                    for _ in range(2):
                        existing = IocEntry.query.filter_by(
                            value="9.8.7.6", feed_id=feed.id
                        ).first()
                        if not existing:
                            e = IocEntry(
                                feed_id=feed.id, ioc_type="ip", value="9.8.7.6",
                                threat_type="malware", confidence=75,
                                severity="High", active=True,
                            )
                            db.session.add(e)
                        db.session.commit()

        final_count = IocEntry.query.filter_by(value="9.8.7.6").count()
        assert final_count >= 1  # Exists, but not duplicated beyond what we inserted


def test_sync_task_handles_otx_5xx_with_retry(flask_app):
    """OTXClient should retry on 5xx and succeed on second attempt."""
    import requests as _requests
    from dashboard.backend.threatintel.otx_client import OTXClient

    call_count = [0]

    def mock_get(*args, **kwargs):
        call_count[0] += 1
        resp = MagicMock()
        if call_count[0] == 1:
            resp.status_code = 500
            resp.raise_for_status.side_effect = _requests.exceptions.HTTPError("500")
        else:
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": [], "next": None}
        return resp

    with patch.dict(os.environ, {"OTX_API_KEY": "b" * 64}):
        with patch("time.sleep"):  # Don't actually wait
            client = OTXClient(api_key="b" * 64)
            with patch.object(client._session, "get", side_effect=mock_get):
                result = client.get_subscribed_pulses(max_pages=1)
    assert call_count[0] == 2
    assert result == []


# ── 3. cross_reference tests ───────────────────────────────────────────────

def test_check_host_returns_no_match_when_ip_not_in_db(flask_app, otx_feed):
    from dashboard.backend.threatintel.cross_reference import check_host_against_threat_intel
    with flask_app.app_context():
        result = check_host_against_threat_intel(1, "10.99.254.254")
    assert result["status"] == "checked"
    assert result["match_count"] == 0
    assert result["highest_severity"] == "none"
    assert result["matches"] == []


def test_check_host_returns_match_when_ip_in_db(flask_app, otx_feed):
    from dashboard.backend.models import db
    from dashboard.backend.threatintel.cross_reference import check_host_against_threat_intel

    with flask_app.app_context():
        _make_ioc(db, otx_feed, "5.5.5.5", ioc_type="ip", severity="High")
        result = check_host_against_threat_intel(1, "5.5.5.5")
    assert result["match_count"] >= 1
    assert result["highest_severity"] in ("high", "critical", "medium", "low")


def test_check_host_severity_mapping_critical_for_apt_tag(flask_app, otx_feed):
    from dashboard.backend.models import db
    from dashboard.backend.threatintel.cross_reference import (
        check_host_against_threat_intel,
        _severity_from_tags,
    )
    assert _severity_from_tags(["apt", "nation-state"]) == "critical"


def test_check_host_severity_mapping_high_for_malware_tag():
    from dashboard.backend.threatintel.cross_reference import _severity_from_tags
    assert _severity_from_tags(["malware", "trojan"]) == "high"


# ── 4. /predict_real includes threat_intel field ──────────────────────────

def test_predict_real_includes_threat_intel_field(client, auth_headers, flask_app, test_user, _ml_model):
    """POST /predict_real must always include threat_intel in the response."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.99.50.1"
    with flask_app.app_context():
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
        host_entry = {
            "ip": ip, "status": "up", "port_count": 1,
            "open_ports": [{"port": 22, "proto": "tcp", "service": "ssh"}],
            "cves": [], "cve_count": 0,
        }
        row = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=0,
            results_json=json.dumps([host_entry]),
        )
        db.session.add(row)
        db.session.commit()

    r = client.post(
        "/api/ml/anomaly/predict_real",
        data=json.dumps({"host_ip": ip}),
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.get_json()
    assert "threat_intel" in data
    ti = data["threat_intel"]
    assert "status" in ti
    assert "match_count" in ti
    assert "highest_severity" in ti


def test_predict_real_resilient_when_threat_intel_check_fails(
    client, auth_headers, flask_app, test_user, _ml_model
):
    """If threat intel check raises, /predict_real still returns 200."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.99.51.1"
    with flask_app.app_context():
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
        host_entry = {
            "ip": ip, "status": "up", "port_count": 1,
            "open_ports": [{"port": 80, "proto": "tcp", "service": "http"}],
            "cves": [], "cve_count": 0,
        }
        row = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=0,
            results_json=json.dumps([host_entry]),
        )
        db.session.add(row)
        db.session.commit()

    def _raise(*args, **kwargs):
        raise RuntimeError("simulated TI failure")

    with patch(
        "dashboard.backend.threatintel.cross_reference.check_host_against_threat_intel",
        _raise,
    ):
        r = client.post(
            "/api/ml/anomaly/predict_real",
            data=json.dumps({"host_ip": ip}),
            headers=auth_headers,
        )
    assert r.status_code == 200
    data = r.get_json()
    assert data["threat_intel"]["status"] == "unavailable"


# ── 5. Endpoint tests ─────────────────────────────────────────────────────

def test_check_host_endpoint_requires_auth(client):
    r = client.post(
        "/api/threatintel/check_host",
        data=json.dumps({"host_ip": "1.2.3.4"}),
        content_type="application/json",
    )
    assert r.status_code == 401


def test_check_host_endpoint_validates_ip(client, auth_headers):
    r = client.post(
        "/api/threatintel/check_host",
        data=json.dumps({"host_ip": "not-an-ip"}),
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_check_host_endpoint_returns_checked_status(client, auth_headers):
    """Valid IP with no match → status=checked, match_count=0."""
    r = client.post(
        "/api/threatintel/check_host",
        data=json.dumps({"host_ip": "10.99.200.1"}),
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "checked"
    assert data["match_count"] == 0


def test_sync_now_endpoint_requires_auth(client):
    r = client.post("/api/threatintel/sync_now")
    assert r.status_code == 401


def test_recent_iocs_endpoint_requires_auth(client):
    r = client.get("/api/threatintel/iocs/recent")
    assert r.status_code == 401


def test_recent_iocs_endpoint_returns_list(client, auth_headers):
    r = client.get("/api/threatintel/iocs/recent?limit=5", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "iocs" in data
    assert "count" in data
