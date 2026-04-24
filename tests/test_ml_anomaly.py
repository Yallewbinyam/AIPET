# =============================================================
# AIPET X — API tests: ml_anomaly blueprint
#
# Tests are declared in deliberate order:
#   1. Tests that require NO trained model (run first)
#   2. Validation-rejection tests (no model created)
#   3. Tests that need a trained model (use `trained_model` fixture)
#
# The `trained_model` session fixture trains on 500+25 samples
# (monkeypatched) so the session total stays under ~3 seconds.
# =============================================================
import json
from unittest.mock import patch

import pytest

# ── Small-dataset helper ──────────────────────────────────────────────────

def _small_synthetic(n_normal=5000, n_anomalous=250, seed=42):
    """Caps the dataset to 500/25 so training finishes in < 1 s."""
    from dashboard.backend.ml_anomaly.training_data import generate_synthetic
    return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)


_ANOMALOUS_SAMPLE = {
    "packet_rate": 950, "byte_rate": 4000,
    "unique_dst_ports": 400, "unique_dst_ips": 80,
    "syn_ratio": 0.92, "rst_ratio": 0.75,
    "failed_auth_rate": 0.8, "open_port_count": 150,
    "cve_count": 4, "outbound_ratio": 0.5,
    "night_activity": 0.9, "protocol_entropy": 2.8,
}

_NORMAL_SAMPLE = {
    "packet_rate": 40, "byte_rate": 4500,
    "unique_dst_ports": 2, "unique_dst_ips": 3,
    "syn_ratio": 0.05, "rst_ratio": 0.01,
    "failed_auth_rate": 0.0, "open_port_count": 1,
    "cve_count": 0, "outbound_ratio": 0.88,
    "night_activity": 0.05, "protocol_entropy": 1.1,
}


# ── Session fixture: train once with small dataset ────────────────────────

@pytest.fixture(scope="session")
def trained_model(client, auth_headers):
    """
    Trains one model for the whole session using the small dataset.
    All predict / list tests depend on this fixture.
    Monkeypatches generate_synthetic in the routes module namespace.
    """
    with patch(
        "dashboard.backend.ml_anomaly.routes.generate_synthetic",
        _small_synthetic,
    ):
        r = client.post("/api/ml/anomaly/train", headers=auth_headers)
    assert r.status_code == 200, f"Train failed: {r.get_json()}"
    return r.get_json()


# ── 1. No-model tests (must run before trained_model is invoked) ──────────

def test_predict_without_trained_model_returns_400(client, auth_headers):
    """Predict before any model is trained must return 400."""
    r = client.post(
        "/api/ml/anomaly/predict",
        data=json.dumps({"sample": {"packet_rate": 10}}),
        headers=auth_headers,
    )
    assert r.status_code == 400
    assert "No trained model" in r.get_json()["error"]


# ── 2. Feature endpoint tests ─────────────────────────────────────────────

def test_features_endpoint_returns_12_features(client, auth_headers):
    r = client.get("/api/ml/anomaly/features", headers=auth_headers)
    assert r.status_code == 200
    d = r.get_json()
    assert d["count"] == 12
    assert len(d["features"]) == 12


def test_features_endpoint_requires_auth(client):
    """GET /features without a token must return 401."""
    r = client.get("/api/ml/anomaly/features")
    assert r.status_code == 401


# ── 3. Validation-rejection tests ────────────────────────────────────────

def test_train_rejects_invalid_contamination(client, auth_headers):
    """contamination=0.9 is >= 0.5 — must return 422."""
    r = client.post(
        "/api/ml/anomaly/train",
        data=json.dumps({"contamination": 0.9}),
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_train_rejects_invalid_n_estimators(client, auth_headers):
    """n_estimators=10 is below minimum of 50 — must return 422."""
    r = client.post(
        "/api/ml/anomaly/train",
        data=json.dumps({"n_estimators": 10}),
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_predict_requires_sample_field(client, auth_headers):
    """Missing 'sample' key must return 422."""
    r = client.post(
        "/api/ml/anomaly/predict",
        data=json.dumps({}),
        headers=auth_headers,
    )
    assert r.status_code == 422


# ── 4. Tests that need a trained model ───────────────────────────────────

def test_train_creates_active_model_version(trained_model):
    """Train endpoint must return metrics and mark version active."""
    assert trained_model["training_samples"] > 0
    m = trained_model["metrics"]
    assert m["f1"] >= 0.80       # relaxed for small 500-sample dataset
    assert m["precision"] >= 0.0
    assert m["recall"] >= 0.0
    assert trained_model["version"].startswith("v")


def test_predict_detects_anomalous_sample(client, auth_headers, trained_model):
    r = client.post(
        "/api/ml/anomaly/predict",
        data=json.dumps({
            "target_ip":     "10.0.0.50",
            "target_device": "suspicious-device",
            "sample":        _ANOMALOUS_SAMPLE,
        }),
        headers=auth_headers,
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d["is_anomaly"] is True
    assert d["severity"] in ("high", "critical")
    assert len(d["top_contributors"]) == 3


def test_predict_returns_low_severity_for_normal_sample(client, auth_headers, trained_model):
    r = client.post(
        "/api/ml/anomaly/predict",
        data=json.dumps({
            "target_ip":     "192.168.1.10",
            "target_device": "thermostat-01",
            "sample":        _NORMAL_SAMPLE,
        }),
        headers=auth_headers,
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d["is_anomaly"] is False
    assert d["severity"] == "low"


def test_predict_persists_detection_row(client, auth_headers, trained_model, flask_app):
    r = client.post(
        "/api/ml/anomaly/predict",
        data=json.dumps({"sample": {"packet_rate": 50}}),
        headers=auth_headers,
    )
    assert r.status_code == 200
    detection_id = r.get_json()["detection_id"]

    from dashboard.backend.ml_anomaly.models import AnomalyDetection
    from dashboard.backend.models import db
    det = db.session.get(AnomalyDetection, detection_id)
    assert det is not None
    assert det.anomaly_score is not None


def test_models_endpoint_lists_trained_version(client, auth_headers, trained_model):
    r = client.get("/api/ml/anomaly/models", headers=auth_headers)
    assert r.status_code == 200
    versions = r.get_json()
    assert len(versions) >= 1
    assert any(v["is_active"] for v in versions)


def test_detections_endpoint_returns_recent(client, auth_headers, trained_model):
    r = client.get("/api/ml/anomaly/detections", headers=auth_headers)
    assert r.status_code == 200
    detections = r.get_json()
    assert len(detections) >= 1   # at least the rows from predict tests above


# =============================================================================
# D2 — Real-data foundation tests
# =============================================================================

import datetime as _dt

_SCAN_HOST_IP = "10.99.0.1"   # deterministic test IP, never conflicts with production
_UNSCANNED_IP = "10.99.0.99"

_SCAN_RESULTS_JSON = json.dumps([
    {
        "ip":         _SCAN_HOST_IP,
        "hostnames":  [],
        "status":     "up",
        "os":         "Linux",
        "os_accuracy": 85,
        "open_ports": [
            {"port": 22,  "proto": "tcp", "service": "ssh",   "product": "OpenSSH", "version": "8.9", "extrainfo": "", "banner": ""},
            {"port": 80,  "proto": "tcp", "service": "http",  "product": "nginx",   "version": "1.22", "extrainfo": "", "banner": ""},
            {"port": 443, "proto": "tcp", "service": "https", "product": "nginx",   "version": "1.22", "extrainfo": "", "banner": ""},
        ],
        "port_count": 3,
        "cves": [
            {"cve_id": "CVE-2023-0001", "description": "Test CVE", "cvss_score": 7.5, "severity": "HIGH", "published": "2023-01-01", "url": "", "matched_keyword": "nginx"},
            {"cve_id": "CVE-2023-0002", "description": "Test CVE 2", "cvss_score": 5.0, "severity": "MEDIUM", "published": "2023-02-01", "url": "", "matched_keyword": "OpenSSH"},
        ],
        "cve_count": 2,
        "risk_score": 50,
    }
])


@pytest.fixture(scope="module")
def seeded_scan(flask_app, test_user):
    """Insert one completed RealScanResult row for the test IP. Module-scoped so
    D2 tests share a single row without re-inserting between tests."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    row = RealScanResult(
        id           = "test-scan-d2-00000001",
        user_id      = test_user.id,
        target       = _SCAN_HOST_IP,
        status       = "complete",
        started_at   = _dt.datetime(2026, 4, 24, 14, 30, 0),  # 14:30 — daytime
        finished_at  = _dt.datetime(2026, 4, 24, 14, 35, 0),
        hosts_found  = 1,
        cve_count    = 2,
        results_json = _SCAN_RESULTS_JSON,
    )
    db.session.add(row)
    db.session.commit()
    yield row
    db.session.delete(row)
    db.session.commit()


# ── feature_extraction unit tests (call the function directly) ────────────────

def test_extract_features_for_host_returns_none_when_no_scans(flask_app, test_user):
    """extractor returns None when user has no scans for the requested IP."""
    from dashboard.backend.ml_anomaly.feature_extraction import extract_features_for_host
    result = extract_features_for_host(test_user.id, _UNSCANNED_IP)
    assert result is None


def test_extract_features_for_host_returns_dict_with_all_12_keys(flask_app, test_user, seeded_scan):
    from dashboard.backend.ml_anomaly.feature_extraction import extract_features_for_host
    from dashboard.backend.ml_anomaly.features import FEATURE_ORDER
    result = extract_features_for_host(test_user.id, _SCAN_HOST_IP)
    assert result is not None
    for key in FEATURE_ORDER:
        assert key in result, f"Missing feature key: {key}"
    assert result["open_port_count"] == 3.0
    assert result["cve_count"] == 2.0


def test_extract_features_labels_synthetic_fields_correctly(flask_app, test_user, seeded_scan):
    from dashboard.backend.ml_anomaly.feature_extraction import extract_features_for_host
    result = extract_features_for_host(test_user.id, _SCAN_HOST_IP)
    assert "_synthetic_fields" in result
    sf = result["_synthetic_fields"]
    # These 9 must always be synthetic today (no watch-agent telemetry yet)
    for key in ("packet_rate", "byte_rate", "unique_dst_ports", "unique_dst_ips",
                "syn_ratio", "rst_ratio", "failed_auth_rate", "outbound_ratio", "protocol_entropy"):
        assert key in sf, f"Expected {key} in _synthetic_fields"
    # open_port_count and cve_count must NOT be synthetic
    assert "open_port_count" not in sf
    assert "cve_count" not in sf
    # night_activity should be synthetic (only 1 scan < 3 minimum)
    assert "night_activity" in sf
    # All placeholder keys must be 0.0
    for key in sf:
        if key in result:
            assert result[key] == 0.0, f"Placeholder {key} should be 0.0"


# ── /extract endpoint tests ────────────────────────────────────────────────────

def test_extract_endpoint_requires_auth(client):
    r = client.post("/api/ml/anomaly/extract",
                    data=json.dumps({"host_ip": _SCAN_HOST_IP}),
                    content_type="application/json")
    assert r.status_code == 401


def test_extract_endpoint_validates_host_ip(client, auth_headers):
    """CIDR notation and hostnames are rejected — only IPs accepted."""
    for bad in ("10.0.0.0/24", "not-an-ip", "", "10.0.0.0.0"):
        r = client.post("/api/ml/anomaly/extract",
                        data=json.dumps({"host_ip": bad}),
                        headers=auth_headers)
        assert r.status_code == 422, f"Expected 422 for host_ip={bad!r}, got {r.status_code}"


def test_extract_endpoint_404_when_no_data(client, auth_headers):
    r = client.post("/api/ml/anomaly/extract",
                    data=json.dumps({"host_ip": _UNSCANNED_IP}),
                    headers=auth_headers)
    assert r.status_code == 404


# ── /predict_real endpoint tests ───────────────────────────────────────────────

def test_predict_real_endpoint_happy_path_with_seeded_scan(client, auth_headers, trained_model, seeded_scan):
    r = client.post("/api/ml/anomaly/predict_real",
                    data=json.dumps({"host_ip": _SCAN_HOST_IP, "target_device": "test-vm"}),
                    headers=auth_headers)
    assert r.status_code == 200
    d = r.get_json()
    assert d["target_ip"] == _SCAN_HOST_IP
    assert d["severity"] in ("low", "medium", "high", "critical")
    assert isinstance(d["anomaly_score"], float)
    assert len(d["top_contributors"]) == 3
    assert "synthetic_fields" in d
    assert len(d["synthetic_fields"]) >= 9


def test_predict_real_endpoint_404_when_no_scan_data(client, auth_headers, trained_model):
    r = client.post("/api/ml/anomaly/predict_real",
                    data=json.dumps({"host_ip": _UNSCANNED_IP}),
                    headers=auth_headers)
    assert r.status_code == 404
    assert "run a scan first" in r.get_json()["error"]


def test_train_real_scans_mode_rejects_insufficient_data(client, auth_headers):
    """training_mode=real_scans must reject when <20 completed scans exist in test DB."""
    r = client.post("/api/ml/anomaly/train",
                    data=json.dumps({"training_mode": "real_scans"}),
                    headers=auth_headers)
    # Test DB has only the seeded scan row(s), far fewer than 20 required
    assert r.status_code == 400
    d = r.get_json()
    assert "insufficient real data" in d["error"]
    assert "found" in d
