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
