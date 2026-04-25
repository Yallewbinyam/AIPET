# =============================================================
# AIPET X — Tests: behavioral Capability 2
#
# Tests the per-device behavioral baseline (mean/std/Z-score)
# built from real scan data using the FEATURE_ORDER vocabulary.
# =============================================================
import json
from unittest.mock import patch

import pytest

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER


# ── Helpers ────────────────────────────────────────────────────────────────

def _make_scan_row(app_db, user_id, ip, port_count=3, cve_count=2, hour=10):
    """Insert a synthetic RealScanResult row containing ip."""
    from datetime import datetime, timezone
    from dashboard.backend.real_scanner.routes import RealScanResult

    ts = datetime.now(timezone.utc).replace(hour=hour, microsecond=0).replace(tzinfo=None)
    cves_data = [{"cve_id": f"CVE-2025-{i:04d}"} for i in range(cve_count)]
    host_entry = {
        "ip": ip,
        "status": "up",
        "port_count": port_count,
        "open_ports": [{"port": 80 + i, "proto": "tcp", "service": "http"} for i in range(port_count)],
        "cves": cves_data,
        "cve_count": cve_count,
        "os": "Linux",
    }
    row = RealScanResult(
        user_id      = user_id,
        target       = ip,
        status       = "complete",
        started_at   = ts,
        finished_at  = ts,
        hosts_found  = 1,
        cve_count    = cve_count,
        results_json = json.dumps([host_entry]),
    )
    app_db.session.add(row)
    app_db.session.commit()
    return row


@pytest.fixture(scope="module")
def seeded_scans(flask_app, test_user):
    """
    Seed 10 completed scan rows for host 10.99.0.1 so the baseline builder
    can compute a real baseline in tests.
    """
    from dashboard.backend.models import db

    with flask_app.app_context():
        for i in range(10):
            # Vary port_count (2-4) so std > 0 and Z-score deviation tests work
            _make_scan_row(db, test_user.id, "10.99.0.1", port_count=2 + (i % 3), cve_count=1, hour=10 + (i % 4))
    yield
    # No cleanup — session-scoped SQLite is dropped at session teardown.


# ── 1. build_device_baseline unit tests ───────────────────────────────────

def test_build_device_baseline_returns_none_when_insufficient_observations(flask_app, test_user):
    """Host with 0 scans → None (cold-start)."""
    from dashboard.backend.behavioral.device_baseline_builder import build_device_baseline
    with flask_app.app_context():
        result = build_device_baseline(test_user.id, "10.99.99.99")
    assert result is None


def test_build_device_baseline_computes_mean_and_std_for_all_12_features(
    flask_app, test_user, seeded_scans
):
    """10 seeded scans → baseline with all 12 FEATURE_ORDER features."""
    from dashboard.backend.behavioral.device_baseline_builder import build_device_baseline
    with flask_app.app_context():
        result = build_device_baseline(test_user.id, "10.99.0.1", min_observations=5)
    assert result is not None
    assert set(result["feature_means"].keys()) == set(FEATURE_ORDER)
    assert set(result["feature_stds"].keys()) == set(FEATURE_ORDER)
    assert result["feature_vocabulary"] == "ml_anomaly_v1"


def test_build_device_baseline_marks_confidence_low_for_5_to_9_observations(
    flask_app, test_user
):
    """Exactly 5 scans → confidence_level='low'."""
    from datetime import datetime, timezone
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.behavioral.device_baseline_builder import build_device_baseline
    from dashboard.backend.models import db

    ip = "10.99.1.1"
    with flask_app.app_context():
        for _ in range(5):
            _make_scan_row(db, test_user.id, ip, port_count=1, cve_count=0)
        result = build_device_baseline(test_user.id, ip, min_observations=5)
    assert result is not None
    assert result["confidence_level"] == "low"
    assert result["observations"] == 5


def test_build_device_baseline_marks_confidence_medium_for_10_to_29_observations(
    flask_app, test_user, seeded_scans
):
    """10 seeded scans → confidence_level='medium'."""
    from dashboard.backend.behavioral.device_baseline_builder import build_device_baseline
    with flask_app.app_context():
        result = build_device_baseline(test_user.id, "10.99.0.1", min_observations=5)
    assert result is not None
    assert result["confidence_level"] == "medium"


def test_build_device_baseline_marks_confidence_high_for_30_plus_observations(
    flask_app, test_user
):
    """Seed 30+ scans for a host → confidence_level='high'."""
    from dashboard.backend.models import db
    from dashboard.backend.behavioral.device_baseline_builder import build_device_baseline

    ip = "10.99.2.1"
    with flask_app.app_context():
        for _ in range(30):
            _make_scan_row(db, test_user.id, ip, port_count=2, cve_count=1)
        result = build_device_baseline(test_user.id, ip, min_observations=5)
    assert result is not None
    assert result["confidence_level"] == "high"


# ── 2. detect_deviations unit tests ───────────────────────────────────────

def test_detect_deviations_returns_no_baseline_when_none_exists(flask_app, test_user):
    """No baseline row → status='no_baseline'."""
    from dashboard.backend.behavioral.device_deviation_detector import detect_deviations
    sample = {f: 0.0 for f in FEATURE_ORDER}
    with flask_app.app_context():
        result = detect_deviations(test_user.id, "10.99.88.88", sample)
    assert result["status"] == "no_baseline"
    assert result["reason"] == "insufficient_data"


def test_detect_deviations_critical_when_any_z_score_exceeds_5(
    flask_app, test_user, seeded_scans
):
    """Insert a baseline then present a dramatically deviating feature vector."""
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline
    from dashboard.backend.behavioral.device_deviation_detector import detect_deviations

    with flask_app.app_context():
        upsert_device_baseline(test_user.id, "10.99.0.1")
        sample = {f: 0.0 for f in FEATURE_ORDER}
        # Make open_port_count massively above the mean (baseline mean ~2)
        sample["open_port_count"] = 9999.0
        result = detect_deviations(test_user.id, "10.99.0.1", sample)

    assert result["status"] == "checked"
    assert result["severity"] == "critical"


def test_detect_deviations_handles_zero_std_gracefully(flask_app, test_user):
    """If std=0 for a feature, z_score must be 0 (not a division error)."""
    from dashboard.backend.behavioral.device_deviation_detector import _compute_z
    z, zero_flag = _compute_z(5.0, 3.0, 0.0)
    assert z == 0.0
    assert zero_flag is True


# ── 3. detect_and_record_deviations inserts ba_anomalies ─────────────────

def test_detect_and_record_deviations_inserts_ba_anomalies_row_when_severity_above_normal(
    flask_app, test_user, seeded_scans
):
    """Critical deviation → a BaAnomaly row is inserted."""
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline
    from dashboard.backend.behavioral.device_deviation_detector import detect_and_record_deviations
    from dashboard.backend.behavioral.models import BaAnomaly

    with flask_app.app_context():
        upsert_device_baseline(test_user.id, "10.99.0.1")
        sample = {f: 0.0 for f in FEATURE_ORDER}
        sample["open_port_count"] = 9999.0
        result = detect_and_record_deviations(test_user.id, "10.99.0.1", sample)

    assert result.get("ba_anomaly_id") is not None
    with flask_app.app_context():
        from dashboard.backend.models import db
        row = db.session.get(BaAnomaly, result["ba_anomaly_id"])
        assert row is not None
        assert row.status == "new"


# ── 4. /predict_real includes behavioral_baseline field ──────────────────

def test_predict_real_includes_behavioral_baseline_field(
    client, auth_headers, flask_app, test_user
):
    """
    POST /api/ml/anomaly/predict_real must always include behavioral_baseline
    in the response, even when no baseline exists (status='no_baseline').
    Requires a trained model.
    """
    from unittest.mock import patch as _patch

    def _small_synthetic(n_normal=5000, n_anomalous=250, seed=42):
        from dashboard.backend.ml_anomaly.training_data import generate_synthetic
        return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)

    # Train a model first
    with _patch("dashboard.backend.ml_anomaly.routes.generate_synthetic", _small_synthetic):
        train_r = client.post("/api/ml/anomaly/train", headers=auth_headers)
    if train_r.status_code != 200:
        pytest.skip("model training failed — skipping predict_real test")

    # Seed enough scan rows so predict_real can find the host
    from dashboard.backend.models import db
    from datetime import datetime, timezone
    from dashboard.backend.real_scanner.routes import RealScanResult

    ip = "10.99.3.1"
    with flask_app.app_context():
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
        host_entry = {
            "ip": ip, "status": "up", "port_count": 2,
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

    r = client.post(
        "/api/ml/anomaly/predict_real",
        data=json.dumps({"host_ip": ip}),
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.get_json()
    assert "behavioral_baseline" in data
    bb = data["behavioral_baseline"]
    assert "status" in bb


def test_predict_real_resilient_when_behavioral_check_fails(
    client, auth_headers, flask_app, test_user
):
    """
    If the behavioral deviation check raises, /predict_real must still return
    200 with behavioral_baseline.status='error' — never a 500.
    """
    from unittest.mock import patch as _patch

    def _small_synthetic(n_normal=5000, n_anomalous=250, seed=42):
        from dashboard.backend.ml_anomaly.training_data import generate_synthetic
        return generate_synthetic(n_normal=500, n_anomalous=25, seed=seed)

    with _patch("dashboard.backend.ml_anomaly.routes.generate_synthetic", _small_synthetic):
        client.post("/api/ml/anomaly/train", headers=auth_headers)

    from dashboard.backend.models import db
    from datetime import datetime, timezone
    from dashboard.backend.real_scanner.routes import RealScanResult

    ip = "10.99.4.1"
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

    def _raise(*args, **kwargs):
        raise RuntimeError("simulated behavioral failure")

    with _patch(
        "dashboard.backend.behavioral.device_deviation_detector.detect_and_record_deviations",
        _raise,
    ):
        r = client.post(
            "/api/ml/anomaly/predict_real",
            data=json.dumps({"host_ip": ip}),
            headers=auth_headers,
        )

    assert r.status_code == 200
    data = r.get_json()
    assert data["behavioral_baseline"]["status"] == "error"


# ── 5. Endpoint auth and validation tests ────────────────────────────────

def test_baseline_build_endpoint_requires_auth(client):
    """POST /api/behavioral/device/baseline/build without JWT → 401."""
    r = client.post(
        "/api/behavioral/device/baseline/build",
        data=json.dumps({"host_ip": "10.0.0.1"}),
        content_type="application/json",
    )
    assert r.status_code == 401


def test_baseline_build_endpoint_returns_400_when_cold_start(
    client, auth_headers
):
    """Host with 0 scans → 400 insufficient_data."""
    r = client.post(
        "/api/behavioral/device/baseline/build",
        data=json.dumps({"host_ip": "10.99.77.77"}),
        headers=auth_headers,
    )
    assert r.status_code == 400
    assert r.get_json()["status"] == "insufficient_data"


def test_baseline_build_endpoint_rejects_invalid_ip(client, auth_headers):
    """Non-IP value → 422 validation error."""
    r = client.post(
        "/api/behavioral/device/baseline/build",
        data=json.dumps({"host_ip": "not-an-ip"}),
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_baseline_build_all_endpoint_requires_auth(client):
    """POST /api/behavioral/device/baselines/build_all without JWT → 401."""
    r = client.post("/api/behavioral/device/baselines/build_all")
    assert r.status_code == 401


def test_device_baseline_list_endpoint(client, auth_headers, seeded_scans, flask_app, test_user):
    """GET /api/behavioral/device/baselines/list → 200 with device_baselines list."""
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline
    with flask_app.app_context():
        upsert_device_baseline(test_user.id, "10.99.0.1")

    r = client.get("/api/behavioral/device/baselines/list", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "device_baselines" in data
    assert "count" in data
