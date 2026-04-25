# =============================================================
# AIPET X — Tests: Capability 6 — MITRE ATT&CK live mapping
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


# ── Catalog tests ─────────────────────────────────────────────────────────────

def test_catalog_contains_all_required_techniques(flask_app):
    from dashboard.backend.mitre_attack.catalog import TECHNIQUE_CATALOG
    required = ["T1110", "T1190", "T1046", "T1071", "T1078", "T1041", "T1040",
                "T1059", "T1083", "T1021", "T1548"]
    for tid in required:
        assert tid in TECHNIQUE_CATALOG, f"{tid} missing from TECHNIQUE_CATALOG"


def test_catalog_seeded_in_db(flask_app):
    from dashboard.backend.mitre_attack.models import MitreTechnique
    with flask_app.app_context():
        count = MitreTechnique.query.count()
    assert count >= 40, f"Expected ≥40 techniques seeded, got {count}"


# ── Mapper: from_ml_features ──────────────────────────────────────────────────

def test_from_ml_features_maps_failed_auth_to_t1110(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_ml_features
    contribs = [{"feature": "failed_auth_rate", "shap_value": 1.5,
                 "raw_value": 0.3, "direction": "increases_anomaly"}]
    result = from_ml_features(contribs)
    assert any(m["technique_id"] == "T1110" for m in result)


def test_from_ml_features_maps_high_cve_count_to_t1190(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_ml_features
    contribs = [{"feature": "cve_count", "shap_value": 1.1,
                 "raw_value": 14, "direction": "increases_anomaly"}]
    result = from_ml_features(contribs)
    assert any(m["technique_id"] == "T1190" for m in result)


def test_from_ml_features_deduplicates_when_two_features_map_to_same_technique(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_ml_features
    contribs = [
        {"feature": "unique_dst_ports", "shap_value": 0.9, "raw_value": 50, "direction": "increases_anomaly"},
        {"feature": "syn_ratio",        "shap_value": 0.7, "raw_value": 0.4, "direction": "increases_anomaly"},
        {"feature": "unique_dst_ips",   "shap_value": 0.5, "raw_value": 10, "direction": "increases_anomaly"},
    ]
    result = from_ml_features(contribs)
    t1046_matches = [m for m in result if m["technique_id"] == "T1046"]
    assert len(t1046_matches) == 1, "T1046 should appear exactly once after dedup"


def test_from_ml_features_returns_only_top_5(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_ml_features
    contribs = [
        {"feature": f, "shap_value": 1.0 - i * 0.1, "raw_value": 1.0, "direction": "increases_anomaly"}
        for i, f in enumerate([
            "failed_auth_rate", "cve_count", "unique_dst_ports", "syn_ratio",
            "unique_dst_ips", "night_activity", "byte_rate",
        ])
    ]
    result = from_ml_features(contribs)
    # At most 5 unique techniques (top 5 contributors, deduplicated)
    assert len(result) <= 5


def test_from_ml_features_ignores_decreases_anomaly(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_ml_features
    contribs = [{"feature": "failed_auth_rate", "shap_value": -1.5,
                 "raw_value": 0.0, "direction": "decreases_anomaly"}]
    result = from_ml_features(contribs)
    assert not any(m["technique_id"] == "T1110" for m in result)


# ── Mapper: from_kev_hit ──────────────────────────────────────────────────────

def test_from_kev_hit_uses_cwe_when_available(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_kev_hit
    result = from_kev_hit("CVE-2021-44228", ["CWE-502"])  # Deserialization → T1059
    assert any(m["technique_id"] == "T1059" for m in result)
    assert all(m["source"] == "kev" for m in result)


def test_from_kev_hit_falls_back_to_t1190_when_no_cwe(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_kev_hit
    result = from_kev_hit("CVE-2099-0001", [])
    assert len(result) == 1
    assert result[0]["technique_id"] == "T1190"
    assert result[0]["confidence"] == "low"


# ── Mapper: from_otx_match ────────────────────────────────────────────────────

def test_from_otx_match_handles_ipv4_indicator(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_otx_match
    result = from_otx_match("IPv4", [])
    assert len(result) == 1
    assert result[0]["technique_id"] == "T1071"
    assert result[0]["source"] == "otx"


def test_from_otx_match_handles_ransomware_tag(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_otx_match
    result = from_otx_match("IPv4", ["ransomware"])
    assert any(m["technique_id"] == "T1486" for m in result)


# ── Mapper: from_behavioral_anomaly ──────────────────────────────────────────

def test_from_behavioral_anomaly_uses_anomaly_types_dict(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_behavioral_anomaly
    result = from_behavioral_anomaly("data_exfil")
    assert any(m["technique_id"] == "T1041" for m in result)
    assert all(m["source"] == "behavioral" for m in result)


# ── Mapper: aggregate_techniques ─────────────────────────────────────────────

def test_aggregate_techniques_dedupes_keeps_highest_confidence(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import aggregate_techniques, TechniqueMapping
    mappings = [
        TechniqueMapping(technique_id="T1110", confidence="low", reason="a", source="otx"),
        TechniqueMapping(technique_id="T1110", confidence="high", reason="b", source="ml_feature"),
    ]
    result = aggregate_techniques(mappings)
    t1110 = next(r for r in result if r["technique_id"] == "T1110")
    assert t1110["confidence"] == "high"


def test_aggregate_techniques_collects_all_source_attributions(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import aggregate_techniques, TechniqueMapping
    mappings = [
        TechniqueMapping(technique_id="T1071", confidence="medium", reason="x", source="ml_feature"),
        TechniqueMapping(technique_id="T1071", confidence="low",    reason="y", source="otx"),
    ]
    result = aggregate_techniques(mappings)
    t1071 = next(r for r in result if r["technique_id"] == "T1071")
    assert "ml_feature" in t1071["sources"]
    assert "otx" in t1071["sources"]


# ── T1071 hardcoding regression tests ────────────────────────────────────────

def test_device_deviation_detector_does_not_hardcode_t1071(flask_app, test_user):
    """The regression test: a high failed_auth_rate deviation must NOT produce T1071."""
    from dashboard.backend.behavioral.models import BaBaseline, BaAnomaly
    from dashboard.backend.behavioral.device_deviation_detector import detect_and_record_deviations
    from dashboard.backend.models import db
    import json as _json

    ip = "10.99.77.42"
    with flask_app.app_context():
        # Seed a baseline where failed_auth_rate is normal=0.0
        bl_data = {
            "feature_means":                {"failed_auth_rate": 0.0, "cve_count": 0.0,
                                              **{f: 0.0 for f in ["rst_ratio","packet_rate","byte_rate",
                                                                    "unique_dst_ips","unique_dst_ports",
                                                                    "night_activity","syn_ratio",
                                                                    "open_port_count","outbound_ratio",
                                                                    "protocol_entropy"]}},
            "feature_stds":                 {"failed_auth_rate": 0.01, "cve_count": 0.01,
                                              **{f: 0.01 for f in ["rst_ratio","packet_rate","byte_rate",
                                                                     "unique_dst_ips","unique_dst_ports",
                                                                     "night_activity","syn_ratio",
                                                                     "open_port_count","outbound_ratio",
                                                                     "protocol_entropy"]}},
            "observations": 20,
            "confidence_level": "high",
            "synthetic_features_in_baseline": [],
        }
        bl = BaBaseline(
            entity_id=ip, entity_type="device",
            entity_name=ip, confidence=90,
            baseline=_json.dumps(bl_data),
        )
        db.session.add(bl)
        db.session.commit()

        # Simulate a scan with very high failed_auth_rate (>5σ above baseline)
        current = {"failed_auth_rate": 0.5, "cve_count": 0.0,
                   **{f: 0.0 for f in ["rst_ratio","packet_rate","byte_rate",
                                        "unique_dst_ips","unique_dst_ports","night_activity",
                                        "syn_ratio","open_port_count","outbound_ratio","protocol_entropy"]}}
        result = detect_and_record_deviations(test_user.id, ip, current)

        if result.get("ba_anomaly_id"):
            anomaly = db.session.get(BaAnomaly, result["ba_anomaly_id"])
            # Should be T1110 (Brute Force), NOT T1071
            assert anomaly.mitre_id != "T1071", (
                f"Bug not fixed: mitre_id is still T1071, expected T1110 for failed_auth_rate deviation"
            )
            assert anomaly.mitre_id == "T1110", (
                f"Expected T1110 (Brute Force) for high failed_auth_rate, got {anomaly.mitre_id}"
            )


def test_device_deviation_detector_maps_failed_auth_to_t1110_not_t1071(flask_app):
    from dashboard.backend.mitre_attack.mitre_mapper import from_behavioral_deviations
    top_devs = [{"feature": "failed_auth_rate", "z_score": 8.5, "direction": "above"}]
    result = from_behavioral_deviations(top_devs)
    assert any(m["technique_id"] == "T1110" for m in result)
    assert not any(m["technique_id"] == "T1071" for m in result), (
        "from_behavioral_deviations should return T1110 for failed_auth_rate, not T1071"
    )


# ── /predict_real integration ─────────────────────────────────────────────────

def test_predict_real_includes_mitre_techniques_field(
    client, auth_headers, flask_app, test_user, _ml_model
):
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.98.10.1"
    with flask_app.app_context():
        ts   = datetime.now(timezone.utc).replace(tzinfo=None)
        host = {"ip": ip, "status": "up", "port_count": 1,
                "open_ports": [{"port": 22, "proto": "tcp", "service": "ssh"}],
                "cves": [], "cve_count": 0}
        row  = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=0,
            results_json=json.dumps([host]),
        )
        db.session.add(row)
        db.session.commit()

    r = client.post("/api/ml/anomaly/predict_real",
                    data=json.dumps({"host_ip": ip}),
                    headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "mitre_techniques" in data
    mt = data["mitre_techniques"]
    assert "status" in mt
    assert "technique_count" in mt


def test_predict_real_resilient_when_mitre_mapper_raises(
    client, auth_headers, flask_app, test_user, _ml_model
):
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.models import db

    ip = "10.98.11.1"
    with flask_app.app_context():
        ts   = datetime.now(timezone.utc).replace(tzinfo=None)
        host = {"ip": ip, "status": "up", "port_count": 1,
                "open_ports": [{"port": 80, "proto": "tcp", "service": "http"}],
                "cves": [], "cve_count": 0}
        row  = RealScanResult(
            user_id=test_user.id, target=ip, status="complete",
            started_at=ts, finished_at=ts, hosts_found=1, cve_count=0,
            results_json=json.dumps([host]),
        )
        db.session.add(row)
        db.session.commit()

    with patch("dashboard.backend.mitre_attack.mitre_mapper.from_ml_features",
               side_effect=RuntimeError("simulated MITRE failure")):
        r = client.post("/api/ml/anomaly/predict_real",
                        data=json.dumps({"host_ip": ip}),
                        headers=auth_headers)
    assert r.status_code == 200
    assert r.get_json()["mitre_techniques"]["status"] == "unavailable"


# ── Endpoint tests ─────────────────────────────────────────────────────────────

def test_get_techniques_endpoint_returns_catalog(client, auth_headers):
    r = client.get("/api/mitre/techniques", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "techniques" in data
    assert data["count"] >= 40


def test_get_techniques_endpoint_filters_by_ids(client, auth_headers):
    r = client.get("/api/mitre/techniques?ids=T1110,T1190", headers=auth_headers)
    assert r.status_code == 200
    ids = {t["technique_id"] for t in r.get_json()["techniques"]}
    assert "T1110" in ids
    assert "T1190" in ids
    assert len(ids) == 2


def test_get_technique_by_id_returns_correct_entry(client, auth_headers):
    r = client.get("/api/mitre/techniques/T1110", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert data["technique_id"] == "T1110"
    assert "Brute Force" in data["name"]


def test_get_technique_by_id_returns_404_when_not_in_catalog(client, auth_headers):
    r = client.get("/api/mitre/techniques/T9999", headers=auth_headers)
    assert r.status_code == 404


def test_map_detection_endpoint_validates_source(client, auth_headers):
    r = client.post("/api/mitre/map_detection",
                    data=json.dumps({"detection_id": 1, "source": "invalid_source"}),
                    headers=auth_headers,
                    content_type="application/json")
    assert r.status_code == 422
