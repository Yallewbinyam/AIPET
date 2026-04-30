"""
AIPET X — Capability 14 (Exploit Path Mapping) test suite.

Pins the v1 contract introduced 2026-04-30:
  - paths derive from real RealScanResult rows + CVE tables, not the
    legacy hardcoded chains the previous implementation emitted
  - list endpoint is owner-filtered (per-resource get/delete deferred)
  - empty real data => zero paths (honest empty, not a fallback to demo)
  - chain steps cite real CVE IDs from live_cves / kev_catalog
  - KEV-listed CVE in the target adds a third "impact" step
  - stats aggregate across analyses regardless of owner (v1)

Pattern follows tests/test_iam_role_replace.py / test_ml_anomaly.py:
session-scoped flask_app, in-memory SQLite, per-test data setup +
teardown via db.session.delete on the rows the test inserted.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from flask_jwt_extended import create_access_token

from dashboard.backend.attackpath.models import ApAnalysis, ApPath
from dashboard.backend.attackpath.routes import (
    _service_to_technique,
    _likelihood_from_factors,
    _generate_attack_paths,
)
from dashboard.backend.real_scanner.routes import RealScanResult
from dashboard.backend.live_cves.models import LiveCve, KevCatalogEntry
from dashboard.backend.risk_engine.models import DeviceRiskScore
from dashboard.backend.models import db, User


# ── Helpers ──────────────────────────────────────────────────

def _make_other_user(email_suffix):
    """Insert a second user so owner-filter tests have a non-self
    actor to compare against. Caller is responsible for cleanup."""
    u = User(
        email         = f"ap-other-{email_suffix}-{uuid.uuid4().hex[:6]}@aipet.test",
        password_hash = "x",
        name          = "AP Other",
        plan          = "enterprise",
    )
    db.session.add(u)
    db.session.commit()
    return u


def _make_scan(user_id, hosts):
    """Insert a complete RealScanResult with the given hosts list as
    results_json. Returns the ApAnalysis-ready scan row.

    `hosts` is a list of dicts roughly matching what real_scanner emits.
    """
    scan = RealScanResult(
        user_id      = user_id,
        target       = "test-target",
        status       = "complete",
        finished_at  = datetime.utcnow(),
        hosts_found  = len(hosts),
        cve_count    = sum(len(h.get("cves") or []) for h in hosts),
        results_json = json.dumps(hosts),
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def _delete_scan(scan):
    db.session.delete(scan)
    db.session.commit()


def _delete_analysis(a):
    ApPath.query.filter_by(analysis_id=a.id).delete()
    db.session.delete(a)
    db.session.commit()


def _seed_cve(cve_id, cvss=None):
    cve = LiveCve(cve_id=cve_id, description="test", cvss_score=cvss,
                  severity="HIGH" if (cvss or 0) >= 7.0 else "MEDIUM")
    db.session.add(cve)
    db.session.commit()
    return cve


def _seed_kev(cve_id):
    kev = KevCatalogEntry(cve_id=cve_id, vendor_project="TestVendor",
                          product="TestProduct",
                          vulnerability_name="Test Vulnerability",
                          short_description="seeded for attackpath test",
                          known_ransomware_use="Unknown")
    db.session.add(kev)
    db.session.commit()
    return kev


def _delete_cve(cve):
    db.session.delete(cve)
    db.session.commit()


# A fixture-shaped host dict the real_scanner-generation tests reuse.
def _make_host(ip, ports, cves=None, risk_score=0):
    return {
        "ip":           ip,
        "hostnames":    [],
        "status":       "up",
        "os":           "Linux",
        "open_ports":   [
            {"port": p, "proto": "tcp", "service": s,
             "product": "", "version": "", "extrainfo": "", "banner": ""}
            for p, s in ports
        ],
        "port_count":   len(ports),
        "cves":         [{"cve_id": c, "cvss_score": 7.5} for c in (cves or [])],
        "cve_count":    len(cves or []),
        "risk_score":   risk_score,
    }


# ─────────────────────────────────────────────────────────────
# Pure-helper tests (no DB)
# ─────────────────────────────────────────────────────────────

def test_service_to_technique_maps_known_services():
    """SSH/Telnet → T1110 (Brute Force); HTTP → T1190; RDP → T1021;
    SMTP → T1566; SNMP → T1046; MQTT/Modbus → T1040."""
    assert _service_to_technique("ssh")         == "T1110"
    assert _service_to_technique("telnet")      == "T1110"
    assert _service_to_technique("http")        == "T1190"
    assert _service_to_technique("https")       == "T1190"
    assert _service_to_technique("rdp")         == "T1021"
    assert _service_to_technique("ms-wbt-server") == "T1021"
    assert _service_to_technique("smtp")        == "T1566"
    assert _service_to_technique("snmp")        == "T1046"
    assert _service_to_technique("mqtt")        == "T1040"
    assert _service_to_technique("modbus")      == "T1040"
    # Unknown defaults to T1190 (broadest fit)
    assert _service_to_technique("unknown")     == "T1190"
    assert _service_to_technique(None)          == "T1190"


def test_likelihood_factors_high_vs_low():
    """Same formula, different inputs — high-CVSS+KEV+exploit+high-risk
    must produce a much higher score than the all-zeros case."""
    high = _likelihood_from_factors(
        cvss=9.8, kev_listed=True, exploit_public=True, device_risk=90
    )
    low  = _likelihood_from_factors(
        cvss=0,   kev_listed=False, exploit_public=False, device_risk=0
    )
    mid  = _likelihood_from_factors(
        cvss=5.0, kev_listed=False, exploit_public=False, device_risk=0
    )
    assert 90 <= high <= 100
    assert low == 0
    assert 10 <= mid <= 15  # cvss/10 = 0.5; avg of (0.5,0,0,0) = 0.125 → 12-13


def test_likelihood_clamped_to_0_100_range():
    """Edge case: garbage input must not produce out-of-range scores."""
    assert _likelihood_from_factors(99, True, True, 999) == 100
    assert _likelihood_from_factors(-5, False, False, -10) == 0


# ─────────────────────────────────────────────────────────────
# DB-touching tests
# ─────────────────────────────────────────────────────────────

def test_attackpath_model_round_trip(flask_app, test_user):
    """ApAnalysis + ApPath persist and the FK relationship resolves."""
    a = ApAnalysis(name="rt", scope="all", created_by=test_user.id)
    db.session.add(a)
    db.session.commit()
    p = ApPath(
        analysis_id = a.id,
        entry_point = "10.0.0.1",
        target      = "10.0.0.99",
        severity    = "High",
        hops        = 2,
        chain       = json.dumps([{"device": "x", "action": "y", "technique": "T1190"}]),
        techniques  = json.dumps(["T1190"]),
        likelihood  = 55,
        impact      = "test",
    )
    db.session.add(p)
    db.session.commit()
    try:
        ra = ApAnalysis.query.filter_by(id=a.id).first()
        rp = ApPath.query.filter_by(id=p.id).first()
        assert ra is not None
        assert ra.name == "rt"
        assert ra.created_by == test_user.id
        assert rp is not None
        assert rp.analysis_id == a.id
        chain = json.loads(rp.chain)
        assert chain[0]["technique"] == "T1190"
    finally:
        _delete_analysis(a)


def test_run_analysis_with_no_real_data_returns_zero_paths(
    client, flask_app, test_user, auth_headers,
):
    """Honest empty: no scans, no paths. The previous implementation
    emitted 5 hardcoded chains regardless of input — this test pins
    the new behaviour and would fail against the legacy code."""
    # Ensure no scan rows for this user. Older tests may have left
    # rows behind; clean them so this test is deterministic.
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    r = client.post("/api/attackpath/analyse",
                    headers=auth_headers,
                    data=json.dumps({"name": "empty-db"}))
    try:
        assert r.status_code == 201, r.data
        body = r.get_json()
        assert body["success"] is True
        assert body["paths"] == []
        assert body["analysis"]["total_paths"] == 0
        assert body["analysis"]["critical_paths"] == 0
        assert body["analysis"]["max_depth"] == 0
    finally:
        a = ApAnalysis.query.filter_by(id=body["analysis"]["id"]).first()
        if a:
            _delete_analysis(a)


def test_run_analysis_with_real_scan_generates_paths(
    client, flask_app, test_user, auth_headers,
):
    """One scan with a real-shaped host that opens an entry-port (22):
    the analysis must produce >=1 path with chain[0].device == that IP."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    scan = _make_scan(test_user.id, [
        _make_host("10.10.0.5", [(22, "ssh")], cves=[]),
    ])
    try:
        r = client.post("/api/attackpath/analyse",
                        headers=auth_headers,
                        data=json.dumps({"name": "real-scan"}))
        assert r.status_code == 201, r.data
        body = r.get_json()
        assert len(body["paths"]) >= 1
        first_chain = body["paths"][0]["chain"]
        assert first_chain[0]["device"] == "10.10.0.5"
        assert first_chain[0]["technique"] == "T1110"  # ssh → brute force
        # Cleanup
        a = ApAnalysis.query.filter_by(id=body["analysis"]["id"]).first()
        if a:
            _delete_analysis(a)
    finally:
        _delete_scan(scan)


def test_run_analysis_path_cites_real_cve_id_from_live_cves(
    client, flask_app, test_user, auth_headers,
):
    """When a host has CVEs, the chain step must cite the real
    cve_id, and the score must use the real LiveCve.cvss_score."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    cve_id = f"CVE-2099-{uuid.uuid4().hex[:5].upper()}"
    cve_row = _seed_cve(cve_id, cvss=9.8)
    scan = _make_scan(test_user.id, [
        _make_host("10.20.0.7", [(80, "http")], cves=[cve_id]),
    ])
    try:
        r = client.post("/api/attackpath/analyse", headers=auth_headers,
                        data=json.dumps({"name": "real-cve"}))
        assert r.status_code == 201
        body = r.get_json()
        assert len(body["paths"]) >= 1
        path = body["paths"][0]
        assert path["chain"][0]["cve_id"] == cve_id
        # CVSS=9.8 + non-KEV + no exploit_public + risk=0 → factors
        # avg = (0.98 + 0 + 0 + 0) / 4 = 0.245 → ~24
        assert 20 <= path["likelihood"] <= 30
        a = ApAnalysis.query.filter_by(id=body["analysis"]["id"]).first()
        if a:
            _delete_analysis(a)
    finally:
        _delete_scan(scan)
        _delete_cve(cve_row)


def test_run_analysis_kev_listed_cve_adds_third_step_and_lifts_likelihood(
    client, flask_app, test_user, auth_headers,
):
    """Two-host scan with a KEV-listed CVE on the target: chain has
    3 steps (entry → pivot → KEV impact) and likelihood ≥ 50."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    cve_id = f"CVE-2099-{uuid.uuid4().hex[:5].upper()}"
    cve_row = _seed_cve(cve_id, cvss=9.8)
    kev_row = _seed_kev(cve_id)
    scan = _make_scan(test_user.id, [
        _make_host("10.30.0.5", [(443, "https")], cves=[]),
        _make_host("10.30.0.99", [(8080, "http")],
                   cves=[cve_id], risk_score=80),
    ])
    try:
        r = client.post("/api/attackpath/analyse", headers=auth_headers,
                        data=json.dumps({"name": "kev-listed"}))
        assert r.status_code == 201
        body = r.get_json()
        # Find the path whose target is the KEV-bearing host
        paths_to_target = [
            p for p in body["paths"] if p["target"] == "10.30.0.99"
        ]
        assert len(paths_to_target) >= 1
        kev_path = paths_to_target[0]
        # 3 steps when KEV match: entry → pivot → impact
        assert len(kev_path["chain"]) == 3
        assert kev_path["chain"][2]["technique"] == "T1565"
        assert kev_path["chain"][2]["cve_id"] == cve_id
        assert kev_path["likelihood"] >= 50
        assert kev_path["severity"] in ("Critical", "High")
        a = ApAnalysis.query.filter_by(id=body["analysis"]["id"]).first()
        if a:
            _delete_analysis(a)
    finally:
        _delete_scan(scan)
        _delete_cve(kev_row)
        _delete_cve(cve_row)


def test_run_analysis_high_risk_score_qualifies_as_entry(
    client, flask_app, test_user, auth_headers,
):
    """A host with no entry-port but a high DeviceRiskScore is still
    a valid entry point per the spec ('OR device_risk_score >= 60')."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    DeviceRiskScore.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    # Port 9999 is NOT in ENTRY_PORTS, so the host only qualifies via
    # the risk-score floor.
    scan = _make_scan(test_user.id, [
        _make_host("10.40.0.5", [(9999, "custom")], cves=[]),
    ])
    risk_row = DeviceRiskScore(
        user_id=test_user.id, entity="10.40.0.5",
        entity_type="device", score=75,
    )
    db.session.add(risk_row)
    db.session.commit()
    try:
        r = client.post("/api/attackpath/analyse", headers=auth_headers,
                        data=json.dumps({"name": "high-risk-entry"}))
        assert r.status_code == 201
        body = r.get_json()
        assert len(body["paths"]) >= 1
        assert body["paths"][0]["entry_point"] == "10.40.0.5"
    finally:
        _delete_scan(scan)
        db.session.delete(risk_row)
        a = ApAnalysis.query.filter(
            ApAnalysis.name == "high-risk-entry"
        ).first()
        if a:
            _delete_analysis(a)


def test_list_analyses_returns_only_owner_rows(
    client, flask_app, test_user, auth_headers,
):
    """The owner filter on /analyses GET: a separate user's analysis
    must NOT appear in test_user's list."""
    other = _make_other_user("listfilter")
    a_self  = ApAnalysis(name="self",  scope="all", created_by=test_user.id)
    a_other = ApAnalysis(name="other", scope="all", created_by=other.id)
    db.session.add_all([a_self, a_other])
    db.session.commit()
    try:
        r = client.get("/api/attackpath/analyses", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [a["id"] for a in body["analyses"]]
        assert a_self.id  in ids
        assert a_other.id not in ids
    finally:
        db.session.delete(a_self)
        db.session.delete(a_other)
        db.session.delete(other)
        db.session.commit()


def test_list_analyses_returns_401_without_jwt(client, flask_app):
    r = client.get("/api/attackpath/analyses")
    assert r.status_code == 401


def test_get_analysis_returns_paths_in_likelihood_desc_order(
    client, flask_app, test_user, auth_headers,
):
    a = ApAnalysis(name="order", scope="all", created_by=test_user.id)
    db.session.add(a)
    db.session.commit()
    p_low  = ApPath(analysis_id=a.id, entry_point="e", target="t",
                    severity="Medium", hops=1, chain="[]", techniques="[]",
                    likelihood=20)
    p_high = ApPath(analysis_id=a.id, entry_point="e", target="t",
                    severity="High",   hops=1, chain="[]", techniques="[]",
                    likelihood=80)
    p_mid  = ApPath(analysis_id=a.id, entry_point="e", target="t",
                    severity="High",   hops=1, chain="[]", techniques="[]",
                    likelihood=55)
    db.session.add_all([p_low, p_high, p_mid])
    db.session.commit()
    try:
        r = client.get(f"/api/attackpath/analyses/{a.id}",
                       headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        likelihoods = [p["likelihood"] for p in body["paths"]]
        assert likelihoods == sorted(likelihoods, reverse=True)
        assert likelihoods == [80, 55, 20]
    finally:
        _delete_analysis(a)


def test_delete_analysis_cascades_paths(
    client, flask_app, test_user, auth_headers,
):
    """DELETE on an analysis removes all attached ApPath rows."""
    a = ApAnalysis(name="cascade", scope="all", created_by=test_user.id)
    db.session.add(a)
    db.session.commit()
    p = ApPath(analysis_id=a.id, entry_point="x", target="y",
               severity="Low", hops=1, chain="[]", techniques="[]",
               likelihood=10)
    db.session.add(p)
    db.session.commit()
    pid = p.id
    aid = a.id

    r = client.delete(f"/api/attackpath/analyses/{aid}",
                      headers=auth_headers)
    assert r.status_code == 200
    assert ApAnalysis.query.filter_by(id=aid).first() is None
    assert ApPath.query.filter_by(id=pid).first() is None


def test_stats_aggregates_across_analyses(
    client, flask_app, test_user, auth_headers,
):
    a = ApAnalysis(name="stats", scope="all", created_by=test_user.id,
                   total_paths=2, critical_paths=1, max_depth=3)
    db.session.add(a)
    db.session.commit()
    p1 = ApPath(analysis_id=a.id, entry_point="e", target="t",
                severity="Critical", hops=3, chain="[]", techniques="[]",
                likelihood=90)
    p2 = ApPath(analysis_id=a.id, entry_point="e", target="t",
                severity="Medium",   hops=1, chain="[]", techniques="[]",
                likelihood=30, blocked=True)
    db.session.add_all([p1, p2])
    db.session.commit()
    try:
        r = client.get("/api/attackpath/stats", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        # We can't assert exact totals (other tests may leave rows in
        # the same session DB), but our two paths must be reflected.
        assert body["total_analyses"] >= 1
        assert body["total_paths"]    >= 2
        assert body["critical_paths"] >= 1
        assert body["blocked_paths"]  >= 1
    finally:
        _delete_analysis(a)


def test_stats_zero_when_no_analyses(client, flask_app, auth_headers):
    """avg_hops and avg_likelihood are guarded against div-by-zero
    when no paths exist — the body must still parse and return 0.0."""
    # Nuke every analysis row to isolate the empty case.
    ApPath.query.delete()
    ApAnalysis.query.delete()
    db.session.commit()

    r = client.get("/api/attackpath/stats", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["total_analyses"]  == 0
    assert body["total_paths"]     == 0
    assert body["critical_paths"]  == 0
    assert body["blocked_paths"]   == 0
    assert body["avg_hops"]        == 0.0
    assert body["avg_likelihood"]  == 0.0


def test_run_analysis_persists_chain_as_parsable_json(
    client, flask_app, test_user, auth_headers,
):
    """Regression guard: the chain column is JSON-encoded text, so
    a JSON-parsing consumer must round-trip without re-escaping."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    scan = _make_scan(test_user.id, [
        _make_host("10.50.0.5", [(22, "ssh")], cves=[]),
    ])
    try:
        r = client.post("/api/attackpath/analyse", headers=auth_headers,
                        data=json.dumps({"name": "json-roundtrip"}))
        assert r.status_code == 201
        body = r.get_json()
        assert body["paths"], "expected at least one path"
        # Pull the row directly from the DB and verify the stored
        # `chain` text parses cleanly into a list of step dicts.
        path_id = body["paths"][0]["id"]
        row = ApPath.query.filter_by(id=path_id).first()
        parsed = json.loads(row.chain)
        assert isinstance(parsed, list)
        assert isinstance(parsed[0], dict)
        assert "device" in parsed[0]
        assert "technique" in parsed[0]
        a = ApAnalysis.query.filter_by(id=body["analysis"]["id"]).first()
        if a:
            _delete_analysis(a)
    finally:
        _delete_scan(scan)


def test_run_analysis_max_depth_reflects_longest_chain(
    client, flask_app, test_user, auth_headers,
):
    """The KEV-impact path emits 3 steps; non-KEV paths emit 2.
    max_depth on the analysis row must match the longest chain."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    cve_id = f"CVE-2099-{uuid.uuid4().hex[:5].upper()}"
    cve_row = _seed_cve(cve_id, cvss=9.0)
    kev_row = _seed_kev(cve_id)
    scan = _make_scan(test_user.id, [
        _make_host("10.60.0.5", [(80, "http")], cves=[]),
        _make_host("10.60.0.99", [(443, "https")], cves=[cve_id], risk_score=70),
    ])
    try:
        r = client.post("/api/attackpath/analyse", headers=auth_headers,
                        data=json.dumps({"name": "max-depth"}))
        assert r.status_code == 201
        body = r.get_json()
        assert body["analysis"]["max_depth"] >= 3
    finally:
        _delete_scan(scan)
        _delete_cve(kev_row)
        _delete_cve(cve_row)
        a = ApAnalysis.query.filter(ApAnalysis.name == "max-depth").first()
        if a:
            _delete_analysis(a)
