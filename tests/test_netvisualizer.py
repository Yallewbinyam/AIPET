"""
AIPET X — Capability 15 (Real Network Topology Graph) test suite.

Pins the v1 contract introduced 2026-04-30:
  - POST /scan ingests from RealScanResult.results_json (no longer
    a stub that just recomputed risk on existing rows)
  - Zone classification: >10 ports → ot; private → corporate;
    public → dmz
  - Edge inference: same-subnet → lateral; non-private → internet-edge
  - Issue generation: cve>=3 OR KEV-listed OR risk>=70
  - User scoping via NvNode.node_meta JSON ({"user_id": N, ...});
    NvEdge / NvIssue scoped transitively via FK to NvNode
  - Empty scan inventory → zero nodes/edges/issues, success=True
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime

from flask_jwt_extended import create_access_token

from dashboard.backend.netvisualizer.models import NvNode, NvEdge, NvIssue
from dashboard.backend.netvisualizer.routes import (
    _classify_zone,
    _is_private_ip,
    _subnet_key,
    _should_create_issue,
    _set_user_meta,
    _node_user_id,
    _scope_node_ids,
    _ingest_for_user,
)
from dashboard.backend.real_scanner.routes import RealScanResult
from dashboard.backend.live_cves.models import KevCatalogEntry
from dashboard.backend.models import db, User


# ── Helpers ──────────────────────────────────────────────────

def _other_user(suffix):
    u = User(
        email         = f"nv-other-{suffix}-{uuid.uuid4().hex[:6]}@aipet.test",
        password_hash = "x",
        name          = "NV Other",
        plan          = "enterprise",
    )
    db.session.add(u)
    db.session.commit()
    return u


def _seed_scan(user_id, hosts):
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


def _seed_kev(cve_id):
    kev = KevCatalogEntry(
        cve_id=cve_id, vendor_project="TestVendor", product="TestProduct",
        vulnerability_name="Test", short_description="seed",
        known_ransomware_use="Unknown",
    )
    db.session.add(kev)
    db.session.commit()
    return kev


def _purge_user_nv(user_id):
    """Wipe everything that belongs to user_id in nv_*. Used for test
    isolation; the production code's _purge_user_state does the same
    but only when called from /scan."""
    node_ids = _scope_node_ids(user_id)
    if node_ids:
        NvIssue.query.filter(NvIssue.node_id.in_(node_ids)).delete(
            synchronize_session=False
        )
        NvEdge.query.filter(
            (NvEdge.source_id.in_(node_ids)) |
            (NvEdge.target_id.in_(node_ids))
        ).delete(synchronize_session=False)
        NvNode.query.filter(NvNode.id.in_(node_ids)).delete(
            synchronize_session=False
        )
        db.session.commit()


def _make_host(ip, ports, cves=None, risk_score=0, port_count=None):
    return {
        "ip":           ip,
        "hostnames":    [],
        "status":       "up",
        "os":           "Linux",
        "open_ports":   [
            {"port": p, "proto": "tcp", "service": s,
             "product": "", "version": ""}
            for p, s in ports
        ],
        "port_count":   port_count if port_count is not None else len(ports),
        "cves":         [{"cve_id": c, "cvss_score": 7.5} for c in (cves or [])],
        "cve_count":    len(cves or []),
        "risk_score":   risk_score,
    }


# ─────────────────────────────────────────────────────────────
# Pure-helper tests (no DB dependency outside model/util imports)
# ─────────────────────────────────────────────────────────────

def test_classify_zone_private_ip_to_corporate():
    h = _make_host("10.0.3.5", [(22, "ssh")])
    assert _classify_zone(h) == "corporate"


def test_classify_zone_public_ip_to_dmz():
    h = _make_host("8.8.8.8", [(443, "https")])
    assert _classify_zone(h) == "dmz"


def test_classify_zone_high_port_count_to_ot():
    """11 open ports overrides IP-class — even a private host with
    that many open services is treated as OT/ICS."""
    ports = [(p, "ssh") for p in range(1, 12)]
    h = _make_host("10.0.3.5", ports, port_count=11)
    assert _classify_zone(h) == "ot"


def test_is_private_ip_recognizes_rfc1918_classes():
    assert _is_private_ip("10.0.0.1")     is True
    assert _is_private_ip("172.16.5.5")   is True
    assert _is_private_ip("192.168.1.1")  is True
    assert _is_private_ip("8.8.8.8")      is False
    assert _is_private_ip("not-an-ip")    is False
    assert _is_private_ip(None)           is False


def test_subnet_key_first_three_octets():
    assert _subnet_key("10.0.3.5")  == "10.0.3"
    assert _subnet_key("10.0.3.99") == "10.0.3"
    assert _subnet_key("not-an-ip") is None


def test_should_create_issue_high_risk_creates_issue():
    h = _make_host("10.0.3.5", [(22, "ssh")], risk_score=85)
    assert _should_create_issue(h, set()) is True


def test_should_create_issue_high_cve_count_creates_issue():
    h = _make_host("10.0.3.5", [(22, "ssh")],
                   cves=["CVE-A", "CVE-B", "CVE-C"])
    assert _should_create_issue(h, set()) is True


def test_should_create_issue_kev_listed_creates_issue():
    h = _make_host("10.0.3.5", [(22, "ssh")], cves=["CVE-KEV"])
    assert _should_create_issue(h, {"CVE-KEV"}) is True


def test_should_create_issue_low_risk_no_issue():
    h = _make_host("10.0.3.5", [(22, "ssh")],
                   cves=["CVE-A"], risk_score=20)
    assert _should_create_issue(h, set()) is False


# ─────────────────────────────────────────────────────────────
# DB-touching ingestion tests
# ─────────────────────────────────────────────────────────────

def test_ingest_empty_db_returns_zero_counts(flask_app, test_user):
    """Honest empty: no scan rows for the user → no nodes/edges/issues
    after ingestion. Pins the new contract (the legacy stub recomputed
    risk on existing rows regardless of scan inventory)."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    counts = _ingest_for_user(test_user.id)
    assert counts == {"nodes": 0, "edges": 0, "issues": 0, "high_risk": 0}
    assert _scope_node_ids(test_user.id) == set()


def test_ingest_creates_real_nodes_with_user_meta(flask_app, test_user):
    """A scan with two hosts produces two real NvNode rows, each
    carrying the calling user_id in node_meta JSON."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.50.0.5",  [(22, "ssh")]),
        _make_host("10.50.0.10", [(80, "http")]),
    ])
    try:
        counts = _ingest_for_user(test_user.id)
        # 2 host nodes; no Internet node (both private)
        assert counts["nodes"] == 2
        node_ids = _scope_node_ids(test_user.id)
        assert len(node_ids) == 2
        for n in NvNode.query.filter(NvNode.id.in_(node_ids)).all():
            assert _node_user_id(n) == test_user.id
            assert json.loads(n.node_meta).get("port_count") == 1
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_ingest_emits_lateral_edge_for_same_subnet_hosts(flask_app, test_user):
    """Two hosts in 10.50.0.0/24 → exactly one lateral NvEdge between them."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.50.0.5",  [(22, "ssh")]),
        _make_host("10.50.0.10", [(80, "http")]),
    ])
    try:
        _ingest_for_user(test_user.id)
        node_ids = _scope_node_ids(test_user.id)
        edges = NvEdge.query.filter(
            (NvEdge.source_id.in_(node_ids)) |
            (NvEdge.target_id.in_(node_ids))
        ).all()
        assert len(edges) == 1
        e = edges[0]
        assert e.protocol == "lateral"
        assert e.bidirectional is True
        assert e.encrypted is True
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_ingest_emits_internet_edge_for_internet_facing_host(flask_app, test_user):
    """Public IP → synthetic Internet node + Internet→host edge.
    The synthetic Internet node belongs to the same user (node_meta)."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("8.8.8.8", [(443, "https")]),
    ])
    try:
        counts = _ingest_for_user(test_user.id)
        # 1 host + 1 synthetic Internet
        assert counts["nodes"] == 2
        nodes = NvNode.query.filter(
            NvNode.id.in_(_scope_node_ids(test_user.id))
        ).all()
        zones = sorted(n.zone for n in nodes)
        assert "internet" in zones and "dmz" in zones
        # Exactly one Internet→host edge
        edges = NvEdge.query.filter(
            (NvEdge.source_id.in_({n.id for n in nodes})) |
            (NvEdge.target_id.in_({n.id for n in nodes}))
        ).all()
        assert len(edges) == 1
        e = edges[0]
        assert e.protocol == "tcp"
        assert e.cross_zone is True
        assert e.encrypted is False
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_ingest_creates_issue_for_high_risk_host(flask_app, test_user):
    """A host with risk_score >= 70 produces exactly one NvIssue,
    severity=High (no KEV in this case)."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.51.0.5", [(80, "http")], risk_score=85),
    ])
    try:
        counts = _ingest_for_user(test_user.id)
        assert counts["issues"] == 1
        node_ids = _scope_node_ids(test_user.id)
        issues = NvIssue.query.filter(NvIssue.node_id.in_(node_ids)).all()
        assert len(issues) == 1
        issue = issues[0]
        assert issue.severity == "High"
        assert "85" in issue.title
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_ingest_creates_critical_issue_for_kev_listed_cve(flask_app, test_user):
    """KEV-listed CVE on a host → severity=Critical issue, even if
    the host's risk_score is modest."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    cve_id = f"CVE-2099-{uuid.uuid4().hex[:5].upper()}"
    kev = _seed_kev(cve_id)
    scan = _seed_scan(test_user.id, [
        _make_host("10.52.0.5", [(8080, "http")],
                   cves=[cve_id], risk_score=20),
    ])
    try:
        counts = _ingest_for_user(test_user.id)
        assert counts["issues"] == 1
        node_ids = _scope_node_ids(test_user.id)
        issues = NvIssue.query.filter(NvIssue.node_id.in_(node_ids)).all()
        assert issues[0].severity == "Critical"
        assert cve_id in issues[0].title
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)
        db.session.delete(kev)
        db.session.commit()


def test_ingest_does_not_create_issue_for_low_risk_clean_host(flask_app, test_user):
    """A host with no CVEs, low risk, no KEV → no issue produced."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.53.0.5", [(22, "ssh")], risk_score=10),
    ])
    try:
        counts = _ingest_for_user(test_user.id)
        assert counts["issues"] == 0
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_user_scoping_isolates_other_users_nodes(flask_app, test_user):
    """User A's ingestion does NOT show up in user B's /graph view.
    Pins the node_meta-based scoping pattern (no schema change)."""
    other = _other_user("scope")
    _purge_user_nv(test_user.id)
    _purge_user_nv(other.id)
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    RealScanResult.query.filter_by(user_id=other.id).delete()
    db.session.commit()

    scan_a = _seed_scan(test_user.id, [
        _make_host("10.99.0.5", [(22, "ssh")]),
    ])
    scan_b = _seed_scan(other.id, [
        _make_host("10.99.0.5", [(22, "ssh")]),
    ])
    try:
        _ingest_for_user(test_user.id)
        _ingest_for_user(other.id)

        a_node_ids = _scope_node_ids(test_user.id)
        b_node_ids = _scope_node_ids(other.id)

        # Disjoint sets — no cross-tenant leakage.
        assert a_node_ids and b_node_ids
        assert a_node_ids.isdisjoint(b_node_ids)
        # Each user owns exactly 1 node (the IP-host; no internet node
        # because IPs are private).
        assert len(a_node_ids) == 1
        assert len(b_node_ids) == 1
    finally:
        _purge_user_nv(test_user.id)
        _purge_user_nv(other.id)
        _delete_scan(scan_a)
        _delete_scan(scan_b)
        db.session.delete(other)
        db.session.commit()


def test_scan_endpoint_returns_summary_counts(client, flask_app, test_user, auth_headers):
    """Smoke: the HTTP route wires through to _ingest_for_user and
    returns the spec'd response keys."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.60.0.5", [(22, "ssh")]),
        _make_host("10.60.0.10", [(80, "http")]),
    ])
    try:
        r = client.post("/api/netvisualizer/scan", headers=auth_headers)
        assert r.status_code == 200, r.data
        body = r.get_json()
        for k in ("success", "nodes_updated", "edges_mapped",
                  "issues_added", "high_risk"):
            assert k in body
        assert body["success"] is True
        assert body["nodes_updated"] == 2
        assert body["edges_mapped"]  == 1   # one same-subnet lateral edge
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)


def test_graph_endpoint_returns_only_user_owned_nodes(
    client, flask_app, test_user, auth_headers,
):
    """GET /graph returns the user's own nodes/edges only — even if
    another user has nodes in the same nv_* tables."""
    other = _other_user("graphscope")
    _purge_user_nv(test_user.id)
    _purge_user_nv(other.id)

    # Pre-seed an existing NvNode for `other` with an IP that overlaps
    # what test_user will ingest. If scoping leaked, /graph would
    # surface it.
    foreign = NvNode(
        name="10.61.0.5", node_type="server", zone="corporate",
        ip_address="10.61.0.5", risk_score=0, internet_facing=False,
        encrypted=True, issue_count=0, status="active",
    )
    _set_user_meta(foreign, other.id)
    db.session.add(foreign)
    db.session.commit()

    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    scan = _seed_scan(test_user.id, [
        _make_host("10.61.0.5", [(22, "ssh")]),
    ])
    try:
        _ingest_for_user(test_user.id)
        r = client.get("/api/netvisualizer/graph", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        # Exactly 1 node returned — the user's own — not the foreign
        # row that was seeded for `other`.
        assert len(body["nodes"]) == 1
        assert body["nodes"][0]["ip_address"] == "10.61.0.5"
    finally:
        _purge_user_nv(test_user.id)
        _purge_user_nv(other.id)
        _delete_scan(scan)
        db.session.delete(other)
        db.session.commit()


def test_stats_endpoint_returns_zero_shape_when_no_user_data(
    client, flask_app, test_user, auth_headers,
):
    """Stats must not crash on no-data; div-by-zero guarded shape."""
    _purge_user_nv(test_user.id)

    r = client.get("/api/netvisualizer/stats", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    for k in ("total_nodes", "total_edges", "total_issues",
              "internet_facing", "high_risk_nodes", "by_zone",
              "by_provider"):
        assert k in body
    assert body["total_nodes"]  == 0
    assert body["total_edges"]  == 0
    assert body["total_issues"] == 0
    assert body["by_zone"]      == {}


def test_update_issue_blocks_other_users_issue(
    client, flask_app, test_user, auth_headers,
):
    """User A can't flip user B's issue.status via PUT — node_id-based
    transitive scoping enforces ownership."""
    other = _other_user("issuescope")
    _purge_user_nv(test_user.id)
    _purge_user_nv(other.id)

    foreign_node = NvNode(
        name="10.62.0.5", node_type="server", zone="corporate",
        ip_address="10.62.0.5", risk_score=80, internet_facing=False,
        encrypted=True, issue_count=1, status="active",
    )
    _set_user_meta(foreign_node, other.id)
    db.session.add(foreign_node)
    db.session.flush()
    foreign_issue = NvIssue(
        node_id=foreign_node.id, severity="High",
        title="Foreign issue", description="x", remediation="y",
        status="open",
    )
    db.session.add(foreign_issue)
    db.session.commit()
    iid = foreign_issue.id
    try:
        r = client.put(
            f"/api/netvisualizer/issues/{iid}",
            headers=auth_headers,
            data=json.dumps({"status": "resolved"}),
        )
        assert r.status_code == 404, r.data
        # Confirm status unchanged at the DB level.
        db.session.refresh(foreign_issue)
        assert foreign_issue.status == "open"
    finally:
        _purge_user_nv(other.id)
        db.session.delete(other)
        db.session.commit()


def test_ingest_is_idempotent_full_refresh(flask_app, test_user):
    """Running _ingest_for_user twice on the same scan produces the
    same node/edge counts — no duplication. Verifies the v1
    'scan = full refresh' semantic in the docstring."""
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()
    _purge_user_nv(test_user.id)

    scan = _seed_scan(test_user.id, [
        _make_host("10.63.0.5", [(22, "ssh")]),
        _make_host("10.63.0.10", [(80, "http")]),
    ])
    try:
        first  = _ingest_for_user(test_user.id)
        second = _ingest_for_user(test_user.id)
        assert first  == second
        assert len(_scope_node_ids(test_user.id)) == 2
    finally:
        _purge_user_nv(test_user.id)
        _delete_scan(scan)
