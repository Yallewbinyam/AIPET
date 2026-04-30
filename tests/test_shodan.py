"""
AIPET X — Capability 16 (Shodan API integration) test suite.

Pins the v1 contract introduced 2026-04-30:
  - SHODAN_API_KEY unset → graceful 503 with configured=False
  - cache hit (looked_up_at < 24h ago) → no live Shodan call
  - cache miss → exactly one shodan.Shodan(key).host(ip) call
  - negative result (Shodan returns no info) → cached with
    node_meta.found = False so quota isn't burned on retries
  - DELETE /cache/<ip> is idempotent (200 whether row existed or not)
  - all routes require JWT
  - response normalisation: ip_str → ip, country_name → country
  - local_scan: latest matching real_scan_results host returned
    when the calling user has scanned the IP

The test suite mocks shodan.Shodan with unittest.mock so the live
PyPI lib is never invoked. SHODAN_API_KEY is monkey-patched per
test that needs it set; the default conftest.py env leaves it
empty, so the no-key paths exercise that default cleanly.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from dashboard.backend.models import db, User
from dashboard.backend.shodan.models import ShodanLookup
from dashboard.backend.shodan.routes import (
    _is_valid_ip, _normalise_host, _cache_hit, _meta_dict,
    SHODAN_API_KEY_ENV,
)
from dashboard.backend.real_scanner.routes import RealScanResult


# ── Helpers ──────────────────────────────────────────────────

def _key_set():
    """Context manager-y patch that sets SHODAN_API_KEY for the
    duration of the with block."""
    return patch.dict(os.environ, {SHODAN_API_KEY_ENV: "test-key-not-real"})


def _purge_shodan_table():
    ShodanLookup.query.delete()
    db.session.commit()


def _seed_cache(ip, raw, hours_old=0, found=True):
    """Insert a ShodanLookup row with controllable freshness."""
    row = ShodanLookup(
        ip = ip,
        raw_json = json.dumps(raw),
        looked_up_at = datetime.utcnow() - timedelta(hours=hours_old),
        node_meta = json.dumps({"found": found, "lookup_count": 1}),
    )
    db.session.add(row)
    db.session.commit()
    return row


# Realistic Shodan host response shape (subset). The actual API
# returns ~100 keys; we mock only what the tests need.
_FAKE_HOST = {
    "ip_str":       "8.8.8.8",
    "hostnames":    ["dns.google"],
    "country_name": "United States",
    "city":         "Mountain View",
    "org":          "Google LLC",
    "isp":          "Google LLC",
    "asn":          "AS15169",
    "ports":        [53, 443],
    "tags":         ["dns"],
    "vulns":        [],
    "last_update":  "2026-04-29T12:00:00",
    "os":           None,
}


# ─────────────────────────────────────────────────────────────
# Pure-helper tests (no DB / no JWT)
# ─────────────────────────────────────────────────────────────

def test_is_valid_ip_accepts_ipv4_and_ipv6():
    assert _is_valid_ip("8.8.8.8")        is True
    assert _is_valid_ip("10.0.0.1")       is True
    assert _is_valid_ip("2001:db8::1")    is True


def test_is_valid_ip_rejects_garbage():
    assert _is_valid_ip("")               is False
    assert _is_valid_ip(None)             is False
    assert _is_valid_ip("not-an-ip")      is False
    assert _is_valid_ip("8.8.8")          is False
    # CIDR is NOT a single address — rejected.
    assert _is_valid_ip("8.8.8.0/24")     is False


def test_normalise_host_renames_keys():
    out = _normalise_host(_FAKE_HOST)
    # ip_str -> ip
    assert out["ip"] == "8.8.8.8"
    assert "ip_str" not in out
    # country_name -> country
    assert out["country"] == "United States"
    assert "country_name" not in out
    # passthrough fields
    assert out["org"] == "Google LLC"
    assert out["ports"] == [53, 443]


def test_normalise_host_handles_garbage_input():
    """Defensive: a non-dict input returns {}, never raises."""
    assert _normalise_host(None) == {}
    assert _normalise_host("string") == {}
    assert _normalise_host(123) == {}


def test_cache_hit_only_when_fresher_than_24h(flask_app, test_user):
    """Boundary check on the TTL: 23h59m = hit, 24h01m = miss."""
    _purge_shodan_table()
    fresh   = _seed_cache("1.1.1.1", _FAKE_HOST, hours_old=0)
    fresh23 = _seed_cache("1.1.1.2", _FAKE_HOST, hours_old=23)
    stale   = _seed_cache("1.1.1.3", _FAKE_HOST, hours_old=25)
    try:
        assert _cache_hit(fresh)   is True
        assert _cache_hit(fresh23) is True
        assert _cache_hit(stale)   is False
        assert _cache_hit(None)    is False
    finally:
        _purge_shodan_table()


# ─────────────────────────────────────────────────────────────
# Endpoint smoke + skip-if-no-key
# ─────────────────────────────────────────────────────────────

def test_status_endpoint_returns_configured_false_when_no_key(
    client, flask_app, auth_headers,
):
    """conftest.py leaves SHODAN_API_KEY unset by default. /status
    must return 200 (NOT 503) so the frontend can render a
    "configure Shodan" prompt instead of a generic error."""
    # Belt-and-suspenders: ensure env var is empty for this test.
    with patch.dict(os.environ, {SHODAN_API_KEY_ENV: ""}):
        r = client.get("/api/shodan/status", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["configured"] is False
        assert "SHODAN_API_KEY" in body["message"]
        # Cache count + TTL hours always reported, even when unconfigured.
        assert "cache_count" in body
        assert body["cache_ttl_hours"] == 24


def test_lookup_returns_503_when_no_key(
    client, flask_app, auth_headers,
):
    with patch.dict(os.environ, {SHODAN_API_KEY_ENV: ""}):
        r = client.get("/api/shodan/lookup/8.8.8.8", headers=auth_headers)
        assert r.status_code == 503
        body = r.get_json()
        assert body["configured"] is False
        assert "SHODAN_API_KEY" in body["message"]


def test_lookup_returns_400_for_invalid_ip(
    client, flask_app, auth_headers,
):
    """IP validation runs BEFORE the configured-check so a
    syntactically wrong input is always 400, not 503."""
    r = client.get("/api/shodan/lookup/not-an-ip", headers=auth_headers)
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "invalid_ip"


def test_lookup_requires_jwt(client, flask_app):
    r = client.get("/api/shodan/lookup/8.8.8.8")
    assert r.status_code == 401


# ─────────────────────────────────────────────────────────────
# Cache hit / miss flow (mocked Shodan client)
# ─────────────────────────────────────────────────────────────

def test_lookup_cache_hit_does_not_call_shodan(
    client, flask_app, test_user, auth_headers,
):
    """A fresh cache row must be served without invoking the live
    Shodan client. Pins the quota-protection guarantee."""
    _purge_shodan_table()
    _seed_cache("1.2.3.4", _FAKE_HOST, hours_old=1, found=True)

    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient"
    ) as mock_client_cls:
        r = client.get("/api/shodan/lookup/1.2.3.4", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["source"] == "cache"
        assert body["found"]  is True
        assert body["shodan"]["org"] == "Google LLC"
        # Critical: client class must NOT have been instantiated.
        mock_client_cls.assert_not_called()
    _purge_shodan_table()


def test_lookup_cache_miss_calls_shodan_and_caches_result(
    client, flask_app, test_user, auth_headers,
):
    """Empty cache → exactly one shodan.host() call. Result then
    persists in the cache for the next request."""
    _purge_shodan_table()

    fake_client = MagicMock()
    fake_client.host.return_value = _FAKE_HOST

    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient",
        return_value=fake_client,
    ) as mock_cls:
        r = client.get("/api/shodan/lookup/9.9.9.9", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["source"] == "shodan"
        assert body["found"]  is True
        assert body["shodan"]["country"] == "United States"

        # Lib was instantiated exactly once, host() called exactly once
        # with our IP.
        mock_cls.assert_called_once()
        fake_client.host.assert_called_once_with("9.9.9.9")

    # Row now in DB.
    row = ShodanLookup.query.get("9.9.9.9")
    assert row is not None
    assert _meta_dict(row).get("found") is True
    assert _meta_dict(row).get("first_looked_up_by") == test_user.id
    _purge_shodan_table()


def test_lookup_caches_negative_result_to_protect_quota(
    client, flask_app, test_user, auth_headers,
):
    """Shodan APIError 'No information available' for an unindexed
    IP must be cached with found=False, so a retry within 24h is a
    cache hit (no quota burn)."""
    _purge_shodan_table()
    from shodan import APIError as RealAPIError

    fake_client = MagicMock()
    fake_client.host.side_effect = RealAPIError("No information available")

    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient",
        return_value=fake_client,
    ):
        r = client.get(
            "/api/shodan/lookup/192.0.2.99", headers=auth_headers,
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["found"]  is False
        assert body["source"] == "shodan"

    row = ShodanLookup.query.get("192.0.2.99")
    assert row is not None
    assert _meta_dict(row).get("found") is False

    # Second call within TTL: cache hit, NO Shodan call.
    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient"
    ) as mock_cls:
        r2 = client.get(
            "/api/shodan/lookup/192.0.2.99", headers=auth_headers,
        )
        assert r2.status_code == 200
        assert r2.get_json()["source"] == "cache"
        assert r2.get_json()["found"]  is False
        mock_cls.assert_not_called()
    _purge_shodan_table()


def test_lookup_stale_cache_triggers_refresh(
    client, flask_app, test_user, auth_headers,
):
    """A row older than 24h is treated as a miss — the row is
    refreshed in place."""
    _purge_shodan_table()
    _seed_cache("5.5.5.5", {"ip_str": "5.5.5.5", "ports": [80]},
                hours_old=30, found=True)

    fake_client = MagicMock()
    fake_client.host.return_value = _FAKE_HOST  # different ports

    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient",
        return_value=fake_client,
    ):
        r = client.get("/api/shodan/lookup/5.5.5.5", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        # Source is "shodan" because the stale cache forced a refresh.
        assert body["source"] == "shodan"
        # Refreshed payload reflects the fake response (53, 443).
        assert body["shodan"]["ports"] == [53, 443]

    # Row updated in place, looked_up_at moved forward.
    row = ShodanLookup.query.get("5.5.5.5")
    assert row is not None
    age = datetime.utcnow() - row.looked_up_at
    assert age < timedelta(hours=1)
    _purge_shodan_table()


def test_lookup_merges_local_scan_data(
    client, flask_app, test_user, auth_headers,
):
    """When the calling user has a real_scan_results row that
    matches the IP, the response carries `local_scan` populated
    from that scan. This is the additive-enrichment promise."""
    _purge_shodan_table()
    RealScanResult.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    target_ip = f"203.0.113.{(uuid.uuid4().int % 200) + 50}"
    scan = RealScanResult(
        user_id      = test_user.id,
        target       = target_ip,
        status       = "complete",
        finished_at  = datetime.utcnow(),
        hosts_found  = 1,
        cve_count    = 0,
        results_json = json.dumps([{
            "ip":         target_ip,
            "open_ports": [{"port": 22, "service": "ssh"}],
            "port_count": 1,
            "cves":       [],
            "cve_count":  0,
            "risk_score": 35,
        }]),
    )
    db.session.add(scan)
    db.session.commit()

    fake_client = MagicMock()
    fake_client.host.return_value = {**_FAKE_HOST, "ip_str": target_ip}

    try:
        with _key_set(), patch(
            "dashboard.backend.shodan.routes._ShodanClient",
            return_value=fake_client,
        ):
            r = client.get(
                f"/api/shodan/lookup/{target_ip}", headers=auth_headers,
            )
            assert r.status_code == 200
            body = r.get_json()
            assert body["local_scan"] is not None
            assert body["local_scan"]["ip"] == target_ip
            assert body["local_scan"]["risk_score"] == 35
            assert body["shodan"]["ip"] == target_ip
    finally:
        _purge_shodan_table()
        db.session.delete(scan)
        db.session.commit()


# ─────────────────────────────────────────────────────────────
# Cache management endpoints
# ─────────────────────────────────────────────────────────────

def test_cache_list_returns_all_entries(
    client, flask_app, test_user, auth_headers,
):
    _purge_shodan_table()
    _seed_cache("8.8.8.8", _FAKE_HOST, hours_old=1)
    _seed_cache("1.1.1.1", _FAKE_HOST, hours_old=2)
    try:
        r = client.get("/api/shodan/cache", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["count"] == 2
        ips = [e["ip"] for e in body["entries"]]
        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips
    finally:
        _purge_shodan_table()


def test_delete_cache_entry_removes_row(
    client, flask_app, test_user, auth_headers,
):
    _purge_shodan_table()
    _seed_cache("9.9.9.9", _FAKE_HOST, hours_old=0)

    r = client.delete("/api/shodan/cache/9.9.9.9", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] is True
    assert body["deleted"] is True
    assert ShodanLookup.query.get("9.9.9.9") is None


def test_delete_cache_entry_idempotent_when_missing(
    client, flask_app, test_user, auth_headers,
):
    """Deleting a non-existent IP returns 200 with deleted=False —
    the post-condition the user wanted is satisfied either way."""
    _purge_shodan_table()
    r = client.delete("/api/shodan/cache/123.123.123.123",
                      headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] is True
    assert body["deleted"] is False


def test_delete_cache_rejects_invalid_ip(
    client, flask_app, test_user, auth_headers,
):
    r = client.delete("/api/shodan/cache/not-an-ip", headers=auth_headers)
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid_ip"


# ─────────────────────────────────────────────────────────────
# /status with key set + mocked info()
# ─────────────────────────────────────────────────────────────

def test_status_with_key_includes_quota_from_info(
    client, flask_app, test_user, auth_headers,
):
    fake_client = MagicMock()
    fake_client.info.return_value = {
        "query_credits":  100, "scan_credits": 0,
        "monitored_ips":  0, "plan": "free",
    }
    with _key_set(), patch(
        "dashboard.backend.shodan.routes._ShodanClient",
        return_value=fake_client,
    ):
        r = client.get("/api/shodan/status", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["configured"] is True
        assert body["quota"]["plan"] == "free"
        assert body["quota"]["query_credits"] == 100
