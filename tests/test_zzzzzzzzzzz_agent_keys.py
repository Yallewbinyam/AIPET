# =============================================================
# AIPET X — Capability 13 Day 1: Agent API Keys + Scan Ingest Tests
# =============================================================

import json
import pytest

from dashboard.backend.agent_keys.auth import generate_api_key, verify_key


# ═══════════════════════════════════════════════════════════
# KEY GENERATION TESTS
# ═══════════════════════════════════════════════════════════

class TestGenerateApiKey:
    def test_returns_tuple_of_three(self):
        result = generate_api_key()
        assert isinstance(result, tuple) and len(result) == 3

    def test_full_key_starts_with_aipet_prefix(self):
        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("aipet_")

    def test_prefix_starts_with_aipet_and_is_14_chars(self):
        full_key, prefix, key_hash = generate_api_key()
        assert prefix.startswith("aipet_")
        assert len(prefix) == 14  # "aipet_" (6) + 8 random chars

    def test_full_key_at_least_64_chars(self):
        full_key, _, __ = generate_api_key()
        assert len(full_key) >= 64

    def test_prefix_is_prefix_of_full_key(self):
        full_key, prefix, __ = generate_api_key()
        assert full_key.startswith(prefix)

    def test_hash_is_non_empty_string(self):
        _, __, key_hash = generate_api_key()
        assert isinstance(key_hash, str) and len(key_hash) > 10

    def test_two_calls_produce_different_keys(self):
        k1, p1, h1 = generate_api_key()
        k2, p2, h2 = generate_api_key()
        assert k1 != k2
        assert h1 != h2


# ═══════════════════════════════════════════════════════════
# VERIFICATION TESTS
# ═══════════════════════════════════════════════════════════

class TestVerifyKey:
    def test_valid_key_returns_row(self, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="verify-test", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=["scan:write"],
        )
        db.session.add(row)
        db.session.commit()

        with flask_app.test_request_context("/"):
            result = verify_key(full_key)
        assert result is not None
        assert result.id == row.id

    def test_invalid_key_returns_none(self, flask_app):
        with flask_app.test_request_context("/"):
            result = verify_key("aipet_completely_wrong_key_xxxxxxxxxxxxxx")
        assert result is None

    def test_wrong_prefix_returns_none(self, flask_app):
        with flask_app.test_request_context("/"):
            result = verify_key("notaipet_somevalue")
        assert result is None

    def test_revoked_key_returns_none(self, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="revoke-verify", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=[], enabled=False,
        )
        db.session.add(row)
        db.session.commit()

        with flask_app.test_request_context("/"):
            result = verify_key(full_key)
        assert result is None

    def test_updates_last_used_at(self, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="last-used-test", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=[],
        )
        db.session.add(row)
        db.session.commit()
        assert row.last_used_at is None

        with flask_app.test_request_context("/"):
            verify_key(full_key)

        db.session.refresh(row)
        assert row.last_used_at is not None

    def test_increments_use_count(self, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="use-count-test", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=[], use_count=0,
        )
        db.session.add(row)
        db.session.commit()

        with flask_app.test_request_context("/"):
            verify_key(full_key)

        db.session.refresh(row)
        assert row.use_count == 1


# ═══════════════════════════════════════════════════════════
# ENDPOINT TESTS — Key Management
# ═══════════════════════════════════════════════════════════

class TestCreateAgentKey:
    def test_create_returns_201_with_full_key(self, client, auth_headers):
        r = client.post("/api/agent/keys",
                        json={"label": "My server agent"},
                        headers=auth_headers)
        assert r.status_code == 201
        data = r.get_json()
        assert "full_key" in data
        assert data["full_key"].startswith("aipet_")
        assert data["label"] == "My server agent"

    def test_full_key_only_once_not_in_list(self, client, auth_headers):
        # Create a key
        r_create = client.post("/api/agent/keys",
                               json={"label": "Once-key"},
                               headers=auth_headers)
        assert r_create.status_code == 201
        full_key = r_create.get_json()["full_key"]

        # List keys — full_key must NOT appear
        r_list = client.get("/api/agent/keys", headers=auth_headers)
        assert r_list.status_code == 200
        body_str = r_list.get_data(as_text=True)
        assert full_key not in body_str

    def test_create_key_no_label_returns_422(self, client, auth_headers):
        r = client.post("/api/agent/keys", json={}, headers=auth_headers)
        assert r.status_code == 422

    def test_hash_not_in_create_response(self, client, auth_headers):
        r = client.post("/api/agent/keys",
                        json={"label": "hash-check"},
                        headers=auth_headers)
        assert r.status_code == 201
        data = r.get_json()
        assert "key_hash" not in data

    def test_create_with_custom_permissions(self, client, auth_headers):
        r = client.post("/api/agent/keys",
                        json={"label": "telemetry only", "permissions": ["telemetry:write"]},
                        headers=auth_headers)
        assert r.status_code == 201
        assert r.get_json()["permissions"] == ["telemetry:write"]


class TestListAgentKeys:
    def test_list_returns_200(self, client, auth_headers):
        r = client.get("/api/agent/keys", headers=auth_headers)
        assert r.status_code == 200

    def test_list_does_not_include_key_hash(self, client, auth_headers):
        r = client.get("/api/agent/keys", headers=auth_headers)
        body_str = r.get_data(as_text=True)
        assert "key_hash" not in body_str

    def test_list_does_not_include_full_key(self, client, auth_headers, test_user):
        # Create a key directly in DB (avoiding HTTP rate limit)
        full_key, row = _make_agent_key(test_user, permissions=["scan:write"])
        r_list = client.get("/api/agent/keys", headers=auth_headers)
        body_str = r_list.get_data(as_text=True)
        assert full_key not in body_str

    def test_list_includes_prefix(self, client, auth_headers, test_user):
        # Create a key directly in DB (avoiding HTTP rate limit)
        full_key, row = _make_agent_key(test_user)
        r_list = client.get("/api/agent/keys", headers=auth_headers)
        keys = r_list.get_json()["keys"]
        prefixes = [k["key_prefix"] for k in keys]
        assert row.key_prefix in prefixes


class TestRevokeAgentKey:
    def test_revoke_marks_key_disabled(self, client, auth_headers, test_user):
        # Create key directly in DB (avoiding HTTP rate limit)
        _, row = _make_agent_key(test_user)
        key_id = row.id

        r_revoke = client.put(f"/api/agent/keys/{key_id}/revoke",
                              json={"reason": "test revoke"},
                              headers=auth_headers)
        assert r_revoke.status_code == 200

        # Key should appear in list as disabled
        r_list = client.get("/api/agent/keys", headers=auth_headers)
        keys = r_list.get_json()["keys"]
        target = next((k for k in keys if k["id"] == key_id), None)
        assert target is not None
        assert target["enabled"] is False
        assert target["revoked_reason"] == "test revoke"

    def test_revoke_404_when_not_owned(self, client, auth_headers, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db, User

        # Create a second user
        other_user = User(email="other-revoke@aipet.io", password_hash="x",
                          name="Other", plan="enterprise")
        db.session.add(other_user)
        db.session.commit()

        _, prefix, key_hash = generate_api_key()
        other_key = AgentApiKey(user_id=other_user.id, label="other-key",
                                key_prefix=prefix, key_hash=key_hash,
                                scope="agent", permissions=[])
        db.session.add(other_key)
        db.session.commit()

        r = client.put(f"/api/agent/keys/{other_key.id}/revoke",
                       json={}, headers=auth_headers)
        assert r.status_code == 404  # not found (owned by other user)


# ═══════════════════════════════════════════════════════════
# AUTH DECORATOR TESTS
# ═══════════════════════════════════════════════════════════

class TestAgentKeyDecorator:
    def test_missing_header_returns_401(self, client):
        r = client.post("/api/agent/scan-results",
                        json={"scan_id": "x", "format": "json",
                              "scan_data": {"hosts": []}})
        assert r.status_code == 401

    def test_invalid_key_returns_401(self, client):
        r = client.post("/api/agent/scan-results",
                        json={"scan_id": "x", "format": "json",
                              "scan_data": {"hosts": []}},
                        headers={"X-Agent-Key": "aipet_invalid_key_xxxxxxxxxxxxxxxx"})
        assert r.status_code == 401

    def test_revoked_key_returns_401(self, client, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="revoked-dec", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=["scan:write"], enabled=False,
        )
        db.session.add(row)
        db.session.commit()

        r = client.post("/api/agent/scan-results",
                        json={"scan_id": "x", "format": "json",
                              "scan_data": {"hosts": []}},
                        headers={"X-Agent-Key": full_key})
        assert r.status_code == 401

    def test_wrong_permission_returns_403(self, client, flask_app, test_user):
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="no-perm-key", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=["telemetry:write"],
        )
        db.session.add(row)
        db.session.commit()

        r = client.post("/api/agent/scan-results",
                        json={"scan_id": "perm-test-01", "format": "json",
                              "scan_data": {"hosts": []}},
                        headers={"X-Agent-Key": full_key})
        assert r.status_code == 403

    def test_valid_key_populates_g_user_id(self, flask_app, test_user):
        from flask import g
        from dashboard.backend.agent_keys.auth import agent_key_required
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=test_user.id, label="g-test-key", key_prefix=prefix,
            key_hash=key_hash, scope="agent", permissions=["scan:write"],
        )
        db.session.add(row)
        db.session.commit()

        captured = {}

        @agent_key_required(permissions=["scan:write"])
        def fake_view():
            captured["user_id"] = g.current_user_id
            captured["key_id"] = g.current_agent_key.id
            return "ok"

        with flask_app.test_request_context(
            "/", headers={"X-Agent-Key": full_key}
        ):
            fake_view()

        assert captured["user_id"] == test_user.id
        assert captured["key_id"] == row.id


# ═══════════════════════════════════════════════════════════
# SCAN INGEST ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════

def _make_agent_key(test_user, permissions=None):
    """Helper: create an enabled AgentApiKey, return (full_key, row)."""
    from dashboard.backend.agent_keys.models import AgentApiKey
    from dashboard.backend.models import db

    full_key, prefix, key_hash = generate_api_key()
    perms = permissions if permissions is not None else ["scan:write", "telemetry:write"]
    row = AgentApiKey(
        user_id=test_user.id, label="ingest-helper-key", key_prefix=prefix,
        key_hash=key_hash, scope="agent", permissions=perms,
    )
    db.session.add(row)
    db.session.commit()
    return full_key, row


MINIMAL_JSON_SCAN = {
    "hosts": [
        {"ip": "10.0.99.1", "ports": [{"port": 22, "service": "ssh", "proto": "tcp"}]}
    ]
}

MINIMAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.99.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestScanIngest:
    def test_accepts_valid_json_scan(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={
                "scan_id": "json-test-001",
                "format": "json",
                "scan_data": MINIMAL_JSON_SCAN,
                "scan_metadata": {"target": "10.0.99.0/24", "scan_type": "discovery",
                                  "started_at": "2026-04-27T12:00:00Z",
                                  "completed_at": "2026-04-27T12:01:00Z",
                                  "host_count": 1, "service_count": 1},
            },
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "real_scan_id" in data
        assert data["host_count"] == 1

    def test_accepts_valid_nmap_xml(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={
                "scan_id": "xml-test-001",
                "format": "nmap_xml",
                "scan_data": MINIMAL_NMAP_XML,
                "scan_metadata": {"target": "10.0.99.2", "scan_type": "full",
                                  "started_at": "2026-04-27T12:00:00Z",
                                  "completed_at": "2026-04-27T12:02:00Z",
                                  "host_count": 1, "service_count": 1},
            },
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["host_count"] == 1

    def test_writes_to_real_scan_results_table(self, client, flask_app, test_user):
        from dashboard.backend.real_scanner.routes import RealScanResult

        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={
                "scan_id": "db-check-001",
                "format": "json",
                "scan_data": MINIMAL_JSON_SCAN,
                "scan_metadata": {"target": "10.0.99.3"},
            },
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 200
        real_scan_id = r.get_json()["real_scan_id"]

        with flask_app.app_context():
            from dashboard.backend.models import db as _db2
            row = _db2.session.get(RealScanResult, real_scan_id)
            assert row is not None
            assert row.status == "complete"
            assert row.user_id == test_user.id

    def test_idempotent_on_duplicate_scan_id(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        payload = {
            "scan_id": "idem-test-001",
            "format": "json",
            "scan_data": MINIMAL_JSON_SCAN,
            "scan_metadata": {"target": "10.0.99.4"},
        }
        r1 = client.post("/api/agent/scan-results", json=payload,
                         headers={"X-Agent-Key": full_key})
        r2 = client.post("/api/agent/scan-results", json=payload,
                         headers={"X-Agent-Key": full_key})

        assert r1.status_code == 200
        assert r2.status_code == 200
        # Same real_scan_id returned on second call
        assert r1.get_json()["real_scan_id"] == r2.get_json()["real_scan_id"]
        assert r2.get_json()["duplicate"] is True

    def test_rejects_malformed_xml_with_400(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={
                "scan_id": "bad-xml-001",
                "format": "nmap_xml",
                "scan_data": "<broken>xml<not_closed>",
            },
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 400

    def test_rejects_missing_scan_id_with_422(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={"format": "json", "scan_data": MINIMAL_JSON_SCAN},
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 422

    def test_rejects_invalid_format_with_422(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={"scan_id": "fmt-fail", "format": "csv", "scan_data": {}},
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 422

    def test_403_without_scan_write_permission(self, client, test_user):
        full_key, _ = _make_agent_key(test_user, permissions=["telemetry:write"])
        r = client.post(
            "/api/agent/scan-results",
            json={"scan_id": "noperm-001", "format": "json",
                  "scan_data": MINIMAL_JSON_SCAN},
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 403

    def test_cross_tenant_scan_id_collision_returns_403(self, client, flask_app, test_user):
        from dashboard.backend.models import db, User

        # Create a second user with their own key
        user2 = User(email="tenant2-scan@aipet.io", password_hash="x",
                     name="Tenant2", plan="enterprise")
        db.session.add(user2)
        db.session.commit()

        from dashboard.backend.agent_keys.models import AgentApiKey
        fk1, pr1, kh1 = generate_api_key()
        fk2, pr2, kh2 = generate_api_key()
        row1 = AgentApiKey(user_id=test_user.id, label="t1key", key_prefix=pr1,
                           key_hash=kh1, scope="agent", permissions=["scan:write"])
        row2 = AgentApiKey(user_id=user2.id, label="t2key", key_prefix=pr2,
                           key_hash=kh2, scope="agent", permissions=["scan:write"])
        db.session.add_all([row1, row2])
        db.session.commit()

        shared_id = "cross-tenant-conflict-001"

        # User 1 submits first
        r1 = client.post("/api/agent/scan-results",
                         json={"scan_id": shared_id, "format": "json",
                               "scan_data": MINIMAL_JSON_SCAN,
                               "scan_metadata": {"target": "10.0.1.1"}},
                         headers={"X-Agent-Key": fk1})
        assert r1.status_code == 200

        # User 2 tries same scan_id → 403
        r2 = client.post("/api/agent/scan-results",
                         json={"scan_id": shared_id, "format": "json",
                               "scan_data": MINIMAL_JSON_SCAN,
                               "scan_metadata": {"target": "10.0.1.1"}},
                         headers={"X-Agent-Key": fk2})
        assert r2.status_code == 403

    def test_empty_host_list_accepted(self, client, test_user):
        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={"scan_id": "empty-hosts-001", "format": "json",
                  "scan_data": {"hosts": []},
                  "scan_metadata": {"target": "10.0.0.0/24"}},
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 200
        assert r.get_json()["host_count"] == 0

    def test_emits_central_event(self, client, flask_app, test_user):
        from dashboard.backend.central_events.models import CentralEvent

        full_key, _ = _make_agent_key(test_user)
        r = client.post(
            "/api/agent/scan-results",
            json={"scan_id": "event-test-001", "format": "json",
                  "scan_data": MINIMAL_JSON_SCAN,
                  "scan_metadata": {"target": "10.0.99.50"}},
            headers={"X-Agent-Key": full_key},
        )
        assert r.status_code == 200

        event = CentralEvent.query.filter_by(
            source_module="agent_scan_ingest",
            event_type="scan_completed",
        ).order_by(CentralEvent.created_at.desc()).first()
        assert event is not None
        assert event.user_id == test_user.id


# ═══════════════════════════════════════════════════════════
# INTEGRATION: full create → scan → revoke flow
# ═══════════════════════════════════════════════════════════

class TestEndToEndFlow:
    def test_create_use_revoke(self, client, auth_headers, test_user):
        # Create key directly in DB (HTTP create is tested in TestCreateAgentKey;
        # using DB helper here keeps total HTTP creates under the 5/min rate limit).
        full_key, row = _make_agent_key(test_user,
                                         permissions=["scan:write", "telemetry:write"])
        key_id = row.id
        assert full_key.startswith("aipet_")

        # 1. Key appears in list as enabled
        r_list = client.get("/api/agent/keys", headers=auth_headers)
        keys = r_list.get_json()["keys"]
        key_in_list = next((k for k in keys if k["id"] == key_id), None)
        assert key_in_list is not None
        assert key_in_list["enabled"] is True

        # 2. Use key to upload scan
        r_scan = client.post(
            "/api/agent/scan-results",
            json={
                "scan_id": "e2e-scan-001",
                "format": "json",
                "scan_data": MINIMAL_JSON_SCAN,
                "scan_metadata": {"target": "10.0.e2e.1"},
            },
            headers={"X-Agent-Key": full_key},
        )
        assert r_scan.status_code == 200
        assert "real_scan_id" in r_scan.get_json()

        # 3. Revoke key via HTTP endpoint
        r_revoke = client.put(f"/api/agent/keys/{key_id}/revoke",
                              json={"reason": "e2e test complete"},
                              headers=auth_headers)
        assert r_revoke.status_code == 200

        # 4. Revoked key is rejected on next use
        r_scan2 = client.post(
            "/api/agent/scan-results",
            json={"scan_id": "e2e-scan-002", "format": "json",
                  "scan_data": MINIMAL_JSON_SCAN},
            headers={"X-Agent-Key": full_key},
        )
        assert r_scan2.status_code == 401
