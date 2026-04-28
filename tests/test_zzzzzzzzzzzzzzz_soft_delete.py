# =============================================================
# AIPET X — Soft-delete feature tests
# Covers: model layer (Phase 2) + endpoints (Phase 3) end-to-end.
# =============================================================

import datetime
import json
import pytest

from dashboard.backend.models import db
from dashboard.backend.agent_monitor.routes import AgentDevice, AgentTelemetry
from dashboard.backend.iam.models import AuditLog


# ---------------------------------------------------------------- helpers

def _mk_device(test_user, agent_id="agent-soft-test-001",
               hostname="testhost", platform="Linux test",
               deleted_at=None):
    """Insert a device in the test DB. Returns the row."""
    dev = AgentDevice(
        id=agent_id,
        user_id=test_user.id,
        hostname=hostname,
        platform=platform,
        first_seen=datetime.datetime.utcnow(),
        last_seen=datetime.datetime.utcnow(),
        status="online",
        deleted_at=deleted_at,
    )
    db.session.add(dev)
    db.session.commit()
    return dev


def _audit_count(action_prefix="device."):
    """Number of audit_log rows whose action starts with action_prefix."""
    return AuditLog.query.filter(
        AuditLog.action.like(action_prefix + "%")
    ).count()


@pytest.fixture(autouse=True)
def _cleanup_devices(flask_app):
    """Each test starts and ends with NO test-prefixed devices in the DB.
    Prevents cross-test pollution since the suite uses a session-scoped
    in-memory SQLite per conftest."""
    with flask_app.app_context():
        AgentDevice.query.filter(AgentDevice.id.like("agent-soft-test-%")).delete()
        AgentTelemetry.query.filter(AgentTelemetry.agent_id.like("agent-soft-test-%")).delete()
        AuditLog.query.filter(AuditLog.action.like("device.%")).delete()
        db.session.commit()
    yield
    with flask_app.app_context():
        AgentDevice.query.filter(AgentDevice.id.like("agent-soft-test-%")).delete()
        AgentTelemetry.query.filter(AgentTelemetry.agent_id.like("agent-soft-test-%")).delete()
        AuditLog.query.filter(AuditLog.action.like("device.%")).delete()
        db.session.commit()


# ═══════════════════════════════════════════════════════════════
# Model layer (Phase 2)
# ═══════════════════════════════════════════════════════════════

class TestQueryHelpers:
    def test_active_excludes_soft_deleted(self, flask_app, test_user):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-active")
            _mk_device(test_user, "agent-soft-test-deleted",
                       deleted_at=datetime.datetime.utcnow())
            ids = [d.id for d in AgentDevice.active()
                   .filter_by(user_id=test_user.id).all()]
            assert "agent-soft-test-active" in ids
            assert "agent-soft-test-deleted" not in ids

    def test_with_deleted_includes_soft_deleted(self, flask_app, test_user):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-active")
            _mk_device(test_user, "agent-soft-test-deleted",
                       deleted_at=datetime.datetime.utcnow())
            ids = [d.id for d in AgentDevice.with_deleted()
                   .filter_by(user_id=test_user.id).all()]
            assert "agent-soft-test-active" in ids
            assert "agent-soft-test-deleted" in ids


class TestSoftDeleteLifecycle:
    def test_soft_delete_sets_deleted_at_and_audits(self, flask_app, test_user):
        with flask_app.app_context():
            dev = _mk_device(test_user, "agent-soft-test-001",
                             hostname="lifecycle-host")
            assert dev.deleted_at is None
            before = _audit_count()
            changed = dev.soft_delete(actor_user_id=test_user.id, reason="test")
            db.session.commit()
            assert changed is True
            assert dev.deleted_at is not None
            assert _audit_count() == before + 1
            entry = (AuditLog.query
                     .filter_by(action="device.soft_deleted",
                                resource="agent-soft-test-001")
                     .first())
            assert entry is not None
            assert entry.user_id == test_user.id
            assert entry.node_meta["reason"] == "test"
            assert entry.node_meta["device_hostname"] == "lifecycle-host"
            assert "deleted_at" in entry.node_meta

    def test_soft_delete_idempotent(self, flask_app, test_user):
        with flask_app.app_context():
            dev = _mk_device(test_user, "agent-soft-test-002")
            dev.soft_delete(actor_user_id=test_user.id, reason="first")
            db.session.commit()
            count_after_first = _audit_count()
            # Second call should be a no-op
            second = dev.soft_delete(actor_user_id=test_user.id, reason="second")
            db.session.commit()
            assert second is False
            assert _audit_count() == count_after_first  # no extra audit row

    def test_restore_clears_deleted_at_and_audits(self, flask_app, test_user):
        with flask_app.app_context():
            dev = _mk_device(test_user, "agent-soft-test-003",
                             deleted_at=datetime.datetime.utcnow())
            before = _audit_count()
            changed = dev.restore(actor_user_id=test_user.id,
                                  reason="false alarm")
            db.session.commit()
            assert changed is True
            assert dev.deleted_at is None
            assert _audit_count() == before + 1
            entry = (AuditLog.query
                     .filter_by(action="device.restored",
                                resource="agent-soft-test-003")
                     .first())
            assert entry is not None
            assert entry.node_meta["reason"] == "false alarm"
            assert "previously_deleted_at" in entry.node_meta

    def test_restore_idempotent_on_active_device(self, flask_app, test_user):
        with flask_app.app_context():
            dev = _mk_device(test_user, "agent-soft-test-004")
            before = _audit_count()
            changed = dev.restore(actor_user_id=test_user.id)
            db.session.commit()
            assert changed is False
            assert _audit_count() == before  # no audit row

    def test_telemetry_after_delete_writes_audit(self, flask_app, test_user):
        with flask_app.app_context():
            dev = _mk_device(test_user, "agent-soft-test-005",
                             hostname="ghost-host",
                             deleted_at=datetime.datetime.utcnow())
            before = _audit_count(action_prefix="device.telemetry_after_delete")
            tnow = datetime.datetime.utcnow()
            dev.record_telemetry_after_delete(telemetry_at=tnow)
            db.session.commit()
            assert _audit_count("device.telemetry_after_delete") == before + 1
            entry = (AuditLog.query
                     .filter_by(action="device.telemetry_after_delete",
                                resource="agent-soft-test-005")
                     .first())
            assert entry.user_id == test_user.id
            assert entry.status == "warning"
            assert entry.node_meta["device_hostname"] == "ghost-host"
            assert "telemetry_at" in entry.node_meta
            assert entry.node_meta["originally_deleted_at"] is not None


# ═══════════════════════════════════════════════════════════════
# Endpoints (Phase 3)
# ═══════════════════════════════════════════════════════════════

class TestDeleteEndpoint:
    def test_delete_endpoint_soft_deletes(self, client, flask_app,
                                           test_user, auth_headers):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-101")
        r = client.delete("/api/agent/devices/agent-soft-test-101",
                          json={"reason": "endpoint test"},
                          headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["deleted"] is True
        assert body.get("already_deleted") is None or body.get("already_deleted") is False
        with flask_app.app_context():
            dev = AgentDevice.with_deleted().filter_by(id="agent-soft-test-101").first()
            assert dev.deleted_at is not None

    def test_delete_endpoint_idempotent(self, client, flask_app,
                                         test_user, auth_headers):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-102",
                       deleted_at=datetime.datetime.utcnow())
        r = client.delete("/api/agent/devices/agent-soft-test-102",
                          json={"reason": "second time"},
                          headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["deleted"] is True
        assert body["already_deleted"] is True

    def test_delete_endpoint_404_unknown_device(self, client, auth_headers):
        r = client.delete("/api/agent/devices/agent-soft-test-does-not-exist",
                          headers=auth_headers)
        assert r.status_code == 404

    def test_delete_endpoint_404_other_users_device(self, client, flask_app,
                                                     test_user, auth_headers):
        # Insert a device owned by a different user_id
        with flask_app.app_context():
            other = AgentDevice(
                id="agent-soft-test-103",
                user_id=test_user.id + 9999,
                hostname="not-mine",
                first_seen=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
            )
            db.session.add(other); db.session.commit()
        r = client.delete("/api/agent/devices/agent-soft-test-103",
                          headers=auth_headers)
        # Other user's device looks like a 404 from the requesting user's
        # perspective (correct -- never leak existence cross-tenant).
        assert r.status_code == 404


class TestRestoreEndpoint:
    def test_restore_endpoint_undeletes(self, client, flask_app,
                                         test_user, auth_headers):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-201",
                       deleted_at=datetime.datetime.utcnow())
        r = client.post("/api/agent/devices/agent-soft-test-201/restore",
                        json={"reason": "restored test"},
                        headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["restored"] is True
        assert body["device"]["deleted_at"] is None
        with flask_app.app_context():
            dev = AgentDevice.with_deleted().filter_by(id="agent-soft-test-201").first()
            assert dev.deleted_at is None

    def test_restore_endpoint_idempotent_on_active(self, client, flask_app,
                                                    test_user, auth_headers):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-202")
        r = client.post("/api/agent/devices/agent-soft-test-202/restore",
                        headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["restored"] is True
        assert body["already_active"] is True

    def test_restore_404_unknown(self, client, auth_headers):
        r = client.post("/api/agent/devices/no-such-device/restore",
                        headers=auth_headers)
        assert r.status_code == 404


class TestListEndpointFiltering:
    def test_list_default_excludes_soft_deleted(self, client, flask_app,
                                                 test_user, auth_headers):
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-301-active")
            _mk_device(test_user, "agent-soft-test-301-deleted",
                       deleted_at=datetime.datetime.utcnow())
        r = client.get("/api/agent/devices", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [d["id"] for d in body["devices"]]
        assert "agent-soft-test-301-active" in ids
        assert "agent-soft-test-301-deleted" not in ids
        assert body["include_deleted"] is False

    def test_list_include_deleted_requires_audit_read_permission(
        self, client, flask_app, test_user, auth_headers
    ):
        # test_user has no roles by default in the test fixture.
        # ?include_deleted=true should be rejected with 403.
        r = client.get("/api/agent/devices?include_deleted=true",
                       headers=auth_headers)
        assert r.status_code == 403
        body = r.get_json()
        assert body["required"] == "audit:read"

    def test_list_include_deleted_with_owner_role_returns_deleted(
        self, client, flask_app, test_user, auth_headers
    ):
        # Grant the test user the 'owner' role -- per the canonical
        # require_permission decorator, owner bypasses all checks.
        with flask_app.app_context():
            from dashboard.backend.iam.models import Role, UserRole
            owner_role = Role.query.filter_by(name="owner").first()
            if not owner_role:
                owner_role = Role(name="owner",
                                  description="test fixture owner")
                db.session.add(owner_role); db.session.commit()
            assignment = UserRole.query.filter_by(
                user_id=test_user.id, role_id=owner_role.id
            ).first()
            if not assignment:
                db.session.add(UserRole(user_id=test_user.id,
                                        role_id=owner_role.id))
                db.session.commit()
            _mk_device(test_user, "agent-soft-test-302-active")
            _mk_device(test_user, "agent-soft-test-302-deleted",
                       deleted_at=datetime.datetime.utcnow())
        r = client.get("/api/agent/devices?include_deleted=true",
                       headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [d["id"] for d in body["devices"]]
        assert "agent-soft-test-302-active" in ids
        assert "agent-soft-test-302-deleted" in ids
        assert body["include_deleted"] is True
