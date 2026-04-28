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

    # =====================================================================
    # Pattern A (2026-04-28): owner-implicit access to OWN deleted devices
    # =====================================================================
    # Pre-Pattern A this endpoint required audit:read for ?include_deleted.
    # That broke tenant self-service: a regular user who soft-deleted their
    # own device by accident had no UI path to recover it. Pattern A
    # opens the per-tenant include_deleted view to anyone authenticated;
    # cross-tenant viewing now sits behind a separate ?all_tenants=true
    # flag that retains the audit:read gate.

    def test_user_can_view_own_deleted_devices(self, client, flask_app,
                                                test_user, auth_headers):
        # Pattern A positive case: regular user (no roles), can see their
        # OWN soft-deleted device with ?include_deleted=true.
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-301-active")
            _mk_device(test_user, "agent-soft-test-301-deleted",
                       deleted_at=datetime.datetime.utcnow())
        r = client.get("/api/agent/devices?include_deleted=true",
                       headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [d["id"] for d in body["devices"]]
        assert "agent-soft-test-301-active" in ids
        assert "agent-soft-test-301-deleted" in ids
        assert body["include_deleted"] is True
        assert body["all_tenants"] is False

    def test_user_cannot_view_other_users_deleted_devices(
        self, client, flask_app, test_user, auth_headers
    ):
        # Pattern A negative case: insert a device owned by a different
        # user_id, soft-delete it. The current authenticated user
        # (test_user) must NOT see it via ?include_deleted=true. Per-
        # tenant scope (filter_by(user_id=uid)) is the safety net even
        # when the include_deleted gate is open.
        with flask_app.app_context():
            other_dev = AgentDevice(
                id="agent-soft-test-302-other-tenant",
                user_id=test_user.id + 9999,    # different tenant
                hostname="not-mine",
                first_seen=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
                deleted_at=datetime.datetime.utcnow(),
            )
            db.session.add(other_dev)
            db.session.commit()
        r = client.get("/api/agent/devices?include_deleted=true",
                       headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [d["id"] for d in body["devices"]]
        assert "agent-soft-test-302-other-tenant" not in ids

    def test_user_can_restore_own_deleted_device(self, client, flask_app,
                                                  test_user, auth_headers):
        # Pattern A: full UI round-trip. User soft-deletes -> sees row in
        # include_deleted view -> restores -> row back to active.
        with flask_app.app_context():
            _mk_device(test_user, "agent-soft-test-303-roundtrip",
                       deleted_at=datetime.datetime.utcnow())
        r = client.post(
            "/api/agent/devices/agent-soft-test-303-roundtrip/restore",
            json={"reason": "Pattern A self-service restore"},
            headers=auth_headers,
        )
        assert r.status_code == 200
        assert r.get_json()["restored"] is True
        with flask_app.app_context():
            dev = (AgentDevice.with_deleted()
                   .filter_by(id="agent-soft-test-303-roundtrip").first())
            assert dev.deleted_at is None

    def test_admin_can_view_cross_tenant_with_explicit_flag(
        self, client, flask_app, test_user, auth_headers
    ):
        # Cross-tenant path: ?include_deleted=true&all_tenants=true.
        # Requires owner role or audit:read permission. Grant owner
        # (canonical bypass) for this test, insert another tenant's
        # deleted device, confirm the admin sees both.
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
            _mk_device(test_user, "agent-soft-test-304-mine",
                       deleted_at=datetime.datetime.utcnow())
            other_dev = AgentDevice(
                id="agent-soft-test-304-other",
                user_id=test_user.id + 9999,
                hostname="other-tenant-deleted",
                first_seen=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
                deleted_at=datetime.datetime.utcnow(),
            )
            db.session.add(other_dev)
            db.session.commit()
        try:
            r = client.get(
                "/api/agent/devices?include_deleted=true&all_tenants=true",
                headers=auth_headers,
            )
            assert r.status_code == 200
            body = r.get_json()
            ids = [d["id"] for d in body["devices"]]
            assert "agent-soft-test-304-mine" in ids
            assert "agent-soft-test-304-other" in ids   # cross-tenant
            assert body["all_tenants"] is True
        finally:
            # Clean up the role assignment so subsequent tests run with
            # a no-roles user (matching Pattern A's primary use case).
            # Re-query Role inside this app_context -- the role row from
            # the earlier context is detached and would raise
            # DetachedInstanceError when SQLAlchemy tries to refresh it.
            with flask_app.app_context():
                from dashboard.backend.iam.models import Role as _Role
                fresh_owner = _Role.query.filter_by(name="owner").first()
                if fresh_owner:
                    UserRole.query.filter_by(
                        user_id=test_user.id, role_id=fresh_owner.id
                    ).delete()
                    db.session.commit()

    def test_all_tenants_without_include_deleted_rejected(
        self, client, flask_app, test_user, auth_headers
    ):
        # Defensive: all_tenants=true without include_deleted is not a
        # supported feature today (cross-tenant active-device snooping
        # is a separate conversation). Endpoint must reject 400.
        r = client.get("/api/agent/devices?all_tenants=true",
                       headers=auth_headers)
        assert r.status_code == 400

    def test_all_tenants_without_admin_role_rejected(
        self, client, flask_app, test_user, auth_headers
    ):
        # Negative: a no-roles user trying to use ?all_tenants=true (with
        # include_deleted=true) is rejected with 403. The cross-tenant
        # gate did NOT regress when we opened the per-tenant gate.
        r = client.get(
            "/api/agent/devices?include_deleted=true&all_tenants=true",
            headers=auth_headers,
        )
        assert r.status_code == 403
        body = r.get_json()
        assert body["required"] == "audit:read"
