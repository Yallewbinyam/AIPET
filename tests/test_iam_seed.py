# =============================================================
# AIPET X — Team-Access F1: seed_default_roles() idempotency
#
# Phase A audit found seed_default_roles() was imported at
# app_cloud.py:66 but never called. F1 wires it into the
# app_context() startup block, mirroring the MITRE seed.
#
# This test pins the contract: calling seed_default_roles() once
# produces 4 roles + 10 permissions; calling it again does not
# duplicate (idempotent via filter_by(...).first() guards).
# =============================================================
from __future__ import annotations

from dashboard.backend.iam.routes import seed_default_roles
from dashboard.backend.iam.models import Role, Permission


def test_seed_default_roles_creates_four_roles_and_ten_permissions(flask_app):
    """First call seeds 4 roles + 10 permissions."""
    seed_default_roles()
    assert Role.query.count() == 4
    assert Permission.query.count() == 10

    role_names = {r.name for r in Role.query.all()}
    assert role_names == {"owner", "admin", "analyst", "viewer"}

    perm_names = {p.name for p in Permission.query.all()}
    assert perm_names == {
        "scan:create", "scan:read",
        "findings:read",
        "reports:read", "reports:create",
        "billing:manage", "iam:manage",
        "audit:read", "sso:manage",
        "terminal:use",
    }


def test_seed_default_roles_is_idempotent(flask_app):
    """Second call must not duplicate rows."""
    # Test 1 already ran the first call. A second call here
    # exercises the filter_by(...).first() idempotency guard.
    seed_default_roles()
    assert Role.query.count() == 4
    assert Permission.query.count() == 10


# =============================================================
# Team-Access F2: assign_role_to_user() helper + register-flow
# =============================================================
import json
import pytest
from dashboard.backend.iam.routes import assign_role_to_user
from dashboard.backend.iam.models import UserRole, AuditLog
from dashboard.backend.models import db, User


def _reset_limiter(flask_app):
    """Wipe Flask-Limiter in-process counters between tests so that
    test_auth.py's deliberate-exhaustion of register/login limits
    doesn't bleed into these tests."""
    entry = flask_app.extensions.get("limiter")
    if entry is None:
        return
    items = entry if isinstance(entry, (set, list, tuple)) else (entry,)
    for lim in items:
        try:
            lim.reset()
        except Exception:
            pass


def test_assign_role_to_user_idempotent(flask_app, test_user):
    """Calling the helper twice for the same (user, role) creates
    exactly one UserRole row; the second call is a no-op."""
    seed_default_roles()  # guarantees 'owner' exists

    # Wipe any prior UserRole rows for this test user so the test
    # is self-contained.
    UserRole.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    ur1 = assign_role_to_user(test_user.id, "owner",
                              assigned_by=test_user.id,
                              reason="test-idempotent")
    db.session.commit()
    assert UserRole.query.filter_by(user_id=test_user.id).count() == 1

    ur2 = assign_role_to_user(test_user.id, "owner",
                              assigned_by=test_user.id,
                              reason="test-idempotent-second-call")
    db.session.commit()
    # Idempotent: same row returned, no new insert.
    assert UserRole.query.filter_by(user_id=test_user.id).count() == 1
    assert ur1.id == ur2.id


def test_assign_role_to_user_nonexistent_role_raises(flask_app, test_user):
    """Helper must raise LookupError on a role name that does not
    exist in the roles table -- caller is responsible for the
    decision to swallow or propagate."""
    seed_default_roles()
    with pytest.raises(LookupError) as exc:
        assign_role_to_user(test_user.id, "this-role-does-not-exist")
    assert "this-role-does-not-exist" in str(exc.value)


def test_register_assigns_owner_role(flask_app, client):
    """End-to-end: POST /api/auth/register creates a user AND
    assigns the 'owner' role atomically; audit_log records the
    assignment with reason=auto-on-registration."""
    seed_default_roles()
    _reset_limiter(flask_app)

    test_email = "f2-pytest-register@aipet.local"
    # Clean any leftover from a prior partial run.
    leftover = User.query.filter_by(email=test_email).first()
    if leftover:
        UserRole.query.filter_by(user_id=leftover.id).delete()
        AuditLog.query.filter_by(resource=f"user:{leftover.id}").delete()
        db.session.delete(leftover)
        db.session.commit()

    r = client.post(
        "/api/auth/register",
        data=json.dumps({
            "email":    test_email,
            "password": "PyTestPass123!",
            "name":     "F2 Pytest",
        }),
        headers={
            "Content-Type":    "application/json",
            "X-Forwarded-For": "10.42.6.1",  # unique IP per test
        },
    )
    assert r.status_code == 201, f"register returned {r.status_code}: {r.data!r}"

    user = User.query.filter_by(email=test_email).first()
    assert user is not None

    # Owner role must be assigned.
    role_count = UserRole.query.filter_by(user_id=user.id).count()
    assert role_count == 1, \
        f"expected 1 user_role row, got {role_count}"

    # Audit log row exists with the structured node_meta.
    audit = AuditLog.query.filter_by(
        resource=f"user:{user.id}",
        action="role.assigned",
    ).first()
    assert audit is not None
    assert audit.node_meta == {
        "role":   "owner",
        "reason": "auto-on-registration",
    }

    # Cleanup.
    UserRole.query.filter_by(user_id=user.id).delete()
    AuditLog.query.filter_by(resource=f"user:{user.id}").delete()
    db.session.delete(user)
    db.session.commit()
