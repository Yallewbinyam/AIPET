# =============================================================
# AIPET X — Phase C backend addition:
# PUT /api/iam/users/<int:user_id>/role
#
# Atomic role replacement. The frontend "Change role" UI used
# DELETE-then-POST in earlier drafts, which left a window where
# the user had zero roles if the second request failed. This
# endpoint does both inside one transaction.
#
# Two cases pinned here:
#   1. happy path -- replacing a non-owner role updates UserRole
#      atomically and writes a structured audit row
#   2. last-owner safety -- changing the only active owner away
#      from owner is refused with 400 + the same error contract
#      the disable/remove endpoints use
# =============================================================
from __future__ import annotations

import json

from flask_jwt_extended import create_access_token

from dashboard.backend.iam.routes import (
    seed_default_roles,
    assign_role_to_user,
)
from dashboard.backend.iam.models import UserRole, AuditLog
from dashboard.backend.models import db, User


def _wipe_user_roles(user_id):
    UserRole.query.filter_by(user_id=user_id).delete()
    db.session.commit()


def test_replace_role_happy_path_swaps_roles_and_writes_audit(
        flask_app, client, test_user):
    """A user with the viewer role -> PUT {role: admin} returns 200,
    flips UserRole atomically (one row, role=admin), and writes
    user.role_changed with {old_roles:[viewer], new_role:admin}."""
    seed_default_roles()

    # Caller: a fresh owner user (so the iam:manage gate passes).
    caller_email = "rolereplace-caller@aipet.local"
    caller = User.query.filter_by(email=caller_email).first()
    if caller is None:
        caller = User(email=caller_email, password_hash="x",
                      name="Role Replace Caller", plan="enterprise")
        db.session.add(caller)
        db.session.commit()
    _wipe_user_roles(caller.id)
    assign_role_to_user(caller.id, "owner",
                        assigned_by=caller.id,
                        reason="test-role-replace-caller")
    db.session.commit()

    # Target: a separate user starting with the viewer role.
    target_email = "rolereplace-target@aipet.local"
    target = User.query.filter_by(email=target_email).first()
    if target is None:
        target = User(email=target_email, password_hash="x",
                      name="Role Replace Target", plan="enterprise")
        db.session.add(target)
        db.session.commit()
    _wipe_user_roles(target.id)
    AuditLog.query.filter_by(resource=f"user:{target.id}").delete()
    db.session.commit()
    assign_role_to_user(target.id, "viewer",
                        assigned_by=caller.id,
                        reason="test-role-replace-seed")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(caller.id))}",
        "Content-Type": "application/json",
    }
    r = client.put(
        f"/api/iam/users/{target.id}/role",
        headers=headers,
        data=json.dumps({"role": "admin"}),
    )
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["id"] == target.id
    assert [role["name"] for role in body["roles"]] == ["admin"]

    # DB-level check: exactly one UserRole row, role.name = admin.
    rows = UserRole.query.filter_by(user_id=target.id).all()
    assert len(rows) == 1

    # Audit row: action + structured node_meta.
    audit = AuditLog.query.filter_by(
        resource=f"user:{target.id}",
        action="user.role_changed",
    ).first()
    assert audit is not None
    assert audit.node_meta == {
        "old_roles": ["viewer"],
        "new_role":  "admin",
    }

    # Cleanup so subsequent test files start clean.
    UserRole.query.filter_by(user_id=target.id).delete()
    UserRole.query.filter_by(user_id=caller.id).delete()
    AuditLog.query.filter_by(resource=f"user:{target.id}").delete()
    AuditLog.query.filter_by(resource=f"user:{caller.id}").delete()
    db.session.delete(target)
    db.session.delete(caller)
    db.session.commit()


def test_replace_role_blocks_changing_last_owner(
        flask_app, client, test_user):
    """If the target is the only active+present owner and the new
    role isn't owner, the endpoint must 400 'last_owner' and leave
    the UserRole row untouched."""
    seed_default_roles()

    # Wipe any prior roles on test_user, then make them the SOLE
    # active owner. (Other tests in this file create+delete their
    # own users; nothing else currently grants owner outside
    # test_user, but the wipe is defensive.)
    _wipe_user_roles(test_user.id)
    AuditLog.query.filter_by(resource=f"user:{test_user.id}").delete()
    db.session.commit()
    assign_role_to_user(test_user.id, "owner",
                        assigned_by=test_user.id,
                        reason="test-role-replace-last-owner")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(test_user.id))}",
        "Content-Type": "application/json",
    }
    r = client.put(
        f"/api/iam/users/{test_user.id}/role",
        headers=headers,
        data=json.dumps({"role": "viewer"}),
    )
    assert r.status_code == 400, r.data
    body = r.get_json()
    assert body["error"] == "last_owner"
    assert "last owner" in body["message"].lower()

    # Untouched: still exactly one UserRole row, still owner.
    rows = UserRole.query.filter_by(user_id=test_user.id).all()
    assert len(rows) == 1

    # No 'user.role_changed' audit row should have been written.
    audit = AuditLog.query.filter_by(
        resource=f"user:{test_user.id}",
        action="user.role_changed",
    ).first()
    assert audit is None
