# =============================================================
# AIPET X — Phase B § 4.10 / § 8 H1: GET /api/iam/permission-matrix
#
# Read-only matrix backing the "Permissions" tab. Returns the
# full role + permission catalogues plus the (role_id,
# permission_id) junction pairs the frontend ticks into a
# checkbox grid. Mutation endpoints (G1/G2/PATCH) are deferred
# to v1.1.
#
# Pin the contract:
#   - 200 happy path with stable shape
#   - default grant matrix matches the user-confirmed mapping
#     (owner=10, admin=8, analyst=5, viewer=3)
#   - every grant references a real role + real permission
#   - 401 without JWT
#   - 403 when the caller lacks iam:manage (and is not owner)
# =============================================================
from __future__ import annotations

from collections import Counter

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


def test_permission_matrix_returns_200_with_correct_shape(
        flask_app, client, test_user):
    """Owner caller -> 200; payload has roles + permissions + grants
    and the catalogue counts match the seed (4 roles, 10 perms)."""
    seed_default_roles()
    _wipe_user_roles(test_user.id)
    assign_role_to_user(test_user.id, "owner",
                        assigned_by=test_user.id,
                        reason="test-permission-matrix")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(test_user.id))}",
        "Content-Type": "application/json",
    }
    r = client.get("/api/iam/permission-matrix", headers=headers)
    assert r.status_code == 200, r.data

    body = r.get_json()
    assert set(body.keys()) == {"roles", "permissions", "grants"}

    assert len(body["roles"]) == 4
    assert {row["name"] for row in body["roles"]} == {
        "owner", "admin", "analyst", "viewer",
    }
    for row in body["roles"]:
        assert set(row.keys()) == {"id", "name", "description"}

    assert len(body["permissions"]) == 10
    for row in body["permissions"]:
        assert set(row.keys()) == {"id", "name", "resource", "action"}

    # Grants is a flat list of {role_id, permission_id}.
    for row in body["grants"]:
        assert set(row.keys()) == {"role_id", "permission_id"}


def test_permission_matrix_grants_match_default_spec(
        flask_app, client, test_user):
    """Per-role grant counts must match the user-confirmed mapping:
    owner=10, admin=8, analyst=5, viewer=3 -> total 26."""
    seed_default_roles()
    _wipe_user_roles(test_user.id)
    assign_role_to_user(test_user.id, "owner",
                        assigned_by=test_user.id,
                        reason="test-permission-matrix-counts")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(test_user.id))}",
        "Content-Type": "application/json",
    }
    body = client.get("/api/iam/permission-matrix",
                      headers=headers).get_json()

    role_id_to_name = {r["id"]: r["name"] for r in body["roles"]}
    counts = Counter(role_id_to_name[g["role_id"]]
                     for g in body["grants"])
    assert counts == {
        "owner":   10,
        "admin":    8,
        "analyst":  5,
        "viewer":   3,
    }
    assert len(body["grants"]) == 26


def test_permission_matrix_grants_reference_valid_ids(
        flask_app, client, test_user):
    """Every (role_id, permission_id) must point at a row that
    exists in this same payload -- no orphan junction rows."""
    seed_default_roles()
    _wipe_user_roles(test_user.id)
    assign_role_to_user(test_user.id, "owner",
                        assigned_by=test_user.id,
                        reason="test-permission-matrix-refs")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(test_user.id))}",
        "Content-Type": "application/json",
    }
    body = client.get("/api/iam/permission-matrix",
                      headers=headers).get_json()

    role_ids = {r["id"] for r in body["roles"]}
    perm_ids = {p["id"] for p in body["permissions"]}
    orphans = [g for g in body["grants"]
               if g["role_id"] not in role_ids
               or g["permission_id"] not in perm_ids]
    assert orphans == []


def test_permission_matrix_unauthenticated_returns_401(
        flask_app, client):
    """No Authorization header -> 401 (Flask-JWT-Extended default)."""
    r = client.get("/api/iam/permission-matrix")
    assert r.status_code == 401


def test_permission_matrix_without_iam_manage_returns_403(
        flask_app, client):
    """A caller with only the viewer role (no iam:manage, not owner)
    must be refused with 403. Uses a dedicated user so the shared
    test_user's owner assignment isn't disturbed."""
    seed_default_roles()

    email = "viewer-pm@aipet.local"
    leftover = User.query.filter_by(email=email).first()
    if leftover:
        UserRole.query.filter_by(user_id=leftover.id).delete()
        db.session.delete(leftover)
        db.session.commit()

    viewer = User(
        email         = email,
        password_hash = "x",
        name          = "Viewer PM",
        plan          = "enterprise",
    )
    db.session.add(viewer)
    db.session.commit()
    assign_role_to_user(viewer.id, "viewer",
                        assigned_by=viewer.id,
                        reason="test-permission-matrix-403")
    db.session.commit()

    headers = {
        "Authorization":
            f"Bearer {create_access_token(identity=str(viewer.id))}",
        "Content-Type": "application/json",
    }
    r = client.get("/api/iam/permission-matrix", headers=headers)
    assert r.status_code == 403
    body = r.get_json()
    assert body.get("required") == "iam:manage"

    # Cleanup so subsequent test files start from a known state.
    # AuditLog rows must go too -- assign_role_to_user wrote one
    # keyed on resource=f"user:{viewer.id}", and SQLite recycles
    # primary keys after a row is deleted, so a later test that
    # queries by resource=f"user:{new_id}" would otherwise collide
    # with this stale row.
    UserRole.query.filter_by(user_id=viewer.id).delete()
    AuditLog.query.filter_by(resource=f"user:{viewer.id}").delete()
    db.session.delete(viewer)
    db.session.commit()
