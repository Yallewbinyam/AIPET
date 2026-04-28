# =============================================================
# AIPET X — Team-Access Tier 1 v1: GET /api/iam/members + audit
#
# Pins the basic-list-with-pagination contract for both endpoints.
# Filters / search / sort / CSV-export are out of scope here -- they
# come in a follow-up session per Phase B § 8 F5/F6.
# =============================================================
from __future__ import annotations

import json

from flask_jwt_extended import create_access_token

from dashboard.backend.iam.routes import (
    seed_default_roles,
    assign_role_to_user,
)
from dashboard.backend.iam.models import UserRole, AuditLog
from dashboard.backend.models import db


# --- helpers ---------------------------------------------------------

def _reset_limiter(flask_app):
    """Wipe Flask-Limiter in-process counters so prior test files'
    deliberate-exhaustions don't bleed in."""
    entry = flask_app.extensions.get("limiter")
    if entry is None:
        return
    items = entry if isinstance(entry, (set, list, tuple)) else (entry,)
    for lim in items:
        try:
            lim.reset()
        except Exception:
            pass


def _owner_headers(flask_app, test_user):
    """Return Authorization headers for test_user with the owner role
    assigned. Idempotent: if owner is already attached, no-op.
    The session-scoped flask_app fixture has already run
    seed_default_roles() at app boot (per F1)."""
    seed_default_roles()  # idempotent; safety net
    assign_role_to_user(test_user.id, "owner",
                        assigned_by=test_user.id,
                        reason="test-owner-grant",
                        emit_audit=False)
    db.session.commit()

    token = create_access_token(identity=str(test_user.id))
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }


# --- /api/iam/members ------------------------------------------------

def test_members_list_returns_200_for_owner(client, flask_app, test_user):
    """Happy path: owner JWT -> 200 with members array, total/pages/page."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    r = client.get("/api/iam/members", headers=headers)
    assert r.status_code == 200, r.data

    body = r.get_json()
    assert isinstance(body.get("members"), list)
    assert "total" in body and "pages" in body and "page" in body

    # The session-scoped test_user must appear in the list with the
    # owner role we just assigned.
    me = next((m for m in body["members"] if m["id"] == test_user.id), None)
    assert me is not None, f"test user not in members list: {body['members']}"
    assert me["email"] == test_user.email
    role_names = {r["name"] for r in me["roles"]}
    assert "owner" in role_names

    # Shape check: every member has the documented fields.
    for m in body["members"]:
        for required in ("id", "email", "name", "plan", "is_active", "roles"):
            assert required in m, f"missing {required} in {m}"


def test_members_list_returns_401_without_jwt(client, flask_app):
    """No JWT -> 401 (Flask-JWT-Extended Missing Authorization Header)."""
    _reset_limiter(flask_app)
    r = client.get("/api/iam/members")
    assert r.status_code == 401, r.data


def test_members_list_pagination_respects_per_page(client, flask_app, test_user):
    """`per_page=1` reduces the response page size; `total` stays accurate."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    r = client.get("/api/iam/members?per_page=1&page=1", headers=headers)
    assert r.status_code == 200
    body = r.get_json()
    assert len(body["members"]) <= 1
    assert body["page"] == 1
    # pages must reflect the per_page cap given the actual total
    if body["total"] > 0:
        assert body["pages"] >= 1


# --- /api/iam/audit --------------------------------------------------

def test_audit_list_returns_200_for_owner(client, flask_app, test_user):
    """Happy path: owner JWT -> 200 with logs array + pagination meta."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Plant one audit row so the list is non-empty regardless of
    # other tests' history.
    from datetime import datetime, timezone
    db.session.add(AuditLog(
        user_id    = test_user.id,
        action     = "test.audit_listing",
        resource   = "test_iam_members_audit",
        ip_address = "127.0.0.1",
        status     = "success",
        timestamp  = datetime.now(timezone.utc),
    ))
    db.session.commit()

    r = client.get("/api/iam/audit?per_page=10", headers=headers)
    assert r.status_code == 200, r.data

    body = r.get_json()
    assert isinstance(body.get("logs"), list)
    assert "total" in body and "pages" in body and "page" in body
    assert body["total"] >= 1

    for entry in body["logs"]:
        for required in ("id", "action", "status"):
            assert required in entry, f"missing {required} in {entry}"


def test_audit_list_returns_401_without_jwt(client, flask_app):
    """No JWT -> 401."""
    _reset_limiter(flask_app)
    r = client.get("/api/iam/audit")
    assert r.status_code == 401, r.data


def test_audit_handles_null_timestamp_gracefully(client, flask_app, test_user):
    """Pre-existing weakness from F2: a row with NULL timestamp must
    not crash the handler. Insert one such row and confirm the
    endpoint still returns 200; the row's timestamp comes back null."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Plant a row, then UPDATE its timestamp to NULL via raw SQL to
    # bypass SQLAlchemy's `default=datetime.utcnow` (which re-fires
    # on flush when the attribute is None). This is the same shape
    # of NULL-timestamp row that the F2 backfill SQL produced before
    # we patched it, and the same shape that crashed get_audit_log
    # in the first place.
    row = AuditLog(
        user_id  = test_user.id,
        action   = "test.null_timestamp_row",
        resource = "test_iam_members_audit",
        status   = "success",
    )
    db.session.add(row)
    db.session.commit()
    db.session.execute(
        db.text("UPDATE audit_log SET timestamp = NULL WHERE id = :id"),
        {"id": row.id},
    )
    db.session.commit()

    # Fetch the latest page and confirm the handler doesn't 500.
    r = client.get("/api/iam/audit?per_page=200", headers=headers)
    assert r.status_code == 200, r.data
    body = r.get_json()
    null_ts = [l for l in body["logs"]
               if l["action"] == "test.null_timestamp_row"]
    assert null_ts, "planted null-timestamp row not found in response"
    assert null_ts[0]["timestamp"] is None, (
        "NULL timestamp should serialise as null, not crash"
    )
