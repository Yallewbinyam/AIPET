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
from dashboard.backend.iam.models import UserRole, AuditLog, Role
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


# =============================================================
# Tier 1 v1 — audit filters + CSV export
# Phase B § 8 F5 + F6
# =============================================================
import csv as _csv
import io as _io
import json as _json
from datetime import datetime, timezone, timedelta


def _seed_audit_rows(test_user, count=5, action="seed.test", status="success"):
    """Insert N audit rows tagged with a unique action+resource so
    a per-test filter selects exactly those rows. Returns the
    resource string (unique per call so concurrent tests don't
    collide)."""
    import uuid as _uuid
    resource = f"audit-filter-test-{_uuid.uuid4().hex[:8]}"
    rows = []
    base = datetime.now(timezone.utc)
    for i in range(count):
        row = AuditLog(
            user_id    = test_user.id,
            action     = action,
            resource   = resource,
            ip_address = "127.0.0.1",
            status     = status,
            timestamp  = base - timedelta(minutes=i),
        )
        rows.append(row)
        db.session.add(row)
    db.session.commit()
    return resource


# --- per-filter tests ------------------------------------------------

def test_audit_filter_action_narrows_results(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    res = _seed_audit_rows(test_user, count=3, action="audit.filter.action_test")

    r = client.get(
        "/api/iam/audit?action=audit.filter.action_test&per_page=20",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 3
    assert all(l["action"] == "audit.filter.action_test"
               for l in body["logs"])
    # Cleanup
    AuditLog.query.filter_by(resource=res if False else res).delete()
    db.session.commit()


def test_audit_filter_actor_narrows_results(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _seed_audit_rows(test_user, count=2, action="audit.filter.actor_test")

    r = client.get(
        f"/api/iam/audit?actor={test_user.id}&action=audit.filter.actor_test",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 2
    assert all(l["user_id"] == test_user.id for l in body["logs"])


def test_audit_filter_status_narrows_results(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _seed_audit_rows(test_user, count=2, action="audit.filter.status_ok",
                     status="success")
    _seed_audit_rows(test_user, count=3, action="audit.filter.status_blk",
                     status="blocked")

    r = client.get(
        "/api/iam/audit?action=audit.filter.status_blk&status=blocked",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 3
    assert all(l["status"] == "blocked" for l in body["logs"])


def test_audit_filter_resource_partial_match(client, flask_app, test_user):
    """resource uses ILIKE %substr% so a partial resource match works."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _seed_audit_rows(test_user, count=2, action="audit.filter.resource_test")

    # The seeded resource starts with "audit-filter-test-"; partial
    # match "filter-test" should return both.
    r = client.get(
        "/api/iam/audit?action=audit.filter.resource_test&resource=filter-test",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 2


def test_audit_filter_since_until_window(client, flask_app, test_user):
    """since is inclusive, until is exclusive."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Plant 3 rows at known timestamps spaced 1 hour apart.
    base = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        AuditLog(
            user_id   = test_user.id,
            action    = "audit.filter.window_test",
            resource  = "audit-window",
            status    = "success",
            timestamp = base + timedelta(hours=i),
        )
        for i in range(3)
    ]
    for r in rows:
        db.session.add(r)
    db.session.commit()

    # since = 12:30, until = 13:30 → only the 13:00 row qualifies.
    # Using `query_string` so Flask URL-encodes the `+` in the
    # +00:00 timezone offset (otherwise it gets decoded as a space).
    since = (base + timedelta(minutes=30)).isoformat()
    until = (base + timedelta(hours=1, minutes=30)).isoformat()
    r = client.get(
        "/api/iam/audit",
        query_string={
            "action": "audit.filter.window_test",
            "since":  since,
            "until":  until,
        },
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 1
    assert body["logs"][0]["timestamp"].startswith("2025-06-15T13:00")


def test_audit_filter_combination(client, flask_app, test_user):
    """Multiple filters AND together."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _seed_audit_rows(test_user, count=2, action="audit.combo.test", status="success")
    _seed_audit_rows(test_user, count=3, action="audit.combo.test", status="blocked")

    r = client.get(
        f"/api/iam/audit?action=audit.combo.test&actor={test_user.id}&status=success",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 2
    assert all(l["status"] == "success" for l in body["logs"])


def test_audit_filter_invalid_since_returns_400(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.get("/api/iam/audit?since=not-a-date", headers=headers)
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "invalid_filter"
    assert body["field"] == "since"


def test_audit_filter_invalid_actor_returns_400(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.get("/api/iam/audit?actor=abc", headers=headers)
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "invalid_filter"
    assert body["field"] == "actor"


def test_audit_filter_no_match_returns_empty(client, flask_app, test_user):
    """Filter combo that matches nothing returns 200 + empty logs."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.get(
        "/api/iam/audit?action=this.action.does.not.exist.0xdeadbeef",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 0
    assert body["logs"] == []


# --- CSV export ------------------------------------------------------

def test_audit_export_csv_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _seed_audit_rows(test_user, count=3, action="audit.export.happy")

    r = client.get(
        "/api/iam/audit/export?action=audit.export.happy",
        headers=headers,
    )
    assert r.status_code == 200
    assert r.content_type.startswith("text/csv")
    # Filename follows the documented pattern.
    cd = r.headers.get("Content-Disposition", "")
    assert 'attachment; filename="audit_log_' in cd
    assert cd.endswith('.csv"')

    text = r.data.decode("utf-8")
    reader = _csv.reader(_io.StringIO(text))
    rows = list(reader)
    assert rows[0] == [
        "timestamp", "user_id", "action", "resource",
        "status", "ip_address", "user_agent", "node_meta_json",
    ]
    assert len(rows) == 1 + 3   # header + 3 seeded rows
    for body_row in rows[1:]:
        assert body_row[2] == "audit.export.happy"   # action column
        assert body_row[1] == str(test_user.id)       # user_id column


def test_audit_export_node_meta_json_escaped(client, flask_app, test_user):
    """node_meta dict serialises as a JSON string; csv handles
    the embedded quotes correctly so a downstream csv parser
    round-trips it."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    row = AuditLog(
        user_id   = test_user.id,
        action    = "audit.export.node_meta",
        resource  = "audit-nm",
        status    = "success",
        timestamp = datetime.now(timezone.utc),
        node_meta = {"role": "owner", "reason": "csv-test", "n": 42},
    )
    db.session.add(row)
    db.session.commit()

    r = client.get(
        "/api/iam/audit/export?action=audit.export.node_meta",
        headers=headers,
    )
    assert r.status_code == 200
    reader = _csv.reader(_io.StringIO(r.data.decode("utf-8")))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 row
    nm_str = rows[1][7]
    parsed = _json.loads(nm_str)
    assert parsed == {"role": "owner", "reason": "csv-test", "n": 42}


def test_audit_export_cap_returns_400(client, flask_app, test_user):
    """Export over the cap returns 400, not a truncated CSV."""
    from dashboard.backend.iam.routes import AUDIT_EXPORT_CAP
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Patch the cap to 3 to avoid inserting thousands of rows.
    import dashboard.backend.iam.routes as iam_routes
    original_cap = iam_routes.AUDIT_EXPORT_CAP
    iam_routes.AUDIT_EXPORT_CAP = 3
    try:
        _seed_audit_rows(test_user, count=5, action="audit.export.cap_test")
        r = client.get(
            "/api/iam/audit/export?action=audit.export.cap_test",
            headers=headers,
        )
        assert r.status_code == 400
        body = r.get_json()
        assert body["error"] == "export_too_large"
        assert body["matching_rows"] == 5
        assert body["limit"] == 3
    finally:
        iam_routes.AUDIT_EXPORT_CAP = original_cap


def test_audit_export_returns_401_without_jwt(client, flask_app):
    _reset_limiter(flask_app)
    r = client.get("/api/iam/audit/export")
    assert r.status_code == 401


# =============================================================
# Tier 1 v1 — member detail + enable/disable
# Phase B § 6.1.2, § 6.1.3, § 6.1.4
# =============================================================
import bcrypt as _bcrypt
import uuid as _uuid_iam
from dashboard.backend.models import User as _User
from dashboard.backend.iam.models import UserRole as _UR
from dashboard.backend.iam.routes import _is_last_owner


def _create_user(email_suffix, name="Member Test", plan="free"):
    """Create a user in the test DB with a fresh email and a real
    bcrypt hash. Returns the user. Caller is responsible for cleanup
    via _delete_user."""
    email = f"member-{email_suffix}-{_uuid_iam.uuid4().hex[:8]}@aipet.local"
    pw_hash = _bcrypt.hashpw(b"PW", _bcrypt.gensalt()).decode("utf-8")
    u = _User(email=email, password_hash=pw_hash, name=name, plan=plan)
    db.session.add(u)
    db.session.commit()
    return u


def _delete_user(u):
    """Tear down a user + their role assignments + their audit rows."""
    _UR.query.filter_by(user_id=u.id).delete()
    AuditLog.query.filter_by(resource=f"user:{u.id}").delete()
    db.session.delete(u)
    db.session.commit()


# --- GET /api/iam/users/<id> ---------------------------------------

def test_member_detail_returns_200_for_owner(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    r = client.get(f"/api/iam/users/{test_user.id}", headers=headers)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["id"] == test_user.id
    assert body["email"] == test_user.email
    for required in ("id", "email", "name", "plan", "is_active",
                     "roles", "last_login", "created_at"):
        assert required in body, f"missing {required} in {body}"
    role_names = {r["name"] for r in body["roles"]}
    assert "owner" in role_names


def test_member_detail_returns_404_for_unknown_id(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.get("/api/iam/users/9999999", headers=headers)
    assert r.status_code == 404
    assert r.get_json()["error"] == "user_not_found"


def test_member_detail_returns_401_without_jwt(client, flask_app, test_user):
    _reset_limiter(flask_app)
    r = client.get(f"/api/iam/users/{test_user.id}")
    assert r.status_code == 401


# --- POST /api/iam/users/<id>/disable ------------------------------

def test_disable_user_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Plant a non-owner second user we can safely disable.
    target = _create_user("disable-happy")
    try:
        r = client.post(
            f"/api/iam/users/{target.id}/disable",
            headers=headers,
            data=json.dumps({"reason": "happy-path test"}),
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["id"] == target.id
        assert body["is_active"] is False

        # Audit row written.
        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.disabled",
        ).all()
        assert len(audit) == 1
        assert audit[0].node_meta == {"reason": "happy-path test"}
    finally:
        _delete_user(target)


def test_disable_user_idempotent_no_extra_audit(client, flask_app, test_user):
    """Calling disable twice -> 200 each time, exactly ONE audit row."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    target = _create_user("disable-idempotent")
    try:
        r1 = client.post(
            f"/api/iam/users/{target.id}/disable",
            headers=headers,
            data=json.dumps({"reason": "first call"}),
        )
        assert r1.status_code == 200
        r2 = client.post(
            f"/api/iam/users/{target.id}/disable",
            headers=headers,
            data=json.dumps({"reason": "second call"}),
        )
        assert r2.status_code == 200

        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.disabled",
        ).all()
        assert len(audit) == 1, (
            f"expected exactly 1 disable audit row; got {len(audit)} "
            f"(idempotent path should not write an audit entry)"
        )
        assert audit[0].node_meta == {"reason": "first call"}
    finally:
        _delete_user(target)


def test_disable_user_returns_404_for_unknown(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.post("/api/iam/users/9999999/disable", headers=headers,
                    data=json.dumps({"reason": "nope"}))
    assert r.status_code == 404


def test_disable_blocks_last_active_owner(client, flask_app, test_user):
    """test_user has owner. No other active owner exists. Disabling
    test_user must return 400 last_owner."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Make sure no OTHER active owner is around. Demote any extra
    # owners by removing their UserRole rows. (The session-scoped
    # SQLite test DB only has test_user as the active owner, but
    # other tests may have planted owners; clean defensively.)
    owner_role = Role.query.filter_by(name='owner').first()
    _UR.query.filter(
        _UR.role_id == owner_role.id,
        _UR.user_id != test_user.id,
    ).delete()
    db.session.commit()

    assert _is_last_owner(test_user.id) is True

    r = client.post(
        f"/api/iam/users/{test_user.id}/disable",
        headers=headers,
        data=json.dumps({"reason": "should be blocked"}),
    )
    assert r.status_code == 400, r.data
    body = r.get_json()
    assert body["error"] == "last_owner"

    # No audit row written for the blocked attempt.
    audit = AuditLog.query.filter_by(
        resource=f"user:{test_user.id}",
        action="user.disabled",
    ).count()
    assert audit == 0


def test_disable_allows_owner_when_other_active_owner_exists(
    client, flask_app, test_user
):
    """A second active+owner user exists, so disabling test_user
    is permitted (would not leave the platform without an owner)."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Plant a second active owner.
    second = _create_user("disable-second-owner")
    try:
        from dashboard.backend.iam.routes import assign_role_to_user
        assign_role_to_user(second.id, "owner",
                            assigned_by=test_user.id,
                            reason="test-second-owner",
                            emit_audit=False)
        db.session.commit()

        # Now there are two active owners. Disabling test_user is OK.
        r = client.post(
            f"/api/iam/users/{test_user.id}/disable",
            headers=headers,
            data=json.dumps({"reason": "second-owner exists"}),
        )
        # NOTE: this revokes JWT-future for test_user but the current
        # JWT is still valid until expiry; the response is the
        # disabled-state body.
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["is_active"] is False
    finally:
        # Restore test_user's active state for other tests.
        target = db.session.get(_User, test_user.id)
        target.is_active = True
        db.session.commit()
        _delete_user(second)


# --- POST /api/iam/users/<id>/enable -------------------------------

def test_enable_user_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    target = _create_user("enable-happy")
    try:
        # Disable first so enable has work to do.
        client.post(
            f"/api/iam/users/{target.id}/disable",
            headers=headers,
            data=json.dumps({"reason": "set up"}),
        )

        r = client.post(
            f"/api/iam/users/{target.id}/enable",
            headers=headers,
            data=json.dumps({"reason": "happy-path enable"}),
        )
        assert r.status_code == 200, r.data
        assert r.get_json()["is_active"] is True

        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.enabled",
        ).all()
        assert len(audit) == 1
        assert audit[0].node_meta == {"reason": "happy-path enable"}
    finally:
        _delete_user(target)


def test_enable_user_idempotent_no_extra_audit(client, flask_app, test_user):
    """Calling enable twice on an already-active user -> 200 each
    time, ZERO audit rows."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    target = _create_user("enable-idempotent")
    try:
        # Already active by default.
        r1 = client.post(
            f"/api/iam/users/{target.id}/enable",
            headers=headers,
            data=json.dumps({"reason": "first"}),
        )
        assert r1.status_code == 200
        r2 = client.post(
            f"/api/iam/users/{target.id}/enable",
            headers=headers,
            data=json.dumps({"reason": "second"}),
        )
        assert r2.status_code == 200

        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.enabled",
        ).count()
        assert audit == 0, (
            f"expected zero enable audit rows; got {audit} "
            f"(idempotent path on already-active should not write)"
        )
    finally:
        _delete_user(target)


def test_enable_user_returns_404_for_unknown(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.post("/api/iam/users/9999999/enable", headers=headers,
                    data=json.dumps({}))
    assert r.status_code == 404


# =============================================================
# Tier 1 v1 — sessions infra (IssuedToken blocklist) + remove +
# restore. Phase B § 6.1.5/6.1.6 + § 8 S1/S2/S3.
# =============================================================
from datetime import datetime as _dt, timezone as _tz, timedelta as _td
from flask_jwt_extended import create_access_token as _cat, decode_token as _decode
from dashboard.backend.iam.models import IssuedToken as _IssuedToken
from dashboard.backend.iam.routes import (
    cleanup_expired_tokens as _cleanup_expired,
)


def _record_token_for(user, expires_in_minutes=15):
    """Make a real JWT and an IssuedToken row pointing at it.
    Returns (token_str, jti). Mirrors what auth.login does in
    production but without going through HTTP. Conftest sets
    JWT_ACCESS_TOKEN_EXPIRES=False so created tokens have no `exp`
    claim; we synthesise expires_at locally to match the production
    helper's far-future placeholder."""
    token = _cat(identity=str(user.id),
                 expires_delta=_td(minutes=expires_in_minutes))
    decoded = _decode(token)
    jti = decoded["jti"]
    exp = decoded.get("exp")
    if exp:
        expires_at = _dt.fromtimestamp(exp, tz=_tz.utc)
    else:
        expires_at = _dt.now(_tz.utc) + _td(minutes=expires_in_minutes)
    db.session.add(_IssuedToken(
        jti        = jti,
        user_id    = user.id,
        issued_at  = _dt.now(_tz.utc),
        expires_at = expires_at,
        revoked    = False,
    ))
    db.session.commit()
    return token, jti


# --- IssuedToken model basic ---------------------------------------

def test_issued_token_model_round_trip(flask_app, test_user):
    """Insert + fetch + revoke + fetch again."""
    _IssuedToken.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    token, jti = _record_token_for(test_user, expires_in_minutes=15)
    fetched = _IssuedToken.query.filter_by(jti=jti).first()
    assert fetched is not None
    assert fetched.user_id == test_user.id
    assert fetched.revoked is False

    fetched.revoked       = True
    fetched.revoked_at    = _dt.now(_tz.utc)
    fetched.revoke_reason = "manual.revoke"
    db.session.commit()

    re = _IssuedToken.query.filter_by(jti=jti).first()
    assert re.revoked is True
    assert re.revoke_reason == "manual.revoke"


# --- Login records IssuedToken --------------------------------------

def test_login_records_issued_token(client, flask_app, test_user):
    """A successful POST /api/auth/login writes an IssuedToken
    row whose jti matches the returned access token."""
    _reset_limiter(flask_app)

    # Ensure test_user has a known password we can log in with.
    import bcrypt as _b
    target = _create_user("login-records", plan="free")
    target.password_hash = _b.hashpw(b"LoginRec123!",
                                     _b.gensalt()).decode("utf-8")
    db.session.commit()
    try:
        before = _IssuedToken.query.filter_by(user_id=target.id).count()
        r = client.post(
            "/api/auth/login",
            data=json.dumps({"email": target.email,
                             "password": "LoginRec123!"}),
            headers={"Content-Type":    "application/json",
                     "X-Forwarded-For": "10.42.8.1"},
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        token = body["token"]
        decoded = _decode(token)
        jti = decoded["jti"]

        after = _IssuedToken.query.filter_by(user_id=target.id).count()
        assert after == before + 1
        row = _IssuedToken.query.filter_by(jti=jti).first()
        assert row is not None
        assert row.user_id == target.id
        assert row.revoked is False
    finally:
        _delete_user(target)


# --- Blocklist callback rejects revoked tokens ---------------------

def test_blocklist_callback_rejects_revoked_token(client, flask_app, test_user):
    """A token with IssuedToken.revoked=True returns 401 from any
    @jwt_required endpoint. Pre-blocklist tokens (no row) keep
    working -- that's the graceful upgrade path."""
    _reset_limiter(flask_app)

    target = _create_user("blocklist", plan="free")
    try:
        token, jti = _record_token_for(target)

        # Token works now.
        r1 = client.get(
            "/api/iam/users/" + str(target.id),
            headers={"Authorization": f"Bearer {token}"},
        )
        # Caller is target user; iam:manage required by detail
        # handler. Without the owner role assignment, expect 403,
        # NOT 401. That tells us the JWT was accepted (not blocklisted).
        assert r1.status_code in (200, 403), r1.data

        # Mark revoked.
        row = _IssuedToken.query.filter_by(jti=jti).first()
        row.revoked    = True
        row.revoked_at = _dt.now(_tz.utc)
        row.revoke_reason = "manual.revoke"
        db.session.commit()

        # Same endpoint, same token, now MUST be 401.
        r2 = client.get(
            "/api/iam/users/" + str(target.id),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 401, (
            f"revoked token must 401, got {r2.status_code}: {r2.data}"
        )
    finally:
        _IssuedToken.query.filter_by(user_id=target.id).delete()
        db.session.commit()
        _delete_user(target)


def test_blocklist_callback_allows_pre_blocklist_token(client, flask_app, test_user):
    """A token issued via create_access_token without an IssuedToken
    row (the "pre-blocklist" case the graceful upgrade path
    protects) is accepted by the blocklist callback as valid."""
    _reset_limiter(flask_app)
    target = _create_user("pre-blocklist", plan="free")
    try:
        token = _cat(identity=str(target.id))
        # Crucially: NO IssuedToken row written.
        r = client.get(
            "/api/iam/users/" + str(target.id),
            headers={"Authorization": f"Bearer {token}"},
        )
        # 200 (owner) or 403 (no role) both prove the JWT was
        # accepted by the blocklist callback. We only fail on 401.
        assert r.status_code != 401, r.data
    finally:
        _delete_user(target)


# --- Remove: revokes tokens, audit, last-owner safety --------------

def test_remove_user_revokes_all_tokens(client, flask_app, test_user):
    """POST /remove flips removed_at + is_active AND mass-revokes
    every outstanding IssuedToken row for the target."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    target = _create_user("remove-revoke", plan="free")
    try:
        # Plant 3 tokens for this user.
        jtis = []
        for _ in range(3):
            _, jti = _record_token_for(target)
            jtis.append(jti)

        r = client.post(
            f"/api/iam/users/{target.id}/remove",
            headers=headers,
            data=json.dumps({"reason": "test-revoke"}),
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["removed_at"] is not None
        assert body["is_active"] is False

        # All three tokens must now be revoked.
        for jti in jtis:
            row = _IssuedToken.query.filter_by(jti=jti).first()
            assert row.revoked is True
            assert row.revoke_reason == "user.removed"
            assert row.revoked_at is not None

        # Audit row written with sessions_revoked count.
        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.removed",
        ).first()
        assert audit is not None
        assert audit.node_meta.get("sessions_revoked") == 3
    finally:
        _IssuedToken.query.filter_by(user_id=target.id).delete()
        db.session.commit()
        _delete_user(target)


def test_remove_user_idempotent(client, flask_app, test_user):
    """Calling remove twice -> 200 each time, exactly ONE audit row,
    no second mass-revoke pass."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    target = _create_user("remove-idemp", plan="free")
    try:
        r1 = client.post(
            f"/api/iam/users/{target.id}/remove",
            headers=headers,
            data=json.dumps({"reason": "first"}),
        )
        assert r1.status_code == 200
        r2 = client.post(
            f"/api/iam/users/{target.id}/remove",
            headers=headers,
            data=json.dumps({"reason": "second"}),
        )
        assert r2.status_code == 200

        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.removed",
        ).all()
        assert len(audit) == 1, (
            f"expected 1 user.removed audit row across 2 calls; "
            f"got {len(audit)}"
        )
    finally:
        _IssuedToken.query.filter_by(user_id=target.id).delete()
        db.session.commit()
        _delete_user(target)


def test_remove_blocks_last_active_owner(client, flask_app, test_user):
    """test_user is the only active+present owner. /remove must 400."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    # Sweep any other owners away.
    owner_role = Role.query.filter_by(name="owner").first()
    UserRole.query.filter(
        UserRole.role_id  == owner_role.id,
        UserRole.user_id  != test_user.id,
    ).delete()
    db.session.commit()

    r = client.post(
        f"/api/iam/users/{test_user.id}/remove",
        headers=headers,
        data=json.dumps({"reason": "should be blocked"}),
    )
    assert r.status_code == 400, r.data
    body = r.get_json()
    assert body["error"] == "last_owner"


def test_remove_user_returns_404_for_unknown(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.post("/api/iam/users/9999999/remove",
                    headers=headers, data=json.dumps({}))
    assert r.status_code == 404


# --- Restore -------------------------------------------------------

def test_restore_user_happy_path(client, flask_app, test_user):
    """A removed user can be restored. removed_at -> NULL,
    is_active -> True, audit row written. Pre-existing IssuedToken
    rows stay revoked (secure default; restored user must log in
    fresh)."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)

    target = _create_user("restore-happy", plan="free")
    try:
        # Plant a token, remove the user, capture the token jti.
        _, jti = _record_token_for(target)
        client.post(
            f"/api/iam/users/{target.id}/remove",
            headers=headers,
            data=json.dumps({"reason": "set up"}),
        )
        # Confirm token is revoked.
        assert _IssuedToken.query.filter_by(jti=jti).first().revoked is True

        # Restore.
        r = client.post(
            f"/api/iam/users/{target.id}/restore",
            headers=headers,
            data=json.dumps({"reason": "happy-path restore"}),
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["removed_at"] is None
        assert body["is_active"] is True

        # The old token MUST stay revoked -- secure default.
        assert _IssuedToken.query.filter_by(jti=jti).first().revoked is True

        # Audit row written.
        audit = AuditLog.query.filter_by(
            resource=f"user:{target.id}",
            action="user.restored",
        ).first()
        assert audit is not None
        assert audit.node_meta == {"reason": "happy-path restore"}
    finally:
        _IssuedToken.query.filter_by(user_id=target.id).delete()
        db.session.commit()
        _delete_user(target)


def test_restore_already_active_returns_400(client, flask_app, test_user):
    """Calling /restore on a non-removed user returns 400."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    target = _create_user("restore-no-op", plan="free")
    try:
        r = client.post(
            f"/api/iam/users/{target.id}/restore",
            headers=headers,
            data=json.dumps({"reason": "no-op safety"}),
        )
        assert r.status_code == 400, r.data
        body = r.get_json()
        assert body["error"] == "not_removed"
    finally:
        _delete_user(target)


def test_restore_user_returns_404_for_unknown(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.post("/api/iam/users/9999999/restore",
                    headers=headers, data=json.dumps({}))
    assert r.status_code == 404


# --- cleanup_expired_tokens helper ---------------------------------

def test_cleanup_expired_tokens(flask_app, test_user):
    """Helper deletes expired non-revoked rows; keeps revoked rows."""
    _IssuedToken.query.filter_by(user_id=test_user.id).delete()
    db.session.commit()

    now = _dt.now(_tz.utc)

    # Three rows: one active (not expired), one expired+not-revoked
    # (should be deleted), one expired+revoked (kept).
    db.session.add(_IssuedToken(
        jti="cleanup-active-" + _uuid_iam.uuid4().hex[:8],
        user_id=test_user.id, issued_at=now,
        expires_at=now + _td(minutes=15), revoked=False,
    ))
    db.session.add(_IssuedToken(
        jti="cleanup-expired-noerev-" + _uuid_iam.uuid4().hex[:8],
        user_id=test_user.id, issued_at=now - _td(hours=2),
        expires_at=now - _td(hours=1), revoked=False,
    ))
    db.session.add(_IssuedToken(
        jti="cleanup-expired-revoked-" + _uuid_iam.uuid4().hex[:8],
        user_id=test_user.id, issued_at=now - _td(hours=2),
        expires_at=now - _td(hours=1), revoked=True,
        revoked_at=now - _td(hours=1, minutes=30),
        revoke_reason="manual.revoke",
    ))
    db.session.commit()

    deleted = _cleanup_expired()
    assert deleted >= 1
    remaining = _IssuedToken.query.filter_by(user_id=test_user.id).all()
    # Active + revoked-expired remain. Non-revoked-expired gone.
    revoke_states = sorted(r.revoked for r in remaining)
    assert revoke_states == [False, True], remaining


# =============================================================
# Tier 1 v1 — invitations (Phase B § 8 I1-I4)
# =============================================================
from unittest.mock import patch as _patch
from dashboard.backend.iam.models import Invitation as _Invitation
from dashboard.backend.iam.routes import (
    expire_pending_invitations as _expire_pending,
    INVITATION_RESEND_MAX as _RESEND_MAX,
)


def _create_test_role(name="viewer"):
    """Ensure a role exists in the test DB; return it."""
    seed_default_roles()
    return Role.query.filter_by(name=name).first()


def _make_invitation(test_user, email_suffix, role_name="viewer",
                     status="pending", expires_in_days=7):
    """Insert an invitation row directly (bypassing the API). Used
    for tests that need a known starting state."""
    role = _create_test_role(role_name)
    inv = _Invitation(
        email      = f"inv-{email_suffix}-{_uuid_iam.uuid4().hex[:6]}@aipet.local",
        token      = "test-token-" + _uuid_iam.uuid4().hex,
        role_id    = role.id,
        invited_by = test_user.id,
        invited_at = _dt.now(_tz.utc),
        expires_at = _dt.now(_tz.utc) + _td(days=expires_in_days),
        status     = status,
    )
    db.session.add(inv)
    db.session.commit()
    return inv


def _delete_invitation(inv):
    db.session.delete(inv)
    db.session.commit()


# --- Invitation model ---------------------------------------------

def test_invitation_model_round_trip(flask_app, test_user):
    inv = _make_invitation(test_user, "model-rt")
    try:
        re = _Invitation.query.filter_by(id=inv.id).first()
        assert re is not None
        assert re.email == inv.email
        assert re.status == "pending"
        assert re.resend_count == 0
        assert re.role_id == inv.role_id
        # Token unique constraint via DB index.
        assert _Invitation.query.filter_by(token=inv.token).count() == 1
    finally:
        _delete_invitation(inv)


# --- POST /api/iam/invitations -------------------------------------

def test_invite_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _create_test_role("viewer")

    test_email = f"invite-happy-{_uuid_iam.uuid4().hex[:6]}@aipet.local"
    # Patch the email sender so tests don't try real SMTP.
    with _patch("dashboard.backend.iam.routes._send_invitation_email",
                return_value=True) as mock_send:
        r = client.post(
            "/api/iam/invitations",
            headers=headers,
            data=json.dumps({"email": test_email, "role_name": "viewer"}),
        )
    assert r.status_code == 201, r.data
    body = r.get_json()
    # Token MUST NOT appear in any response field.
    assert "token" not in body, "token leaked in API response"
    assert body["email"] == test_email
    assert body["role"] == "viewer"
    assert body["status"] == "pending"
    assert body["email_delivered"] is True
    assert mock_send.called

    # Audit row written.
    audit = AuditLog.query.filter_by(
        resource=f"invitation:{body['id']}",
        action="invitation.created",
    ).first()
    assert audit is not None
    assert audit.node_meta["email"] == test_email
    assert audit.node_meta["role"] == "viewer"

    # Cleanup.
    _Invitation.query.filter_by(id=body["id"]).delete()
    AuditLog.query.filter_by(resource=f"invitation:{body['id']}").delete()
    db.session.commit()


def test_invite_rejects_existing_user_email(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _create_test_role("viewer")

    with _patch("dashboard.backend.iam.routes._send_invitation_email",
                return_value=True):
        r = client.post(
            "/api/iam/invitations",
            headers=headers,
            data=json.dumps({"email": test_user.email, "role_name": "viewer"}),
        )
    assert r.status_code == 400
    assert r.get_json()["error"] == "user_exists"


def test_invite_rejects_duplicate_pending(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _create_test_role("viewer")

    test_email = f"invite-dup-{_uuid_iam.uuid4().hex[:6]}@aipet.local"
    with _patch("dashboard.backend.iam.routes._send_invitation_email",
                return_value=True):
        r1 = client.post(
            "/api/iam/invitations",
            headers=headers,
            data=json.dumps({"email": test_email, "role_name": "viewer"}),
        )
        assert r1.status_code == 201
        r2 = client.post(
            "/api/iam/invitations",
            headers=headers,
            data=json.dumps({"email": test_email, "role_name": "viewer"}),
        )
    assert r2.status_code == 400
    body = r2.get_json()
    assert body["error"] == "duplicate_pending"
    assert body["invitation_id"]

    # Cleanup the one we created.
    inv_id = r1.get_json()["id"]
    _Invitation.query.filter_by(id=inv_id).delete()
    AuditLog.query.filter_by(resource=f"invitation:{inv_id}").delete()
    db.session.commit()


def test_invite_rejects_invalid_role(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    test_email = f"invite-badrole-{_uuid_iam.uuid4().hex[:6]}@aipet.local"
    r = client.post(
        "/api/iam/invitations",
        headers=headers,
        data=json.dumps({"email": test_email, "role_name": "nope"}),
    )
    assert r.status_code == 400
    assert r.get_json()["error"] == "role_not_found"


def test_invite_rejects_invalid_email(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    r = client.post(
        "/api/iam/invitations",
        headers=headers,
        data=json.dumps({"email": "not-an-email", "role_name": "viewer"}),
    )
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid_email"


def test_invite_email_send_failure_persists_invitation(client, flask_app, test_user):
    """Best-effort email delivery: if SMTP fails, the invitation row
    persists (status=pending, can be resent), the API returns 201
    with email_delivered=false."""
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    _create_test_role("viewer")

    test_email = f"invite-smtpfail-{_uuid_iam.uuid4().hex[:6]}@aipet.local"
    with _patch("dashboard.backend.iam.routes._send_invitation_email",
                return_value=False) as mock_send:
        r = client.post(
            "/api/iam/invitations",
            headers=headers,
            data=json.dumps({"email": test_email, "role_name": "viewer"}),
        )
    assert r.status_code == 201
    body = r.get_json()
    assert body["email_delivered"] is False
    assert mock_send.called
    # Row persists.
    assert _Invitation.query.filter_by(id=body["id"]).first() is not None
    _Invitation.query.filter_by(id=body["id"]).delete()
    AuditLog.query.filter_by(resource=f"invitation:{body['id']}").delete()
    db.session.commit()


# --- GET /api/iam/invitations --------------------------------------

def test_invitations_list_default_status_pending(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv_p = _make_invitation(test_user, "list-pending", status="pending")
    inv_a = _make_invitation(test_user, "list-accepted", status="accepted")
    try:
        r = client.get("/api/iam/invitations", headers=headers)
        assert r.status_code == 200
        body = r.get_json()
        ids = [i["id"] for i in body["invitations"]]
        assert inv_p.id in ids
        assert inv_a.id not in ids
        # Token NEVER returned.
        for inv in body["invitations"]:
            assert "token" not in inv

        # status=all returns both.
        r2 = client.get("/api/iam/invitations?status=all", headers=headers)
        body2 = r2.get_json()
        ids2 = [i["id"] for i in body2["invitations"]]
        assert inv_p.id in ids2
        assert inv_a.id in ids2
    finally:
        _delete_invitation(inv_p)
        _delete_invitation(inv_a)


# --- POST /api/iam/invitations/<id>/resend ------------------------

def test_resend_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "resend-happy")
    try:
        with _patch("dashboard.backend.iam.routes._send_invitation_email",
                    return_value=True):
            r = client.post(
                f"/api/iam/invitations/{inv.id}/resend",
                headers=headers,
                data=json.dumps({}),
            )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["resend_count"] == 1
        assert body["last_resent_at"] is not None
    finally:
        _delete_invitation(inv)


def test_resend_max_count_returns_429(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "resend-max")
    # Pre-set resend_count to the cap so the next call exceeds.
    inv.resend_count = _RESEND_MAX
    inv.last_resent_at = _dt.now(_tz.utc) - _td(hours=2)  # past cooldown
    db.session.commit()
    try:
        with _patch("dashboard.backend.iam.routes._send_invitation_email",
                    return_value=True):
            r = client.post(
                f"/api/iam/invitations/{inv.id}/resend",
                headers=headers,
                data=json.dumps({}),
            )
        assert r.status_code == 429
        assert r.get_json()["error"] == "resend_limit_exceeded"
    finally:
        _delete_invitation(inv)


def test_resend_cooldown_returns_429(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "resend-cool")
    inv.resend_count = 1
    inv.last_resent_at = _dt.now(_tz.utc)  # just now
    db.session.commit()
    try:
        with _patch("dashboard.backend.iam.routes._send_invitation_email",
                    return_value=True):
            r = client.post(
                f"/api/iam/invitations/{inv.id}/resend",
                headers=headers,
                data=json.dumps({}),
            )
        assert r.status_code == 429
        assert r.get_json()["error"] == "resend_cooldown"
    finally:
        _delete_invitation(inv)


def test_resend_rejects_non_pending(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "resend-nonpend", status="accepted")
    try:
        r = client.post(
            f"/api/iam/invitations/{inv.id}/resend",
            headers=headers,
            data=json.dumps({}),
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "not_pending"
    finally:
        _delete_invitation(inv)


# --- POST /api/iam/invitations/<id>/revoke ------------------------

def test_revoke_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "revoke-happy")
    try:
        r = client.post(
            f"/api/iam/invitations/{inv.id}/revoke",
            headers=headers,
            data=json.dumps({"reason": "no longer needed"}),
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] == "revoked"
        assert body["revoked_at"] is not None

        # Audit row written.
        audit = AuditLog.query.filter_by(
            resource=f"invitation:{inv.id}",
            action="invitation.revoked",
        ).first()
        assert audit is not None
        assert audit.node_meta == {"reason": "no longer needed"}
    finally:
        AuditLog.query.filter_by(resource=f"invitation:{inv.id}").delete()
        _delete_invitation(inv)


def test_revoke_rejects_accepted_invitation(client, flask_app, test_user):
    _reset_limiter(flask_app)
    headers = _owner_headers(flask_app, test_user)
    inv = _make_invitation(test_user, "revoke-accept", status="accepted")
    try:
        r = client.post(
            f"/api/iam/invitations/{inv.id}/revoke",
            headers=headers,
            data=json.dumps({}),
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "already_accepted"
    finally:
        _delete_invitation(inv)


# --- POST /api/auth/accept-invitation -----------------------------

def test_accept_invitation_happy_path(client, flask_app, test_user):
    _reset_limiter(flask_app)
    inv = _make_invitation(test_user, "accept-happy")
    try:
        r = client.post(
            "/api/auth/accept-invitation",
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "10.42.9.1"},
            data=json.dumps({
                "token":    inv.token,
                "name":     "Accept Test User",
                "password": "AcceptTest123!",
            }),
        )
        assert r.status_code == 201, r.data
        body = r.get_json()
        assert body["token"]  # JWT issued
        assert body["role"] == "viewer"
        new_user_id = body["user"]["id"]

        # New user exists with viewer role.
        u = db.session.get(_User, new_user_id)
        assert u is not None
        assert u.email == inv.email
        roles = (db.session.query(Role)
                 .join(UserRole, UserRole.role_id == Role.id)
                 .filter(UserRole.user_id == new_user_id).all())
        assert "viewer" in {r.name for r in roles}

        # Invitation marked accepted.
        re = _Invitation.query.filter_by(id=inv.id).first()
        assert re.status == "accepted"
        assert re.accepted_by == new_user_id

        # Cleanup. AuditLog rows for the new user span THREE
        # distinct shapes:
        #   (a) user_id = new_user_id (events the user authored)
        #   (b) resource = f"invitation:{inv.id}" (the invitation
        #       events themselves)
        #   (c) resource = f"user:{new_user_id}" (the role.assigned
        #       written by assign_role_to_user, whose user_id field
        #       is the inviter, NOT the new user) -- this is the
        #       row that bleeds into test_iam_seed.py if missed,
        #       because SQLite reuses the deleted user's id.
        UserRole.query.filter_by(user_id=new_user_id).delete()
        AuditLog.query.filter(
            (AuditLog.user_id == new_user_id) |
            (AuditLog.resource == f"invitation:{inv.id}") |
            (AuditLog.resource == f"user:{new_user_id}")
        ).delete(synchronize_session=False)
        _IssuedToken.query.filter_by(user_id=new_user_id).delete()
        db.session.delete(u)
        db.session.commit()
    finally:
        _delete_invitation(inv)


def test_accept_invitation_expired(client, flask_app, test_user):
    _reset_limiter(flask_app)
    inv = _make_invitation(test_user, "accept-expired")
    inv.expires_at = _dt.now(_tz.utc) - _td(hours=1)
    db.session.commit()
    try:
        r = client.post(
            "/api/auth/accept-invitation",
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "10.42.9.2"},
            data=json.dumps({
                "token":    inv.token,
                "name":     "Expired Test",
                "password": "ExpiredTest123!",
            }),
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "expired"
        # Status now 'expired' (lazy transition).
        re = _Invitation.query.filter_by(id=inv.id).first()
        assert re.status == "expired"
    finally:
        _delete_invitation(inv)


def test_accept_invitation_already_used(client, flask_app, test_user):
    _reset_limiter(flask_app)
    inv = _make_invitation(test_user, "accept-used", status="accepted")
    try:
        r = client.post(
            "/api/auth/accept-invitation",
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "10.42.9.3"},
            data=json.dumps({
                "token":    inv.token,
                "name":     "Replay Test",
                "password": "ReplayTest123!",
            }),
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "already_accepted"
    finally:
        _delete_invitation(inv)


def test_accept_invitation_email_collision(client, flask_app, test_user):
    """Race: a user registers with the invitation's email between
    invite and accept. The accept endpoint must 409 with a
    distinguishable error code."""
    _reset_limiter(flask_app)
    inv = _make_invitation(test_user, "accept-collide")

    # Plant a User with the SAME email.
    collision_user = _User(
        email         = inv.email,
        password_hash = _bcrypt.hashpw(
            b"Collide123!", _bcrypt.gensalt()).decode("utf-8"),
        name          = "Collision",
        plan          = "free",
        is_active     = True,
    )
    db.session.add(collision_user)
    db.session.commit()
    try:
        r = client.post(
            "/api/auth/accept-invitation",
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "10.42.9.4"},
            data=json.dumps({
                "token":    inv.token,
                "name":     "Collision Test",
                "password": "CollisionTest123!",
            }),
        )
        assert r.status_code == 409
        assert r.get_json()["error"] == "email_collision"
    finally:
        AuditLog.query.filter_by(user_id=collision_user.id).delete()
        db.session.delete(collision_user)
        _delete_invitation(inv)


def test_accept_invitation_invalid_token(client, flask_app):
    _reset_limiter(flask_app)
    r = client.post(
        "/api/auth/accept-invitation",
        headers={"Content-Type": "application/json",
                 "X-Forwarded-For": "10.42.9.5"},
        data=json.dumps({
            "token":    "nope-this-token-does-not-exist",
            "name":     "X",
            "password": "Xpassword123!",
        }),
    )
    assert r.status_code == 404
    assert r.get_json()["error"] == "invitation_not_found"


def test_accept_invitation_weak_password(client, flask_app, test_user):
    _reset_limiter(flask_app)
    inv = _make_invitation(test_user, "accept-weak")
    try:
        r = client.post(
            "/api/auth/accept-invitation",
            headers={"Content-Type": "application/json",
                     "X-Forwarded-For": "10.42.9.6"},
            data=json.dumps({
                "token":    inv.token,
                "name":     "Weak",
                "password": "1234",
            }),
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "weak_password"
    finally:
        _delete_invitation(inv)


# --- expire_pending_invitations() helper --------------------------

def test_expire_pending_invitations(flask_app, test_user):
    """Helper transitions only past-expiry pending rows to expired.
    Already-accepted and not-yet-expired stay untouched."""
    inv_expired   = _make_invitation(test_user, "exp-old", status="pending")
    inv_expired.expires_at = _dt.now(_tz.utc) - _td(hours=1)
    inv_active    = _make_invitation(test_user, "exp-fresh", status="pending",
                                     expires_in_days=7)
    inv_accepted  = _make_invitation(test_user, "exp-acc", status="accepted")
    inv_accepted.expires_at = _dt.now(_tz.utc) - _td(hours=1)  # expired but accepted
    db.session.commit()
    try:
        transitioned = _expire_pending()
        assert transitioned >= 1
        assert _Invitation.query.filter_by(id=inv_expired.id).first().status == "expired"
        assert _Invitation.query.filter_by(id=inv_active.id).first().status == "pending"
        # Accepted stays accepted regardless of expiry.
        assert _Invitation.query.filter_by(id=inv_accepted.id).first().status == "accepted"
    finally:
        _delete_invitation(inv_expired)
        _delete_invitation(inv_active)
        _delete_invitation(inv_accepted)
