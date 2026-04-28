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
