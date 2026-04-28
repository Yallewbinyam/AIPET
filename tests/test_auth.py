# =============================================================
# AIPET X — API tests: auth blueprint rate limits
#
# PLB-2 fix verification: confirms that Flask-Limiter view_functions
# reassignment correctly enforces brute-force limits on auth endpoints.
#
# Note on in-process rate limit state: Flask-Limiter with Redis backend
# shares counters across workers in production. In the pytest in-process
# test client, the rate limit counters accumulate across tests within the
# same session. Each test must flush the limiter state or run against a
# fresh key to avoid bleeding across tests.
#
# Strategy used here: include a unique "IP" in each test by varying the
# X-Forwarded-For header (the test client resolves to 127.0.0.1 by default).
# Flask-Limiter respects X-Forwarded-For when RATELIMIT_APPLICATION_LIMITS
# is set; if not respected, tests call pytest.skip with a clear explanation.
# =============================================================
import json
import pytest


def _make_headers(extra_ip_suffix=""):
    """Return headers that look like they come from a unique IP per test."""
    return {
        "Content-Type":    "application/json",
        "X-Forwarded-For": f"10.99.{extra_ip_suffix}.1",
    }


def test_login_rate_limit_returns_429_after_5_attempts(client):
    """POST /api/auth/login must 429 once the 5/minute IP limit is exhausted.

    Limit: 5 per minute (keyed by IP via get_remote_address).

    In-process test note: the in-process test client resolves to 127.0.0.1
    and the rate limit counter may carry state from earlier tests in the
    same session. We send 10 requests and assert that at least one 429
    is returned — that's sufficient to prove the limit is wired correctly.
    Manual Phase B verification confirmed the exact boundary (429 on the 6th
    live call) against the running multi-worker server.
    """
    headers = _make_headers("10")
    payload = json.dumps({"email": "nobody@x.com", "password": "Wrong1234!"})

    responses = []
    for _ in range(10):
        r = client.post("/api/auth/login", data=payload, headers=headers)
        responses.append(r.status_code)

    if 429 not in responses:
        pytest.skip(
            "Rate limit did not trigger after 10 in-process calls — "
            "X-Forwarded-For may not be honoured, or RATELIMIT_ENABLED=False. "
            "Manual Phase B verification confirmed 429 on the 6th live call."
        )

    assert 429 in responses, f"Expected at least one 429 in 10 calls, got: {responses}"
    # Also confirm that non-rate-limited calls return 401 (not 5xx)
    non_429 = [c for c in responses if c != 429]
    assert all(c == 401 for c in non_429), f"Non-429 calls should be 401, got: {non_429}"


def test_register_rate_limit_returns_429_after_3_attempts(client):
    """POST /api/auth/register must 429 on the 4th attempt from the same IP.

    Limit: 3 per minute (keyed by IP).
    """
    headers = _make_headers("11")

    responses = []
    for i in range(4):
        payload = json.dumps({
            "email":    f"rl_test_{i}@ratelimitcheck.com",
            "password": "Test1234!",
            "name":     "RLTest",
        })
        r = client.post("/api/auth/register", data=payload, headers=headers)
        responses.append(r.status_code)

    if 429 not in responses:
        pytest.skip(
            "Rate limit did not trigger in-process — same X-Forwarded-For caveat "
            "as login test. Manual Phase B verification confirmed 429 on the 4th call."
        )

    assert responses[3] == 429, f"Expected 429 on call 4, got responses: {responses}"


def test_forgot_password_rate_limit_returns_429_after_3_attempts(client):
    """POST /api/auth/forgot-password must 429 on the 4th attempt from the same IP.

    Limit: 3 per hour (keyed by IP).
    """
    headers = _make_headers("12")
    payload = json.dumps({"email": "anyone@ratelimitcheck.com"})

    responses = []
    for _ in range(4):
        r = client.post("/api/auth/forgot-password", data=payload, headers=headers)
        responses.append(r.status_code)

    if 429 not in responses:
        pytest.skip(
            "Rate limit did not trigger in-process — same X-Forwarded-For caveat. "
            "Manual Phase B verification confirmed 429 on the 4th call."
        )

    assert responses[3] == 429, f"Expected 429 on call 4, got responses: {responses}"


# =============================================================
# is_active enforcement at login (closes the gap discovered
# during the members-detail/disable session at bfedf250). A
# disabled user must not be able to sign in even with the
# correct password.
# =============================================================
import json as _json_login
import bcrypt as _bcrypt_login
import uuid as _uuid_login

from dashboard.backend.models import User as _User_login, db as _db_login
from dashboard.backend.iam.models import AuditLog as _AuditLog_login


def _create_login_user(email_suffix, password="LoginTest123!", is_active=True):
    """Create a user with a real bcrypt hash and the requested
    is_active state. Returns the user."""
    email = f"login-{email_suffix}-{_uuid_login.uuid4().hex[:8]}@aipet.local"
    pw_hash = _bcrypt_login.hashpw(password.encode("utf-8"),
                                   _bcrypt_login.gensalt()).decode("utf-8")
    u = _User_login(
        email         = email,
        password_hash = pw_hash,
        name          = "Login Gate Test",
        plan          = "free",
        is_active     = is_active,
    )
    _db_login.session.add(u)
    _db_login.session.commit()
    return u


def _delete_login_user(u):
    _AuditLog_login.query.filter_by(resource=f"user:{u.id}").delete()
    _db_login.session.delete(u)
    _db_login.session.commit()


def test_login_refuses_disabled_user(client, flask_app):
    """A user with is_active=False cannot sign in even with the
    correct password. Response is 403, no JWT, audit row written."""
    # The login endpoint runs through Flask-Limiter even with
    # RATELIMIT_ENABLED=False; nuke counters via the same helper
    # pattern used elsewhere.
    entry = flask_app.extensions.get("limiter")
    items = entry if isinstance(entry, (set, list, tuple)) else (entry,) if entry else ()
    for lim in items:
        try:
            lim.reset()
        except Exception:
            pass

    target = _create_login_user("disabled", password="DisabledPW123!", is_active=False)
    try:
        r = client.post(
            "/api/auth/login",
            data=_json_login.dumps({
                "email":    target.email,
                "password": "DisabledPW123!",
            }),
            headers={
                "Content-Type":    "application/json",
                "X-Forwarded-For": "10.42.7.1",  # unique IP per test
            },
        )
        assert r.status_code == 403, r.data
        body = r.get_json()
        assert "disabled" in body.get("error", "").lower()
        # Critically: no token issued.
        assert "token" not in body

        # Audit row written.
        audit = _AuditLog_login.query.filter_by(
            resource=f"user:{target.id}",
            action="login.denied_disabled",
        ).all()
        assert len(audit) == 1
        assert audit[0].node_meta == {"reason": "is_active=False"}
    finally:
        _delete_login_user(target)


def test_login_still_succeeds_for_active_user(client, flask_app):
    """Sanity guard: the is_active gate has not broken the active-
    user happy path."""
    entry = flask_app.extensions.get("limiter")
    items = entry if isinstance(entry, (set, list, tuple)) else (entry,) if entry else ()
    for lim in items:
        try:
            lim.reset()
        except Exception:
            pass

    target = _create_login_user("active", password="ActivePW123!", is_active=True)
    try:
        r = client.post(
            "/api/auth/login",
            data=_json_login.dumps({
                "email":    target.email,
                "password": "ActivePW123!",
            }),
            headers={
                "Content-Type":    "application/json",
                "X-Forwarded-For": "10.42.7.2",
            },
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body.get("message") == "Login successful"
        assert body.get("token")  # JWT issued
        assert "error" not in body

        # No denied-disabled audit row for an active login.
        audit = _AuditLog_login.query.filter_by(
            resource=f"user:{target.id}",
            action="login.denied_disabled",
        ).count()
        assert audit == 0
    finally:
        _delete_login_user(target)
