# =============================================================
# AIPET X — PLB-4 email backend tests
#
# Verifies the SMTP wiring and graceful-degradation contract:
#   1. init_email() with SMTP creds set  -> email_enabled=True
#   2. init_email() without SMTP creds   -> email_enabled=False (no crash)
#   3. forgot-password actually invokes Flask-Mail when configured
#   4. forgot-password short-circuits with a WARNING log when disabled
#   5. SMTP_PASSWORD never appears in init logs (PLB-5 scrubber denylist
#      protects Sentry; this test pins the in-process logging behaviour)
# =============================================================
from __future__ import annotations

import logging
import os
import sys
import json
from unittest.mock import patch

import pytest
from flask import Flask

from dashboard.backend.observability.email_setup import (
    init_email,
    email_status,
    _resolve_default_sender,
)


# --- Helpers --------------------------------------------------------

def _make_isolated_app(env_overrides: dict) -> Flask:
    """Construct a bare Flask app and run init_email() against it under
    a controlled os.environ. Avoids touching the session-scoped fixture
    so each test sees a fresh enabled/disabled state."""
    app = Flask(__name__)
    # Save + patch env, run init_email, restore.
    saved = {k: os.environ.get(k) for k in env_overrides}
    try:
        for k, v in env_overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        init_email(app)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return app


# --- Test 1: init with SMTP set ------------------------------------

def test_email_backend_initialises_with_smtp_set():
    app = _make_isolated_app({
        "SMTP_USER":     "sender@example.com",
        "SMTP_PASSWORD": "fake-password-not-real",
        "SMTP_HOST":     "smtp.example.com",
        "SMTP_PORT":     "587",
        "SMTP_FROM_NAME": "AIPET Test",
    })
    assert app.email_enabled is True
    assert app.config["MAIL_SERVER"]   == "smtp.example.com"
    assert app.config["MAIL_PORT"]     == 587
    assert app.config["MAIL_USERNAME"] == "sender@example.com"
    # Default sender must include the display name + bracketed address.
    assert app.config["MAIL_DEFAULT_SENDER"] == "AIPET Test <sender@example.com>"
    # Flask-Mail must have bound to the app.
    assert "mail" in app.extensions

    # Public introspection helper must NOT leak the password.
    status = email_status(app)
    assert status["enabled"] is True
    assert "password" not in status
    for v in status.values():
        assert "fake-password-not-real" not in str(v)


# --- Test 2: init without SMTP creds -------------------------------

def test_email_backend_skips_init_with_smtp_unset():
    app = _make_isolated_app({
        "SMTP_USER":     "",
        "SMTP_PASSWORD": "",
        "SMTP_HOST":     "",
        "SMTP_PORT":     "587",
    })
    # Graceful degradation: app initialises, flag is False, no exception.
    assert app.email_enabled is False
    # Flask-Mail still binds (the extension is registered) -- it just
    # won't actually deliver because USERNAME / PASSWORD are empty.
    assert "mail" in app.extensions
    # email_status must report disabled but still expose the public knobs.
    status = email_status(app)
    assert status["enabled"] is False
    assert status["user_configured"] is False


# --- Test 3: forgot-password sends mail when enabled ---------------

def _reset_limiter(flask_app):
    """Wipe Flask-Limiter in-process counters so prior auth-tests'
    hits on /api/auth/forgot-password (3-per-hour) don't bleed into
    these tests. RATELIMIT_ENABLED=False in conftest is not honoured
    by Flask-Limiter 4.x once a limiter has been instantiated.

    Flask-Limiter 4.x stores a *set* of Limiter instances under
    app.extensions['limiter'], not a single object."""
    entry = flask_app.extensions.get("limiter")
    if entry is None:
        return
    items = entry if isinstance(entry, (set, list, tuple)) else (entry,)
    for lim in items:
        try:
            lim.reset()
        except Exception:
            # Some storage backends raise NotImplementedError on reset.
            # Best-effort: just continue.
            pass


def test_forgot_password_invokes_mail_send_when_configured(client, flask_app):
    """Force email_enabled=True on the session app, mock Mail.send,
    POST /api/auth/forgot-password for an existing user, assert send
    was called once with the expected recipient."""
    from dashboard.backend.models import User, db
    _reset_limiter(flask_app)

    # Create the target user inside a nested transaction so the test
    # is self-contained.
    target_email = "fp-test@aipet.io"
    if not User.query.filter_by(email=target_email).first():
        u = User(
            email         = target_email,
            password_hash = "x",
            name          = "FP Test",
            plan          = "free",
        )
        db.session.add(u)
        db.session.commit()

    saved_enabled = getattr(flask_app, "email_enabled", False)
    flask_app.email_enabled = True
    try:
        with patch("flask_mail.Mail.send") as mock_send:
            r = client.post(
                "/api/auth/forgot-password",
                data=json.dumps({"email": target_email}),
                headers={
                    "Content-Type":    "application/json",
                    # Unique IP per test -- avoids forgot-password's
                    # 3/hour rate limit bleeding from test_auth.py.
                    "X-Forwarded-For": "10.42.4.1",
                },
            )
            assert r.status_code == 200
            assert mock_send.call_count == 1
            sent_msg = mock_send.call_args[0][0]
            # Flask-Mail Message has .recipients (list) and .subject.
            assert target_email in sent_msg.recipients
            assert "Password Reset" in sent_msg.subject
    finally:
        flask_app.email_enabled = saved_enabled


# --- Test 4: forgot-password short-circuits when disabled ----------

def test_forgot_password_logs_warning_when_unconfigured(client, flask_app, caplog):
    """email_enabled=False -- forgot-password must return the same
    enumeration-safe 200 message AND log a clear WARNING."""
    from dashboard.backend.models import User, db
    _reset_limiter(flask_app)

    target_email = "fp-disabled@aipet.io"
    if not User.query.filter_by(email=target_email).first():
        u = User(
            email         = target_email,
            password_hash = "x",
            name          = "FP Disabled",
            plan          = "free",
        )
        db.session.add(u)
        db.session.commit()

    saved_enabled = getattr(flask_app, "email_enabled", False)
    flask_app.email_enabled = False
    try:
        # The route uses current_app.logger, which is namespaced.
        # caplog.set_level on the root catches everything below.
        with caplog.at_level(logging.WARNING):
            with patch("flask_mail.Mail.send") as mock_send:
                r = client.post(
                    "/api/auth/forgot-password",
                    data=json.dumps({"email": target_email}),
                    headers={
                        "Content-Type":    "application/json",
                        # Unique IP per test -- see note above.
                        "X-Forwarded-For": "10.42.5.1",
                    },
                )
        assert r.status_code == 200
        # Generic enumeration-safe message returned.
        body = r.get_json()
        assert "If that email exists" in body.get("message", "")
        # Mail.send must NOT have been called.
        assert mock_send.call_count == 0
        # A WARNING line about the disabled backend must be present.
        warnings = [rec.getMessage() for rec in caplog.records
                    if rec.levelno >= logging.WARNING]
        assert any("email backend disabled" in m.lower() or
                   "smtp_user" in m.lower()
                   for m in warnings), \
            f"Expected disabled-backend warning; got: {warnings}"
    finally:
        flask_app.email_enabled = saved_enabled


# --- Test 5: SMTP_PASSWORD never logged ----------------------------

def test_smtp_password_not_in_init_logs(caplog):
    """init_email() logs host/port/user/sender on the enabled path.
    The password value MUST NOT appear in any log record."""
    secret = "ThisIsNotARealPasswordButLooksLikeOne123"
    with caplog.at_level(logging.WARNING):
        _make_isolated_app({
            "SMTP_USER":     "secret-user@example.com",
            "SMTP_PASSWORD": secret,
            "SMTP_HOST":     "smtp.example.com",
            "SMTP_PORT":     "587",
            "SMTP_FROM_NAME": "AIPET",
        })

    # Walk every captured record + its formatted message + raw args.
    for rec in caplog.records:
        msg = rec.getMessage()
        assert secret not in msg, f"SMTP_PASSWORD leaked into log: {msg!r}"
        # Defensive: also check the raw format args.
        if rec.args:
            for arg in (rec.args if isinstance(rec.args, tuple) else (rec.args,)):
                assert secret not in str(arg), \
                    f"SMTP_PASSWORD leaked via args: {arg!r}"


# --- Test 6 (bonus): _resolve_default_sender format ----------------

def test_default_sender_format():
    assert _resolve_default_sender("user@example.com", "AIPET X Notifications") \
        == "AIPET X Notifications <user@example.com>"
    # Blank display name -> bare address only.
    assert _resolve_default_sender("user@example.com", "") == "user@example.com"
    # Whitespace-only display name treated as blank.
    assert _resolve_default_sender("user@example.com", "   ") == "user@example.com"
    # Missing user defaults to noreply@aipet.io.
    assert _resolve_default_sender("", "AIPET") == "AIPET <noreply@aipet.io>"
