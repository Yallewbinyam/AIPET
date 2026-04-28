# =============================================================
# AIPET X — Pytest fixtures (pilot: established by ml_anomaly)
# Copy this pattern for every new module's test file.
#
# Env vars are set BEFORE any project import so the app factory
# picks them up when it reads config.py.
# =============================================================
import os

os.environ.setdefault("JWT_SECRET_KEY",              "test-jwt-secret-key-for-aipet-x-pytest-testing-only")
os.environ.setdefault("SECRET_KEY",                  "test-flask-secret-key-for-aipet-x-pytest")
os.environ.setdefault("DATABASE_URL",                "sqlite:///:memory:")
os.environ.setdefault("SENTRY_DSN",                  "")
os.environ.setdefault("STRIPE_SECRET_KEY",           "sk_test_placeholder")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET",       "whsec_placeholder")
# Use in-process memory storage for rate limits in tests — prevents the test
# Flask-Limiter from sharing Redis counters with the running production server.
os.environ.setdefault("FLASK_LIMITER_STORAGE_URI",   "memory://")
os.environ.setdefault("GOOGLE_CLIENT_ID",       "placeholder")
os.environ.setdefault("GOOGLE_CLIENT_SECRET",   "placeholder")
os.environ.setdefault("MAIL_USERNAME",          "")
os.environ.setdefault("MAIL_PASSWORD",          "")
# PLB-4: ensure tests do NOT inherit real SMTP creds from a developer's
# .env. The session flask_app boots with email_enabled=False; tests that
# need email_enabled=True construct their own Flask app via init_email().
os.environ["SMTP_USER"]      = ""
os.environ["SMTP_PASSWORD"]  = ""
os.environ["SMTP_HOST"]      = "smtp.gmail.com"
os.environ["SMTP_PORT"]      = "587"
os.environ["SMTP_FROM_NAME"] = "AIPET X Test Suite"

import pytest
from sqlalchemy.pool import StaticPool
from flask_jwt_extended import create_access_token

from dashboard.backend.app_cloud import create_app
from dashboard.backend.models import db as _db


@pytest.fixture(scope="session")
def flask_app():
    """
    Session-scoped app with in-memory SQLite.
    StaticPool ensures all connections share the same DB.
    Rate limiting is disabled so limit tests don't bleed across runs.
    """
    app = create_app("testing")
    app.config.update({
        "TESTING":                True,
        "DEBUG":                  True,   # bypasses force_https in app_cloud.py
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"check_same_thread": False},
            "poolclass":    StaticPool,
        },
        "RATELIMIT_ENABLED": False,
        "JWT_ACCESS_TOKEN_EXPIRES": False,   # tokens never expire in tests
    })

    ctx = app.app_context()
    ctx.push()
    _db.create_all()

    yield app

    _db.drop_all()
    ctx.pop()


@pytest.fixture(scope="session")
def client(flask_app):
    """Flask test client. Reused for the whole session."""
    return flask_app.test_client()


@pytest.fixture(scope="session")
def test_user(flask_app):
    """
    Inserts a test user once. Email: test-pytest@aipet.io
    plan=enterprise so all endpoints are accessible.
    """
    from dashboard.backend.models import User
    u = User(
        email         = "test-pytest@aipet.io",
        password_hash = "x",
        name          = "PyTest User",
        plan          = "enterprise",
    )
    _db.session.add(u)
    _db.session.commit()
    yield u


@pytest.fixture(scope="session")
def auth_headers(flask_app, test_user):
    """
    JWT bearer token for test_user.
    Identity is str(user.id) — matches the pattern in auth/routes.py.
    """
    token = create_access_token(identity=str(test_user.id))
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
