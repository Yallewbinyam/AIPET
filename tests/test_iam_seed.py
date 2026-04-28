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
