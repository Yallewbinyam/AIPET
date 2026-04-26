# =============================================================
# AIPET X — Agent API Key Auth
# Decorator + helpers for agent authentication via X-Agent-Key header.
# Completely separate from JWT (human) auth path.
# =============================================================

import secrets
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from flask import request, jsonify, g

KEY_FORMAT = "aipet_"
_PREFIX_RANDOM_LEN = 8  # random chars stored as prefix for fast DB lookup


def generate_api_key() -> tuple:
    """
    Returns (full_key, prefix, bcrypt_hash).
    full_key is shown ONCE at creation and never stored.
    prefix (aipet_ + 8 chars) is stored for fast lookup.
    bcrypt_hash is the at-rest representation.
    """
    raw = secrets.token_urlsafe(48)  # ~64 URL-safe chars
    full_key = f"{KEY_FORMAT}{raw}"
    prefix = full_key[: len(KEY_FORMAT) + _PREFIX_RANDOM_LEN]  # e.g. "aipet_abcd1234"
    key_hash = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()
    return full_key, prefix, key_hash


def verify_key(full_key: str):
    """
    Validates an agent API key.
    Returns the AgentApiKey row on success, None otherwise.
    Updates last_used_at, last_used_ip, use_count on success.

    Steps:
    1. Must start with KEY_FORMAT
    2. Extract prefix for indexed lookup
    3. Iterate candidates (usually 0–1 rows) and bcrypt-verify
    4. Reject if expired
    """
    from .models import AgentApiKey
    from ..models import db

    if not full_key or not full_key.startswith(KEY_FORMAT):
        return None

    prefix = full_key[: len(KEY_FORMAT) + _PREFIX_RANDOM_LEN]
    candidates = AgentApiKey.query.filter_by(key_prefix=prefix, enabled=True).all()

    for row in candidates:
        try:
            if not bcrypt.checkpw(full_key.encode(), row.key_hash.encode()):
                continue
        except Exception:
            continue

        # Check expiry
        if row.expires_at and row.expires_at < datetime.now(timezone.utc):
            return None

        # Update usage telemetry (best-effort)
        try:
            row.last_used_at = datetime.now(timezone.utc)
            row.last_used_ip = (request.remote_addr or "")[:64]
            row.use_count = (row.use_count or 0) + 1
            db.session.commit()
        except Exception:
            db.session.rollback()

        return row

    return None


def agent_or_jwt_required(*, scope: str = "agent", permissions: list = None):
    """
    Hybrid decorator: accepts EITHER a JWT (Authorization: Bearer …) OR
    an agent API key (X-Agent-Key: aipet_…).

    Resolution order:
      1. If X-Agent-Key header is present, validate it. On success, sets
         g.current_user_id = key.user_id, g.current_agent_key = key,
         g.auth_mode = "agent_key".
      2. Otherwise fall back to JWT. Sets g.current_user_id = jwt subject,
         g.current_agent_key = None, g.auth_mode = "jwt".
      3. If neither header is present and no JWT in cookie, returns 401.

    This is what /api/agent/telemetry needs so the same endpoint serves
    both interactive dashboard sessions (JWT) and the systemd-managed
    device agent (X-Agent-Key).
    """
    from functools import wraps as _wraps

    def decorator(fn):
        @_wraps(fn)
        def wrapped(*args, **kwargs):
            # Path 1: agent key
            api_key = request.headers.get("X-Agent-Key", "").strip()
            if api_key:
                key_row = verify_key(api_key)
                if not key_row:
                    return jsonify({"error": "Invalid or revoked agent key"}), 401
                if key_row.scope != scope:
                    return jsonify({"error": f"Key does not have required scope: {scope}"}), 403
                if permissions:
                    key_perms = key_row.permissions or []
                    missing = [p for p in permissions if p not in key_perms]
                    if missing:
                        return jsonify({"error": f"Key missing permissions: {missing}"}), 403
                g.current_agent_key = key_row
                g.current_user_id = key_row.user_id
                g.auth_mode = "agent_key"
                return fn(*args, **kwargs)

            # Path 2: JWT (defer the import so this module stays light)
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            try:
                verify_jwt_in_request()
            except Exception as exc:
                return jsonify({"error": "Authentication required (X-Agent-Key or Bearer JWT)"}), 401
            try:
                uid = int(get_jwt_identity())
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid JWT subject"}), 401
            g.current_agent_key = None
            g.current_user_id = uid
            g.auth_mode = "jwt"
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def agent_key_required(*, scope: str = "agent", permissions: list = None):
    """
    Decorator analog to @jwt_required for agent endpoints.
    Reads X-Agent-Key header, verifies, populates g.current_agent_key
    and g.current_user_id.

    Returns 401 if key is missing/invalid/revoked.
    Returns 403 if scope or permissions don't match.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            api_key = request.headers.get("X-Agent-Key", "").strip()
            if not api_key:
                return jsonify({"error": "Agent API key required (X-Agent-Key header)"}), 401

            key_row = verify_key(api_key)
            if not key_row:
                return jsonify({"error": "Invalid or revoked agent key"}), 401

            if key_row.scope != scope:
                return jsonify({"error": f"Key does not have required scope: {scope}"}), 403

            if permissions:
                key_perms = key_row.permissions or []
                missing = [p for p in permissions if p not in key_perms]
                if missing:
                    return jsonify({"error": f"Key missing permissions: {missing}"}), 403

            g.current_agent_key = key_row
            g.current_user_id = key_row.user_id
            return fn(*args, **kwargs)
        return wrapped
    return decorator
