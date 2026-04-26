# =============================================================
# AIPET X — Agent API Key Management Endpoints
# User-facing (JWT-protected): create, list, revoke, delete, usage.
# =============================================================

from datetime import datetime, timezone

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from ..models import db, User
from .models import AgentApiKey
from .auth import generate_api_key
from ..validation import validate_body, optional, is_safe_string

agent_keys_bp = Blueprint("agent_keys", __name__)

_VALID_PERMISSIONS = {"scan:write", "telemetry:write"}

_CREATE_SCHEMA = {
    "label":       lambda v: is_safe_string(v, 128) and len(str(v).strip()) >= 1,
    "permissions": optional(lambda v: isinstance(v, list) and all(p in _VALID_PERMISSIONS for p in v)),
    "expires_at":  optional(lambda v: is_safe_string(v, 64)),
}

_REVOKE_SCHEMA = {
    "reason": optional(lambda v: is_safe_string(v, 256)),
}


# ── POST /api/agent/keys ──────────────────────────────────

@agent_keys_bp.route("", methods=["POST"])
@jwt_required()
@validate_body(_CREATE_SCHEMA)
def create_agent_key():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(silent=True) or {}
    label = data["label"].strip()
    permissions = data.get("permissions") or ["scan:write", "telemetry:write"]
    expires_at_str = data.get("expires_at")

    # Max 20 active agent keys per user
    active_count = AgentApiKey.query.filter_by(user_id=user_id, enabled=True).count()
    if active_count >= 20:
        return jsonify({"error": "Maximum 20 active agent keys. Revoke an existing key first."}), 400

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({"error": "Invalid expires_at format. Use ISO 8601."}), 422

    full_key, prefix, key_hash = generate_api_key()

    key_row = AgentApiKey(
        user_id=user_id,
        label=label,
        key_prefix=prefix,
        key_hash=key_hash,
        scope="agent",
        permissions=permissions,
        enabled=True,
        expires_at=expires_at,
    )
    db.session.add(key_row)
    db.session.commit()

    return jsonify({
        "message": "Agent key created. Copy it now — it will NOT be shown again.",
        "id":           key_row.id,
        "label":        key_row.label,
        "full_key":     full_key,
        "key_prefix":   prefix,
        "permissions":  key_row.permissions,
        "scope":        key_row.scope,
        "created_at":   key_row.created_at.isoformat(),
        "expires_at":   key_row.expires_at.isoformat() if key_row.expires_at else None,
    }), 201


# ── GET /api/agent/keys ───────────────────────────────────

@agent_keys_bp.route("", methods=["GET"])
@jwt_required()
def list_agent_keys():
    user_id = int(get_jwt_identity())
    keys = (
        AgentApiKey.query
        .filter_by(user_id=user_id)
        .order_by(AgentApiKey.last_used_at.desc().nullslast(), AgentApiKey.created_at.desc())
        .all()
    )
    return jsonify({
        "keys": [k.to_dict() for k in keys],
        "total": len(keys),
        "active": sum(1 for k in keys if k.enabled),
    }), 200


# ── PUT /api/agent/keys/<id>/revoke ───────────────────────

@agent_keys_bp.route("/<int:key_id>/revoke", methods=["PUT"])
@jwt_required()
def revoke_agent_key(key_id):
    user_id = int(get_jwt_identity())
    key_row = AgentApiKey.query.filter_by(id=key_id, user_id=user_id).first()
    if not key_row:
        return jsonify({"error": "Agent key not found"}), 404

    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "")).strip()[:256] or None

    key_row.enabled = False
    key_row.revoked_at = datetime.now(timezone.utc)
    key_row.revoked_reason = reason
    db.session.commit()

    return jsonify({"message": f"Agent key '{key_row.label}' revoked.", "id": key_row.id}), 200


# ── DELETE /api/agent/keys/<id> ───────────────────────────

@agent_keys_bp.route("/<int:key_id>", methods=["DELETE"])
@jwt_required()
def delete_agent_key(key_id):
    user_id = int(get_jwt_identity())
    key_row = AgentApiKey.query.filter_by(id=key_id, user_id=user_id).first()
    if not key_row:
        return jsonify({"error": "Agent key not found"}), 404

    db.session.delete(key_row)
    db.session.commit()
    return jsonify({"deleted": True, "id": key_id}), 200


# ── GET /api/agent/keys/usage ─────────────────────────────

@agent_keys_bp.route("/usage", methods=["GET"])
@jwt_required()
def agent_keys_usage():
    from sqlalchemy import func
    user_id = int(get_jwt_identity())

    all_keys = AgentApiKey.query.filter_by(user_id=user_id).all()
    active = [k for k in all_keys if k.enabled]
    revoked = [k for k in all_keys if not k.enabled]

    # Top keys by use_count
    top = sorted(active, key=lambda k: k.use_count or 0, reverse=True)[:5]

    return jsonify({
        "total_active":  len(active),
        "total_revoked": len(revoked),
        "top_keys": [
            {
                "id":        k.id,
                "label":     k.label,
                "use_count": k.use_count,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in top
        ],
    }), 200
