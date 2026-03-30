# =============================================================
# AIPET Cloud — API Key Management Routes
# Enterprise plan only.
# Keys are hashed with SHA-256 before storage.
# Raw key is shown ONCE at generation — never stored.
# =============================================================

import os
import hashlib
import secrets
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from ..models import db, User, APIKey


api_keys_bp = Blueprint('api_keys', __name__)


def hash_key(raw_key):
    """
    Hash an API key using SHA-256.
    We store only the hash — never the raw key.
    This protects users even if the database is breached.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_raw_key():
    """
    Generate a cryptographically secure random API key.
    Format: aipet_ent_<32 random hex characters>
    Example: aipet_ent_a3f8c2d1e4b5a6c7d8e9f0a1b2c3d4e5
    
    secrets.token_hex() uses the OS random number generator
    which is cryptographically secure — safe for production.
    """
    return f"aipet_ent_{secrets.token_hex(32)}"


def require_enterprise(user):
    """
    Check if a user has Enterprise plan.
    Returns (allowed, error_response) tuple.
    If allowed is False, return the error_response to the client.
    """
    if user.plan != 'enterprise':
        return False, jsonify({
            'error': 'API key access requires the Enterprise plan.',
            'upgrade_url': '/pricing'
        }), 403
    return True, None, None


# ─────────────────────────────────────────────────────────────
# ENDPOINT 1: Generate a new API key
# ─────────────────────────────────────────────────────────────

@api_keys_bp.route('', methods=['POST'])
@jwt_required()
def create_api_key():
    """
    Generate a new API key for the logged-in Enterprise user.

    Request body: { "name": "My CI/CD Pipeline" }
    Response:     { "key": "aipet_ent_...", "id": 1, "name": "..." }

    IMPORTANT: The raw key is returned ONCE here and never again.
    We only store the hash. If the user loses it, they must generate
    a new one.
    """
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Enterprise only
    if user.plan != 'enterprise':
        return jsonify({
            'error': 'API key access requires the Enterprise plan.',
            'upgrade_url': '/pricing'
        }), 403

    # Max 10 API keys per user — prevents abuse
    existing_count = APIKey.query.filter_by(
        user_id=user.id,
        is_active=True
    ).count()

    if existing_count >= 10:
        return jsonify({
            'error': 'Maximum of 10 active API keys allowed. Revoke an existing key first.'
        }), 400

    data = request.get_json() or {}
    name = data.get('name', '').strip()

    if not name:
        return jsonify({'error': 'API key name is required'}), 400

    if len(name) > 100:
        return jsonify({'error': 'Name must be 100 characters or less'}), 400

    # Generate the raw key — this is shown to the user ONCE
    raw_key  = generate_raw_key()
    key_hash = hash_key(raw_key)

    # Store only the hash
    api_key = APIKey(
        user_id    = user.id,
        key_hash   = key_hash,
        name       = name,
        is_active  = True,
        created_at = datetime.now(timezone.utc),
    )
    db.session.add(api_key)
    db.session.commit()

    current_app.logger.info(
        f"[api_keys] User {user.email} created API key '{name}' (id: {api_key.id})"
    )

    return jsonify({
        'message': 'API key created. Copy it now — it will not be shown again.',
        'key':     raw_key,
        'id':      api_key.id,
        'name':    api_key.name,
        'created_at': api_key.created_at.isoformat(),
    }), 201


# ─────────────────────────────────────────────────────────────
# ENDPOINT 2: List all API keys
# ─────────────────────────────────────────────────────────────

@api_keys_bp.route('', methods=['GET'])
@jwt_required()
def list_api_keys():
    """
    List all active API keys for the logged-in user.
    Returns metadata only — never the raw key or hash.
    """
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.plan != 'enterprise':
        return jsonify({
            'error': 'API key access requires the Enterprise plan.'
        }), 403

    keys = APIKey.query.filter_by(
        user_id   = user.id,
        is_active = True
    ).order_by(APIKey.created_at.desc()).all()

    return jsonify({
        'keys': [
            {
                'id':        k.id,
                'name':      k.name,
                'created_at': k.created_at.isoformat() if k.created_at else None,
                'last_used': k.last_used.isoformat() if k.last_used else 'Never',
                # Show only first 16 chars of hash as a safe identifier
                'key_preview': f"aipet_ent_...{k.key_hash[:8]}",
            }
            for k in keys
        ],
        'total': len(keys),
        'limit': 10,
    }), 200


# ─────────────────────────────────────────────────────────────
# ENDPOINT 3: Revoke an API key
# ─────────────────────────────────────────────────────────────

@api_keys_bp.route('/<int:key_id>', methods=['DELETE'])
@jwt_required()
def revoke_api_key(key_id):
    """
    Revoke (deactivate) an API key by ID.
    The key record stays in the database for audit purposes
    but is_active is set to False so it can no longer be used.
    """
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Find the key — must belong to this user
    api_key = APIKey.query.filter_by(
        id        = key_id,
        user_id   = user.id,
        is_active = True
    ).first()

    if not api_key:
        return jsonify({'error': 'API key not found'}), 404

    # Deactivate — do not delete, keep for audit trail
    api_key.is_active = False
    db.session.commit()

    current_app.logger.info(
        f"[api_keys] User {user.email} revoked API key '{api_key.name}' (id: {key_id})"
    )

    return jsonify({
        'message': f"API key '{api_key.name}' has been revoked."
    }), 200


# ─────────────────────────────────────────────────────────────
# API KEY AUTHENTICATION MIDDLEWARE
# ─────────────────────────────────────────────────────────────

def authenticate_api_key(raw_key):
    """
    Validate an API key from a request header.
    Called by any endpoint that accepts API key authentication.

    Returns the User object if valid, None if invalid.

    Usage in a route:
        key_header = request.headers.get('X-API-Key')
        user = authenticate_api_key(key_header)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
    """
    if not raw_key:
        return None

    # Hash the provided key and look it up
    key_hash = hash_key(raw_key)
    api_key  = APIKey.query.filter_by(
        key_hash  = key_hash,
        is_active = True
    ).first()

    if not api_key:
        return None

    # Update last_used timestamp
    api_key.last_used = datetime.now(timezone.utc)
    db.session.commit()

    return User.query.get(api_key.user_id)