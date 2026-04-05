# =============================================================
# AIPET Cloud — Authentication Routes
# =============================================================
import os
import sys
import bcrypt
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

import os as _os
_base = '/app' if _os.path.exists('/app') else '/home/binyam/AIPET'
sys.path.insert(0, _base)

from dashboard.backend.models import db, User

auth_bp = Blueprint("auth", __name__)

# In-memory store for tracking failed login attempts
# Format: {email: {"count": int, "locked_until": datetime|None}}
_login_attempts = {}


@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name     = data.get("name", "").strip()

    if not email or not password or not name:
        return jsonify({"error": "Email, password and name are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email address"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    user = User(
        email         = email,
        password_hash = password_hash,
        name          = name,
        plan          = "free",
        scans_used    = 0,
        created_at    = datetime.now(timezone.utc)
    )
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Account created successfully",
        "token":   token,
        "user":    user.to_dict()
    }), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    now     = datetime.now(timezone.utc)
    attempt = _login_attempts.get(email, {"count": 0, "locked_until": None})

    # Check if account is currently locked
    if attempt["locked_until"] and now < attempt["locked_until"]:
        remaining = int((attempt["locked_until"] - now).total_seconds() / 60)
        return jsonify({
            "error": f"Account temporarily locked. Try again in {remaining} minute(s)."
        }), 429

    user = User.query.filter_by(email=email).first()

    if not user:
        # Increment failure counter even for non-existent users
        # This prevents user enumeration attacks
        new_count = attempt["count"] + 1
        _login_attempts[email] = {
            "count": new_count,
            "locked_until": now + timedelta(minutes=15) if new_count >= 5 else None
        }
        return jsonify({"error": "Invalid email or password"}), 401

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user.password_hash.encode("utf-8")
    ):
        new_count = attempt["count"] + 1
        locked_until = now + timedelta(minutes=15) if new_count >= 5 else None

        _login_attempts[email] = {
            "count": new_count,
            "locked_until": locked_until
        }

        if locked_until:
            return jsonify({
                "error": "Too many failed attempts. Account locked for 15 minutes."
            }), 429

        remaining_attempts = 5 - new_count
        return jsonify({
            "error": f"Invalid email or password. {remaining_attempts} attempt(s) remaining."
        }), 401

    # Successful login — reset failure counter
    _login_attempts.pop(email, None)

    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Login successful",
        "token":   token,
        "user":    user.to_dict()
    }), 200


@auth_bp.route("/api/auth/me", methods=["GET"])
@jwt_required()
def get_me():
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict()), 200


@auth_bp.route("/api/auth/change-password", methods=["POST"])
@jwt_required()
def change_password():
    user_id  = get_jwt_identity()
    user     = User.query.get(int(user_id))
    data     = request.json or {}
    current  = data.get("current_password", "")
    new_pass = data.get("new_password", "")

    if not current or not new_pass:
        return jsonify({"error": "Both passwords required"}), 400
    if len(new_pass) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    if not bcrypt.checkpw(
        current.encode("utf-8"),
        user.password_hash.encode("utf-8")
    ):
        return jsonify({"error": "Current password is incorrect"}), 401

    user.password_hash = bcrypt.hashpw(
        new_pass.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

# =============================================================
# Google SSO
# =============================================================
from authlib.integrations.flask_client import OAuth
from flask import redirect, current_app, session
import secrets

oauth = OAuth()

def init_google_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={'scope': 'openid email profile'},
    )

@auth_bp.route('/api/auth/google', methods=['GET'])
def google_login():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    redirect_uri = current_app.config['GOOGLE_REDIRECT_URI']
    return oauth.google.authorize_redirect(redirect_uri, state=state)

@auth_bp.route('/api/auth/google/callback', methods=['GET'])
def google_callback():
    from ..models import User, db
    from flask_jwt_extended import create_access_token

    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo')

        if not userinfo:
            return redirect('http://localhost:3000/login?error=google_failed')

        email = userinfo.get('email')
        name  = userinfo.get('name', email.split('@')[0])

        if not email:
            return redirect('http://localhost:3000/login?error=no_email')

        user = User.query.filter_by(email=email).first()

        if not user:
            import bcrypt
            random_password = secrets.token_urlsafe(32)
            password_hash   = bcrypt.hashpw(random_password.encode(), bcrypt.gensalt()).decode()
            user = User(
                email         = email,
                name          = name,
                password_hash = password_hash,
                plan          = 'free',
            )
            db.session.add(user)
            db.session.commit()

        access_token = create_access_token(identity=str(user.id))
        return redirect(f'http://localhost:3000?sso_token={access_token}&plan={user.plan}')

    except Exception as e:
        current_app.logger.error(f'Google SSO error: {e}')
        return redirect('http://localhost:3000/login?error=sso_failed')
