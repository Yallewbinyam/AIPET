# =============================================================
# AIPET Cloud — Authentication Routes
# =============================================================
import os
import sys
import secrets
import bcrypt
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

import os as _os
_base = '/app' if _os.path.exists('/app') else '/home/binyam/AIPET'
sys.path.insert(0, _base)

from dashboard.backend.models import db, User, PasswordResetToken
from dashboard.backend.validation import validate_body, LOGIN_SCHEMA, REGISTER_SCHEMA, CHANGE_PASSWORD_SCHEMA

auth_bp = Blueprint("auth", __name__)

# In-memory store for tracking failed login attempts
# Format: {email: {"count": int, "locked_until": datetime|None}}
_login_attempts = {}


@auth_bp.route("/api/auth/register", methods=["POST"])
@validate_body(REGISTER_SCHEMA)
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

    try:
        from dashboard.backend.central_events.adapter import emit_event
        emit_event(
            source_module = "auth",
            source_table  = "users",
            source_row_id = user.id,
            event_type    = "user_registered",
            severity      = "info",
            user_id       = user.id,
            entity        = user.email,
            entity_type   = "user",
            title         = f"New user registered: {user.email}",
            payload       = {"plan": user.plan},
        )
    except Exception:
        current_app.logger.exception("emit_event call site error in auth (register)")

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Account created successfully",
        "token":   token,
        "user":    user.to_dict(),
        "onboarding_complete": False,
    }), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
@validate_body(LOGIN_SCHEMA)
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
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module = "auth",
                source_table  = "users",
                source_row_id = "unknown",
                event_type    = "user_login_failed",
                severity      = "medium",
                user_id       = None,
                entity        = email,
                entity_type   = "user",
                title         = f"Failed login attempt for {email} (account not found)",
                payload       = {"reason": "account_not_found"},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in auth (login_failed)")
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

        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module = "auth",
                source_table  = "users",
                source_row_id = user.id,
                event_type    = "user_login_failed",
                severity      = "medium",
                user_id       = user.id,
                entity        = email,
                entity_type   = "user",
                title         = f"Failed login attempt for {email}",
                payload       = {"reason": "bad_password", "attempt_count": new_count},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in auth (login_failed)")

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

    try:
        from dashboard.backend.central_events.adapter import emit_event
        emit_event(
            source_module = "auth",
            source_table  = "users",
            source_row_id = user.id,
            event_type    = "user_login",
            severity      = "info",
            user_id       = user.id,
            entity        = user.email,
            entity_type   = "user",
            title         = f"User logged in: {user.email}",
            payload       = {"plan": user.plan},
        )
    except Exception:
        current_app.logger.exception("emit_event call site error in auth (login)")

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Login successful",
        "token":   token,
        "user":    user.to_dict(),
        "onboarding_complete": user.onboarding_complete or False,
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
@validate_body(CHANGE_PASSWORD_SCHEMA)
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


@auth_bp.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400

    user = User.query.filter_by(email=email).first()
    # Always return 200 to prevent user enumeration
    if not user:
        return jsonify({"message": "If that email exists, a reset link has been sent."}), 200

    # Expire any existing unused tokens for this user
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
    db.session.commit()

    token_str  = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    prt = PasswordResetToken(user_id=user.id, token=token_str, expires_at=expires_at)
    db.session.add(prt)
    db.session.commit()

    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    reset_url    = f"{frontend_url}?reset_token={token_str}"

    try:
        from flask_mail import Mail, Message
        mail    = Mail(current_app)
        subject = "AIPET X — Password Reset Request"
        body_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:540px;margin:0 auto;background:#0a0f1a;color:#e0e0e0;padding:32px;border-radius:8px;">
          <div style="border-bottom:3px solid #00e5ff;padding-bottom:16px;margin-bottom:24px;">
            <span style="color:#00e5ff;font-size:18px;font-weight:700;">AIPET X</span>
          </div>
          <h2 style="color:#e0e0e0;margin:0 0 12px;">Password Reset Request</h2>
          <p style="color:#94a3b8;margin:0 0 24px;">We received a request to reset the password for <strong style="color:#e0e0e0;">{user.email}</strong>. Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
          <a href="{reset_url}" style="display:inline-block;background:#00e5ff;color:#000;font-weight:700;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:14px;">Reset Password</a>
          <p style="color:#475569;font-size:12px;margin-top:28px;">If you did not request this, ignore this email — your password will not change.</p>
        </div>"""
        msg = Message(subject=subject, sender=current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@aipet.io"), recipients=[user.email], html=body_html)
        mail.send(msg)
    except Exception as e:
        current_app.logger.error(f"Password reset email failed: {e}")

    return jsonify({"message": "If that email exists, a reset link has been sent."}), 200


@auth_bp.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data         = request.get_json(silent=True) or {}
    token_str    = data.get("token", "").strip()
    new_password = data.get("new_password", "")

    if not token_str or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    prt = PasswordResetToken.query.filter_by(token=token_str, used=False).first()
    if not prt:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    now = datetime.now(timezone.utc)
    expires = prt.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        prt.used = True
        db.session.commit()
        return jsonify({"error": "Reset token has expired. Request a new one."}), 400

    user = User.query.get(prt.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    prt.used = True
    db.session.commit()

    jwt = create_access_token(identity=str(user.id))
    return jsonify({"message": "Password reset successfully", "token": jwt, "user": user.to_dict()}), 200


@auth_bp.route("/api/auth/complete-onboarding", methods=["POST"])
@jwt_required()
def complete_onboarding():
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    data         = request.get_json(silent=True) or {}
    organisation = data.get("organisation", "").strip()
    industry     = data.get("industry", "").strip()

    if organisation:
        user.organisation = organisation
    if industry:
        user.industry = industry
    user.onboarding_complete = True
    db.session.commit()

    return jsonify({"message": "Onboarding complete", "user": user.to_dict()}), 200


# =============================================================
# Google SSO
# =============================================================
from authlib.integrations.flask_client import OAuth
from flask import redirect, session

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
