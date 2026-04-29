import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Blueprint, current_app, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, User
from dashboard.backend.iam.models import (
    Role, Permission, UserRole, AuditLog, SSOProvider, IssuedToken,
    Invitation,
)

iam_bp = Blueprint('iam', __name__, url_prefix='/api/iam')

# ── Audit helper ─────────────────────────────────────────────
def log_action(user_id, action, resource=None, status='success', details=None):
    """
    Append a row to audit_log. Backward-compatible signature: existing
    callers that pass only the first 3-4 positional args keep working.

    `details` (added with the soft-delete migration) populates the
    optional `node_meta` JSON column for structured event detail
    (e.g. soft-delete reason, denormalised hostname for posterity,
    timestamps that survive even if the referenced row is later hard-
    deleted).
    """
    try:
        entry = AuditLog(
            user_id    = user_id,
            action     = action,
            resource   = resource,
            ip_address = request.remote_addr if request else None,
            user_agent = (request.headers.get('User-Agent', '') if request else ''),
            status     = status,
            node_meta  = details,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

# ── RBAC decorator ───────────────────────────────────────────
def require_permission(permission_name):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            # Owner bypasses all permission checks
            user_roles = UserRole.query.filter_by(user_id=user_id).all()
            role_ids = [ur.role_id for ur in user_roles]
            roles = Role.query.filter(Role.id.in_(role_ids)).all()
            role_names = [r.name for r in roles]
            if 'owner' in role_names:
                return f(*args, **kwargs)
            # Check specific permission
            for role in roles:
                for perm in role.permissions:
                    if perm.name == permission_name:
                        return f(*args, **kwargs)
            log_action(user_id, f'permission_denied:{permission_name}', status='blocked')
            return jsonify({'error': 'Insufficient permissions', 'required': permission_name}), 403
        return decorated
    return decorator

# ── Role-assignment helper (Team-Access F2) ──────────────────
def assign_role_to_user(user_id, role_name, assigned_by=None,
                        reason='manual', emit_audit=True):
    """
    Idempotently assign a role to a user.

    Returns the UserRole row (existing or newly-created). On a fresh
    assignment, also adds an `audit_log` entry with structured detail
    in `node_meta`: `{"role": <role_name>, "reason": <reason>}`.

    Caller is responsible for `db.session.commit()` -- this helper
    only stages rows on the session so the caller can bundle the
    role assignment into an enclosing transaction (e.g. atomic with
    user creation in `auth.register`).

    Raises:
      LookupError: when `role_name` does not exist in the `roles`
                   table. Caller should catch + decide how to handle
                   (registration shouldn't fail on this; the helper
                   stays neutral).
    """
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        raise LookupError(f"Role not found: {role_name!r}")

    existing = UserRole.query.filter_by(user_id=user_id,
                                        role_id=role.id).first()
    if existing is not None:
        return existing  # idempotent no-op; no audit row written

    ur = UserRole(
        user_id     = user_id,
        role_id     = role.id,
        assigned_by = assigned_by,
    )
    db.session.add(ur)

    if emit_audit:
        # Inline AuditLog creation (NOT log_action -- that helper
        # commits on its own, which would break the caller-commits
        # contract of this helper).
        db.session.add(AuditLog(
            user_id    = assigned_by,
            action     = 'role.assigned',
            resource   = f'user:{user_id}',
            ip_address = request.remote_addr if request else None,
            user_agent = (request.headers.get('User-Agent', '')
                          if request else ''),
            status     = 'success',
            node_meta  = {'role': role_name, 'reason': reason},
        ))

    return ur


# ── Role endpoints ───────────────────────────────────────────
@iam_bp.route('/roles', methods=['GET'])
@jwt_required()
def get_roles():
    roles = Role.query.all()
    return jsonify([{
        'id': r.id, 'name': r.name, 'description': r.description,
        'permissions': [p.name for p in r.permissions]
    } for r in roles])

@iam_bp.route('/roles', methods=['POST'])
@require_permission('iam:manage')
def create_role():
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'error': 'Role name required'}), 400
    if Role.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Role already exists'}), 409
    role = Role(name=data['name'], description=data.get('description', ''))
    db.session.add(role)
    db.session.commit()
    log_action(get_jwt_identity(), 'role_created', resource=data['name'])
    return jsonify({'message': 'Role created', 'id': role.id}), 201

# ── User role assignment ─────────────────────────────────────
@iam_bp.route('/users/<user_id>/roles', methods=['GET'])
@jwt_required()
def get_user_roles(user_id):
    user_roles = UserRole.query.filter_by(user_id=user_id).all()
    roles = [Role.query.get(ur.role_id) for ur in user_roles]
    return jsonify([{'id': r.id, 'name': r.name} for r in roles if r])

@iam_bp.route('/users/<user_id>/roles', methods=['POST'])
@require_permission('iam:manage')
def assign_role(user_id):
    data = request.get_json()
    role = Role.query.filter_by(name=data.get('role')).first()
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    existing = UserRole.query.filter_by(user_id=user_id, role_id=role.id).first()
    if existing:
        return jsonify({'message': 'Role already assigned'}), 200
    user_role = UserRole(
        user_id     = user_id,
        role_id     = role.id,
        assigned_by = get_jwt_identity()
    )
    db.session.add(user_role)
    db.session.commit()
    log_action(get_jwt_identity(), 'role_assigned', resource=f'{user_id}:{role.name}')
    return jsonify({'message': 'Role assigned successfully'}), 201

@iam_bp.route('/users/<user_id>/roles/<role_name>', methods=['DELETE'])
@require_permission('iam:manage')
def revoke_role(user_id, role_name):
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    UserRole.query.filter_by(user_id=user_id, role_id=role.id).delete()
    db.session.commit()
    log_action(get_jwt_identity(), 'role_revoked', resource=f'{user_id}:{role_name}')
    return jsonify({'message': 'Role revoked successfully'})

# ── Members list ─────────────────────────────────────────────
# Phase B § 6.1.1 v1 minimum: list users with their roles. Basic
# pagination, no filters yet (search/sort/status come in a follow-
# up). Permission gate is `iam:manage` for now -- when F0 lands an
# `iam:read` permission, this is the place that gets relaxed so
# admin/analyst/viewer can read the team list without being able
# to mutate it. Today, owner-role users pass via the role-name
# bypass in require_permission().
@iam_bp.route('/members', methods=['GET'])
@require_permission('iam:manage')
def list_members():
    from dashboard.backend.models import User
    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 25, type=int), 100)

    pagination = User.query.order_by(User.email.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Per-user role lookup. N+1 in shape; acceptable at v1 scale
    # (typical tenant ~ tens of users per page). When member counts
    # justify it, this becomes a single joined query loaded eagerly.
    members = []
    for u in pagination.items:
        user_roles = UserRole.query.filter_by(user_id=u.id).all()
        role_ids   = [ur.role_id for ur in user_roles]
        roles      = (Role.query.filter(Role.id.in_(role_ids)).all()
                      if role_ids else [])
        members.append({
            'id':            u.id,
            'email':         u.email,
            'name':          u.name,
            'plan':          u.plan,
            'organisation':  u.organisation,
            'created_at':    u.created_at.isoformat() if u.created_at else None,
            'last_login':    u.last_login.isoformat() if u.last_login else None,
            'is_active':     bool(u.is_active),
            'roles':         [{'id': r.id, 'name': r.name} for r in roles],
        })

    return jsonify({
        'members': members,
        'total':   pagination.total,
        'pages':   pagination.pages,
        'page':    pagination.page,
    })


# ── Member detail / enable / disable ─────────────────────────
# Helpers shared by GET /users/<id>, POST /users/<id>/disable,
# POST /users/<id>/enable. Last-owner safety net is enforced in
# the same db.session as the status toggle so a single request
# can't disable the platform's only owner. (At higher concurrency
# we'd add `with_for_update()` on the user_roles query; v1 row
# counts make that overkill.)

def _serialize_member(user):
    """Canonical member-detail dict. Re-fetches roles per call;
    callers that already have the role list in hand can pre-populate
    it -- not needed at v1 scale."""
    user_roles = UserRole.query.filter_by(user_id=user.id).all()
    role_ids   = [ur.role_id for ur in user_roles]
    roles      = (Role.query.filter(Role.id.in_(role_ids)).all()
                  if role_ids else [])
    return {
        'id':           user.id,
        'email':        user.email,
        'name':         user.name,
        'plan':         user.plan,
        'organisation': user.organisation,
        'created_at':   user.created_at.isoformat() if user.created_at else None,
        'last_login':   user.last_login.isoformat() if user.last_login else None,
        # The is_active column is nullable in the DB schema (no
        # NOT NULL constraint); coalesce to True for any historical
        # rows that may have NULL.
        'is_active':    True if user.is_active is None else bool(user.is_active),
        'removed_at':   user.removed_at.isoformat() if user.removed_at else None,
        'roles':        [{'id': r.id, 'name': r.name} for r in roles],
    }


def _is_last_owner(target_user_id):
    """True iff target is the only owner who is BOTH active AND
    not soft-removed. We count active+present owners (not all
    role-assigned owners) because the safety net's purpose is
    preventing platform lockout -- a disabled or removed user
    retains their owner role assignment but cannot use it without
    first being re-enabled / restored. A literal "only user with
    the role" check would let admins disable both owners in
    sequence and end up with zero active owners; this widened
    check protects against that.

    Active = is_active True OR NULL (the column is nullable;
    NULL is treated as active, matching the rest of the codebase).
    Present = removed_at IS NULL (soft-removed users are excluded)."""
    owner_role = Role.query.filter_by(name='owner').first()
    if owner_role is None:
        return False  # 'owner' not seeded; nothing to protect

    target_has_owner = UserRole.query.filter_by(
        user_id=target_user_id, role_id=owner_role.id
    ).first() is not None
    if not target_has_owner:
        return False

    other_active_owners = (db.session.query(User.id)
        .join(UserRole, UserRole.user_id == User.id)
        .filter(
            UserRole.role_id == owner_role.id,
            User.id != target_user_id,
            db.or_(User.is_active.is_(True), User.is_active.is_(None)),
            User.removed_at.is_(None),
        )
        .count())
    return other_active_owners == 0


def cleanup_expired_tokens():
    """Delete IssuedToken rows whose JWT has already expired AND
    were never explicitly revoked. Revoked rows stay so the
    blocklist can keep saying "no" past the natural expiry until
    the JWT signature itself stops being trusted.

    Not auto-scheduled in v1 -- run manually or wire a Celery beat
    job in v2. Returns the deletion row count for caller-side
    logging."""
    now = datetime.now(timezone.utc)
    deleted = (IssuedToken.query
               .filter(IssuedToken.expires_at < now,
                       IssuedToken.revoked.is_(False))
               .delete(synchronize_session=False))
    db.session.commit()
    return deleted


@iam_bp.route('/users/<int:user_id>', methods=['GET'])
@require_permission('iam:manage')
def get_member_detail(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'user_not_found',
                        'message': f'No user with id={user_id}'}), 404
    return jsonify(_serialize_member(user)), 200


@iam_bp.route('/users/<int:user_id>/disable', methods=['POST'])
@require_permission('iam:manage')
def disable_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'user_not_found',
                        'message': f'No user with id={user_id}'}), 404

    # Idempotent: already disabled -> 200, no audit row written.
    # (`is_active` is nullable; treat NULL as True/active.)
    currently_active = (True if user.is_active is None
                        else bool(user.is_active))
    if not currently_active:
        return jsonify(_serialize_member(user)), 200

    # Last-owner safety net.
    if _is_last_owner(user_id):
        return jsonify({
            'error':   'last_owner',
            'message': 'Cannot disable the last owner of the platform.',
        }), 400

    data = request.get_json(silent=True) or {}
    reason = data.get('reason')

    user.is_active = False
    db.session.add(user)
    db.session.commit()

    log_action(
        get_jwt_identity(),
        'user.disabled',
        resource=f'user:{user_id}',
        details={'reason': reason} if reason else None,
    )
    return jsonify(_serialize_member(user)), 200


@iam_bp.route('/users/<int:user_id>/enable', methods=['POST'])
@require_permission('iam:manage')
def enable_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'user_not_found',
                        'message': f'No user with id={user_id}'}), 404

    currently_active = (True if user.is_active is None
                        else bool(user.is_active))
    if currently_active:
        # Idempotent: already enabled -> 200, no audit row written.
        return jsonify(_serialize_member(user)), 200

    data = request.get_json(silent=True) or {}
    reason = data.get('reason')

    user.is_active = True
    db.session.add(user)
    db.session.commit()

    log_action(
        get_jwt_identity(),
        'user.enabled',
        resource=f'user:{user_id}',
        details={'reason': reason} if reason else None,
    )
    return jsonify(_serialize_member(user)), 200


@iam_bp.route('/users/<int:user_id>/remove', methods=['POST'])
@require_permission('iam:manage')
def remove_user(user_id):
    """Soft-remove a user. is_active flips to False, removed_at
    stamped, and ALL outstanding IssuedToken rows for the user
    are revoked atomically with revoke_reason='user.removed' so
    the user's access cuts immediately rather than on JWT expiry.
    Audit row is written. Idempotent: if already removed, 200 +
    no extra side effects. Last-owner safety net per
    _is_last_owner."""
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'user_not_found',
                        'message': f'No user with id={user_id}'}), 404

    # Idempotent: already removed.
    if user.removed_at is not None:
        return jsonify(_serialize_member(user)), 200

    if _is_last_owner(user_id):
        return jsonify({
            'error':   'last_owner',
            'message': 'Cannot remove the last owner of the platform.',
        }), 400

    data       = request.get_json(silent=True) or {}
    reason     = data.get('reason')
    actor_id   = get_jwt_identity()
    now        = datetime.now(timezone.utc)

    # Single transaction: flip flags + mass-revoke tokens.
    user.is_active  = False
    user.removed_at = now
    db.session.add(user)

    sessions_revoked = (
        IssuedToken.query
        .filter(IssuedToken.user_id == user_id,
                IssuedToken.revoked.is_(False))
        .update({
            'revoked':       True,
            'revoked_at':    now,
            'revoked_by':    int(actor_id) if actor_id is not None else None,
            'revoke_reason': 'user.removed',
        }, synchronize_session=False)
    )
    db.session.commit()

    log_action(
        actor_id,
        'user.removed',
        resource=f'user:{user_id}',
        details={
            'reason':           reason,
            'sessions_revoked': sessions_revoked,
            'email':            user.email,    # denormalised for posterity
        },
    )
    return jsonify(_serialize_member(user)), 200


@iam_bp.route('/users/<int:user_id>/restore', methods=['POST'])
@require_permission('iam:manage')
def restore_user(user_id):
    """Undo a soft-remove. Sets removed_at to NULL and is_active
    to True. Does NOT un-revoke the user's pre-existing
    IssuedToken rows; they must log in again to get a fresh
    token. This is the secure default -- restored access starts
    a new session, not a resurrected old one. Returns 400 if the
    target is not currently removed (no-op safety)."""
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'user_not_found',
                        'message': f'No user with id={user_id}'}), 404

    if user.removed_at is None:
        return jsonify({
            'error':   'not_removed',
            'message': 'Cannot restore a user that has not been removed.',
        }), 400

    data   = request.get_json(silent=True) or {}
    reason = data.get('reason')

    user.removed_at = None
    user.is_active  = True
    db.session.add(user)
    db.session.commit()

    log_action(
        get_jwt_identity(),
        'user.restored',
        resource=f'user:{user_id}',
        details={'reason': reason} if reason else None,
    )
    return jsonify(_serialize_member(user)), 200


# ── Invitations ──────────────────────────────────────────────
# Phase B § 8 I1-I4. Five admin endpoints + one public endpoint
# (the accept-invitation flow lives in auth/routes.py because
# it creates a user and issues a JWT, mirroring register/login).
#
# Token discipline: `Invitation.token` is the recipient's auth
# at accept time. It is delivered ONCE in the invitation email
# body and MUST NOT appear in any list/detail/audit response.
# `_serialize_invitation` enforces that contract.
#
# Email delivery is best-effort: if SMTP is down, the row still
# persists with status='pending' and the admin can resend.

# Resend rate limiting (per-invitation, in-process). Phase B
# v1.1 may move this to Redis for multi-worker correctness; the
# v1 dev/test footprint with a single Gunicorn process is fine.
INVITATION_RESEND_MAX        = 3
INVITATION_RESEND_COOLDOWN_S = 5 * 60   # 5 min between resends


def _serialize_invitation(inv):
    """Canonical invitation dict. **Token is deliberately omitted**
    -- it leaves the system exactly once via email and is the
    recipient's auth credential. Any list/detail surface that
    leaked it would be a credential disclosure."""
    role = db.session.get(Role, inv.role_id) if inv.role_id else None
    inviter = db.session.get(User, inv.invited_by) if inv.invited_by else None
    return {
        'id':              inv.id,
        'email':           inv.email,
        'role':            role.name if role else None,
        'role_id':         inv.role_id,
        'invited_by':      inv.invited_by,
        'invited_by_email': inviter.email if inviter else None,
        'invited_at':      inv.invited_at.isoformat() if inv.invited_at else None,
        'expires_at':      inv.expires_at.isoformat() if inv.expires_at else None,
        'accepted_at':     inv.accepted_at.isoformat() if inv.accepted_at else None,
        'accepted_by':     inv.accepted_by,
        'revoked_at':      inv.revoked_at.isoformat() if inv.revoked_at else None,
        'revoked_by':      inv.revoked_by,
        'status':          inv.status,
        'resend_count':    inv.resend_count,
        'last_resent_at':  inv.last_resent_at.isoformat() if inv.last_resent_at else None,
        # NB: 'token' field intentionally absent.
    }


def _send_invitation_email(invitation, role_name):
    """Best-effort email send. Returns True on send, False
    otherwise. Logs WARNING on failure but never raises -- the
    invitation row is the durable record; admin can resend."""
    if not getattr(current_app, 'email_enabled', False):
        current_app.logger.warning(
            "Invitation email NOT sent for invitation_id=%s -- "
            "email backend disabled (PLB-4 SMTP unset). "
            "Token created; admin can resend after fixing SMTP.",
            invitation.id,
        )
        return False

    try:
        from flask_mail import Mail, Message
        mail = Mail(current_app)
        frontend_url = os.environ.get(
            "FRONTEND_URL", "http://localhost:3000"
        ).rstrip('/')
        accept_url = f"{frontend_url}/accept-invitation?token={invitation.token}"
        inviter = db.session.get(User, invitation.invited_by)
        inviter_name = (inviter.name if inviter else "An administrator")
        expires_str = invitation.expires_at.strftime("%Y-%m-%d %H:%M UTC")

        subject = "You're invited to AIPET X"
        body_text = (
            f"Hi,\n\n"
            f"{inviter_name} has invited you to join AIPET X with the role "
            f"`{role_name}`.\n\n"
            f"Accept this invitation: {accept_url}\n\n"
            f"This link expires at {expires_str}. If you did not expect "
            f"this invitation, you can safely ignore it.\n\n"
            f"-- AIPET X"
        )
        body_html = (
            f'<div style="font-family:Arial,sans-serif;max-width:540px;'
            f'margin:0 auto;background:#0a0f1a;color:#e0e0e0;padding:32px;'
            f'border-radius:8px;">'
            f'<div style="border-bottom:3px solid #00e5ff;padding-bottom:16px;'
            f'margin-bottom:24px;"><span style="color:#00e5ff;font-size:18px;'
            f'font-weight:700;">AIPET X</span></div>'
            f'<h2 style="color:#e0e0e0;margin:0 0 12px;">You\'re invited</h2>'
            f'<p style="color:#94a3b8;margin:0 0 16px;">'
            f'<strong style="color:#e0e0e0;">{inviter_name}</strong> has '
            f'invited you to join AIPET X with role '
            f'<strong style="color:#e0e0e0;">{role_name}</strong>.</p>'
            f'<p style="color:#94a3b8;margin:0 0 24px;">Click the button '
            f'below to set a password and join. This link expires '
            f'<strong>{expires_str}</strong>.</p>'
            f'<a href="{accept_url}" style="display:inline-block;'
            f'background:#00e5ff;color:#000;font-weight:700;padding:12px 28px;'
            f'border-radius:6px;text-decoration:none;font-size:14px;">'
            f'Accept invitation</a>'
            f'<p style="color:#475569;font-size:12px;margin-top:28px;">'
            f'If you did not expect this invitation, you can safely '
            f'ignore it.</p></div>'
        )

        msg = Message(
            subject    = subject,
            sender     = current_app.config.get("MAIL_DEFAULT_SENDER",
                                                 "noreply@aipet.io"),
            recipients = [invitation.email],
            body       = body_text,
            html       = body_html,
        )
        mail.send(msg)
        return True
    except Exception:
        current_app.logger.exception(
            "Invitation email failed for invitation_id=%s; row persists, "
            "admin can resend",
            invitation.id,
        )
        return False


def expire_pending_invitations():
    """Mark every pending Invitation past its expires_at as expired.
    Not auto-scheduled in v1 -- run manually or wire a Celery beat
    task in v2. Returns the count of rows transitioned."""
    now = datetime.now(timezone.utc)
    updated = (Invitation.query
               .filter(Invitation.status == 'pending',
                       Invitation.expires_at < now)
               .update({'status': 'expired'},
                       synchronize_session=False))
    db.session.commit()
    return updated


@iam_bp.route('/invitations', methods=['POST'])
@require_permission('iam:manage')
def create_invitation():
    """Invite a new team member by email.

    Body: {"email": str, "role_name": str,
           "expires_in_days": int (optional, default 7, max 30)}

    On success: 201 + serialised Invitation (without token).
    On 4xx: 400 with field-level error code.
    """
    data = request.get_json(silent=True) or {}
    email     = (data.get('email') or '').strip().lower()
    role_name = (data.get('role_name') or '').strip()
    expires_in_days = data.get('expires_in_days', 7)

    if not email or '@' not in email:
        return jsonify({'error': 'invalid_email',
                        'message': "'email' must be a valid email"}), 400
    if not role_name:
        return jsonify({'error': 'invalid_role',
                        'message': "'role_name' is required"}), 400
    try:
        expires_in_days = int(expires_in_days)
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid_expires_in_days',
                        'message': "'expires_in_days' must be an integer"}), 400
    if expires_in_days < 1 or expires_in_days > 30:
        return jsonify({'error': 'invalid_expires_in_days',
                        'message': "'expires_in_days' must be in [1, 30]"}), 400

    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        return jsonify({'error': 'role_not_found',
                        'message': f"No role named {role_name!r}"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user is not None:
        return jsonify({
            'error':   'user_exists',
            'message': "User already exists; assign role directly.",
        }), 400

    pending = (Invitation.query
               .filter_by(email=email, status='pending')
               .first())
    if pending is not None:
        return jsonify({
            'error':       'duplicate_pending',
            'message':     ("Pending invitation already exists for this "
                            "email; resend or revoke."),
            'invitation_id': pending.id,
        }), 400

    now = datetime.now(timezone.utc)
    inv = Invitation(
        email      = email,
        token      = secrets.token_urlsafe(48),
        role_id    = role.id,
        invited_by = int(get_jwt_identity()),
        invited_at = now,
        expires_at = now + timedelta(days=expires_in_days),
        status     = 'pending',
    )
    db.session.add(inv)
    db.session.commit()

    sent = _send_invitation_email(inv, role_name)

    log_action(
        get_jwt_identity(),
        'invitation.created',
        resource=f'invitation:{inv.id}',
        details={
            'email':       email,
            'role':        role_name,
            'expires_at':  inv.expires_at.isoformat(),
            'email_sent':  sent,
        },
    )

    body = _serialize_invitation(inv)
    body['email_delivered'] = sent
    return jsonify(body), 201


@iam_bp.route('/invitations', methods=['GET'])
@require_permission('iam:manage')
def list_invitations():
    """List invitations. Default status filter is 'pending';
    pass ?status=all to see every status, or specific values
    'accepted' / 'revoked' / 'expired'."""
    status = request.args.get('status', 'pending')
    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 25, type=int), 100)

    q = Invitation.query.order_by(Invitation.invited_at.desc())
    if status != 'all':
        q = q.filter(Invitation.status == status)

    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'invitations': [_serialize_invitation(i) for i in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page':  pagination.page,
    })


@iam_bp.route('/invitations/<inv_id>/resend', methods=['POST'])
@require_permission('iam:manage')
def resend_invitation(inv_id):
    """Re-send an existing pending invitation. Same token; expiry
    optionally extended (capped at 30 days from original
    invited_at). Rate-limited per-invitation: max 3 resends, no
    closer than 5 min apart."""
    inv = db.session.get(Invitation, inv_id)
    if inv is None:
        return jsonify({'error': 'invitation_not_found'}), 404

    if inv.status != 'pending':
        return jsonify({
            'error':   'not_pending',
            'message': f"Cannot resend an invitation with status={inv.status}",
        }), 400

    if inv.resend_count >= INVITATION_RESEND_MAX:
        return jsonify({
            'error':   'resend_limit_exceeded',
            'message': (f"Resend limit of {INVITATION_RESEND_MAX} reached "
                        f"for this invitation. Revoke and re-invite."),
        }), 429

    if inv.last_resent_at is not None:
        elapsed = (datetime.now(timezone.utc)
                   - inv.last_resent_at.replace(tzinfo=timezone.utc)
                   ).total_seconds()
        if elapsed < INVITATION_RESEND_COOLDOWN_S:
            wait_min = int((INVITATION_RESEND_COOLDOWN_S - elapsed) // 60) + 1
            return jsonify({
                'error':   'resend_cooldown',
                'message': (f"Resent too recently. Wait ~{wait_min} "
                            f"minute(s) and try again."),
            }), 429

    data = request.get_json(silent=True) or {}
    extend_days = data.get('extend_expiry_days')
    if extend_days is not None:
        try:
            extend_days = int(extend_days)
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid_extend_expiry_days'}), 400
        if extend_days < 0:
            return jsonify({'error': 'invalid_extend_expiry_days'}), 400
        # Cap: 30 days from original invited_at.
        max_expiry = inv.invited_at + timedelta(days=30)
        new_expiry = min(
            datetime.now(timezone.utc) + timedelta(days=extend_days),
            max_expiry,
        )
        # Naive-datetime comparison guard for nullable awareness.
        if new_expiry.tzinfo is not None:
            new_expiry = new_expiry.replace(tzinfo=None)
        inv.expires_at = new_expiry

    role = db.session.get(Role, inv.role_id)
    role_name = role.name if role else 'unknown'
    sent = _send_invitation_email(inv, role_name)

    inv.resend_count   += 1
    inv.last_resent_at  = datetime.now(timezone.utc)
    db.session.commit()

    log_action(
        get_jwt_identity(),
        'invitation.resent',
        resource=f'invitation:{inv.id}',
        details={
            'email_sent':   sent,
            'resend_count': inv.resend_count,
            'expires_at':   inv.expires_at.isoformat(),
        },
    )

    body = _serialize_invitation(inv)
    body['email_delivered'] = sent
    return jsonify(body), 200


@iam_bp.route('/invitations/<inv_id>/revoke', methods=['POST'])
@require_permission('iam:manage')
def revoke_invitation(inv_id):
    """Revoke a pending or expired invitation. Already-accepted
    invitations cannot be revoked (use member /remove instead)."""
    inv = db.session.get(Invitation, inv_id)
    if inv is None:
        return jsonify({'error': 'invitation_not_found'}), 404

    if inv.status == 'accepted':
        return jsonify({
            'error':   'already_accepted',
            'message': ("Cannot revoke an accepted invitation; "
                        "use the member remove endpoint instead."),
        }), 400

    if inv.status == 'revoked':
        # Idempotent.
        return jsonify(_serialize_invitation(inv)), 200

    data   = request.get_json(silent=True) or {}
    reason = data.get('reason')
    actor  = get_jwt_identity()

    inv.status     = 'revoked'
    inv.revoked_at = datetime.now(timezone.utc)
    inv.revoked_by = int(actor) if actor is not None else None
    db.session.commit()

    log_action(
        actor,
        'invitation.revoked',
        resource=f'invitation:{inv.id}',
        details={'reason': reason} if reason else None,
    )
    return jsonify(_serialize_invitation(inv)), 200


# ── Audit log ────────────────────────────────────────────────
# Phase B § 8 F5/F6: the JSON list and the CSV export share the
# same filter parser + WHERE-clause builder so behaviour stays in
# lockstep across both surfaces. Index coverage for these columns
# is currently nil (only the PK on id); at v1 row counts that's
# fine, but a composite index on (timestamp DESC, action, user_id)
# is tracked as a separate F-row for when scale justifies it.

# Hard cap on a single CSV export. Larger downloads are not
# silently truncated; the caller gets a 400 instructing them to
# narrow filters.
AUDIT_EXPORT_CAP = 10_000


def _parse_audit_filters(args):
    """Parse the audit-log query filters from a Flask `request.args`-
    like mapping. Returns ``(filters_dict, error_response_or_none)``.

    On invalid input (malformed datetime, non-integer actor),
    returns ``(None, (json_response, 400))``. Caller short-circuits.
    """
    filters = {}

    # since/until: ISO 8601, inclusive lower / exclusive upper.
    # Accept the JS-friendly trailing-Z form by translating to +00:00.
    for key in ('since', 'until'):
        raw = args.get(key)
        if raw:
            try:
                filters[key] = datetime.fromisoformat(raw.replace('Z', '+00:00'))
            except ValueError:
                return None, (jsonify({
                    'error':   'invalid_filter',
                    'field':   key,
                    'message': f"'{key}' must be ISO 8601 datetime; got {raw!r}",
                }), 400)

    # actor: integer user id (matches audit_log.user_id).
    actor_raw = args.get('actor')
    if actor_raw is not None and actor_raw != '':
        try:
            filters['actor'] = int(actor_raw)
        except ValueError:
            return None, (jsonify({
                'error':   'invalid_filter',
                'field':   'actor',
                'message': f"'actor' must be an integer user id; got {actor_raw!r}",
            }), 400)

    # action / status: exact match. resource: partial (ILIKE).
    for key in ('action', 'resource', 'status'):
        raw = args.get(key)
        if raw:
            filters[key] = raw

    return filters, None


def _apply_audit_filters(query, filters):
    """Add WHERE clauses to a SQLAlchemy `query` based on parsed
    filters. All present filters AND together; absent filters are
    left out (no constraint)."""
    if 'since' in filters:
        query = query.filter(AuditLog.timestamp >= filters['since'])
    if 'until' in filters:
        query = query.filter(AuditLog.timestamp <  filters['until'])
    if 'action' in filters:
        query = query.filter(AuditLog.action == filters['action'])
    if 'actor' in filters:
        query = query.filter(AuditLog.user_id == filters['actor'])
    if 'resource' in filters:
        query = query.filter(
            AuditLog.resource.ilike(f"%{filters['resource']}%")
        )
    if 'status' in filters:
        query = query.filter(AuditLog.status == filters['status'])
    return query


@iam_bp.route('/audit', methods=['GET'])
@require_permission('audit:read')
def get_audit_log():
    filters, error = _parse_audit_filters(request.args)
    if error is not None:
        return error

    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    base = AuditLog.query.order_by(AuditLog.timestamp.desc())
    base = _apply_audit_filters(base, filters)

    logs = base.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        # F2-discovered hardening: l.timestamp can be NULL for rows
        # inserted via raw SQL that bypassed the Python-level
        # default. Coalesce here so the handler doesn't crash; an
        # Alembic migration adding DB-level DEFAULT NOW() is tracked
        # separately as Phase B § 8 F8.
        'logs': [{
            'id': l.id, 'user_id': l.user_id, 'action': l.action,
            'resource': l.resource, 'ip_address': l.ip_address,
            'timestamp': l.timestamp.isoformat() if l.timestamp else None,
            'status': l.status,
        } for l in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'page':  logs.page,
    })


@iam_bp.route('/audit/export', methods=['GET'])
@require_permission('iam:manage')
def export_audit_log():
    """CSV export of audit log entries matching the same filters as
    /api/iam/audit. Hard cap at AUDIT_EXPORT_CAP rows -- callers
    over-cap get a 400 with the count + cap so they can narrow."""
    import io, csv, json as json_lib

    filters, error = _parse_audit_filters(request.args)
    if error is not None:
        return error

    base = AuditLog.query.order_by(AuditLog.timestamp.desc())
    base = _apply_audit_filters(base, filters)

    matching = base.count()
    if matching > AUDIT_EXPORT_CAP:
        return jsonify({
            'error':         'export_too_large',
            'matching_rows': matching,
            'limit':         AUDIT_EXPORT_CAP,
            'message': (
                f'Export would return {matching} rows; cap is '
                f'{AUDIT_EXPORT_CAP}. Narrow filters and try again.'
            ),
        }), 400

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        'timestamp', 'user_id', 'action', 'resource',
        'status', 'ip_address', 'user_agent', 'node_meta_json',
    ])
    for row in base.all():
        writer.writerow([
            row.timestamp.isoformat() if row.timestamp else '',
            row.user_id if row.user_id is not None else '',
            row.action or '',
            row.resource or '',
            row.status or '',
            row.ip_address or '',
            row.user_agent or '',
            json_lib.dumps(row.node_meta) if row.node_meta is not None else '',
        ])

    timestamp_str = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'audit_log_{timestamp_str}.csv'

    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type':        'text/csv; charset=utf-8',
        },
    )

# ── SSO providers ────────────────────────────────────────────
@iam_bp.route('/sso', methods=['GET'])
@require_permission('sso:manage')
def get_sso_providers():
    providers = SSOProvider.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'enabled': p.enabled,
        'tenant_id': p.tenant_id, 'metadata_url': p.metadata_url
    } for p in providers])

@iam_bp.route('/sso', methods=['POST'])
@require_permission('sso:manage')
def configure_sso():
    data = request.get_json()
    provider = SSOProvider(
        name         = data.get('name'),
        client_id    = data.get('client_id'),
        tenant_id    = data.get('tenant_id'),
        metadata_url = data.get('metadata_url'),
        enabled      = data.get('enabled', False)
    )
    db.session.add(provider)
    db.session.commit()
    log_action(get_jwt_identity(), 'sso_configured', resource=data.get('name'))
    return jsonify({'message': 'SSO provider configured', 'id': provider.id}), 201

# ── Seed default roles ───────────────────────────────────────
def seed_default_roles():
    """Create default roles and permissions if they don't exist."""
    default_roles = [
        {'name': 'owner',   'description': 'Full platform access including billing and IAM'},
        {'name': 'admin',   'description': 'Full security access, no billing'},
        {'name': 'analyst', 'description': 'Read, scan, and analyse — no admin settings'},
        {'name': 'viewer',  'description': 'Read-only access to findings and reports'},
    ]
    default_permissions = [
        {'name': 'scan:create',   'resource': 'scan',     'action': 'create'},
        {'name': 'scan:read',     'resource': 'scan',     'action': 'read'},
        {'name': 'findings:read', 'resource': 'findings', 'action': 'read'},
        {'name': 'reports:read',  'resource': 'reports',  'action': 'read'},
        {'name': 'reports:create','resource': 'reports',  'action': 'create'},
        {'name': 'billing:manage','resource': 'billing',  'action': 'manage'},
        {'name': 'iam:manage',    'resource': 'iam',      'action': 'manage'},
        {'name': 'audit:read',    'resource': 'audit',    'action': 'read'},
        {'name': 'sso:manage',    'resource': 'sso',      'action': 'manage'},
        {'name': 'terminal:use',  'resource': 'terminal', 'action': 'use'},
    ]
    for rdata in default_roles:
        if not Role.query.filter_by(name=rdata['name']).first():
            db.session.add(Role(**rdata))
    for pdata in default_permissions:
        if not Permission.query.filter_by(name=pdata['name']).first():
            db.session.add(Permission(**pdata))
    db.session.commit()
