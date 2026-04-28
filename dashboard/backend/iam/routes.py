import uuid
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, User
from dashboard.backend.iam.models import Role, Permission, UserRole, AuditLog, SSOProvider

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
