import uuid
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, User
from dashboard.backend.iam.models import Role, Permission, UserRole, AuditLog, SSOProvider

iam_bp = Blueprint('iam', __name__, url_prefix='/api/iam')

# ── Audit helper ─────────────────────────────────────────────
def log_action(user_id, action, resource=None, status='success'):
    try:
        entry = AuditLog(
            user_id    = user_id,
            action     = action,
            resource   = resource,
            ip_address = request.remote_addr,
            user_agent = request.headers.get('User-Agent', ''),
            status     = status
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

# ── Audit log ────────────────────────────────────────────────
@iam_bp.route('/audit', methods=['GET'])
@require_permission('audit:read')
def get_audit_log():
    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    logs     = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'logs': [{
            'id': l.id, 'user_id': l.user_id, 'action': l.action,
            'resource': l.resource, 'ip_address': l.ip_address,
            'timestamp': l.timestamp.isoformat(), 'status': l.status
        } for l in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'page':  logs.page
    })

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
