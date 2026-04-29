import uuid
from datetime import datetime
from dashboard.backend.models import db

class Role(db.Model):
    __tablename__ = 'roles'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    permissions = db.relationship('Permission', secondary='role_permissions', backref='roles')

class Permission(db.Model):
    __tablename__ = 'permissions'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    resource    = db.Column(db.String(50))
    action      = db.Column(db.String(50))

role_permissions = db.Table('role_permissions',
    db.Column('role_id',       db.String(36), db.ForeignKey('roles.id'),       primary_key=True),
    db.Column('permission_id', db.String(36), db.ForeignKey('permissions.id'), primary_key=True)
)

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role_id     = db.Column(db.String(36), db.ForeignKey('roles.id'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
    action     = db.Column(db.String(100), nullable=False)
    resource   = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    status     = db.Column(db.String(20), default='success')
    # Structured detail for any audit event. Examples:
    #   device.soft_deleted -> {"reason": "...", "device_hostname": "..."}
    #   device.restored     -> {"reason": "...", "device_hostname": "...",
    #                            "previously_deleted_at": "<iso>"}
    #   device.telemetry_after_delete -> {"telemetry_at": "<iso>",
    #                            "originally_deleted_at": "<iso>"}
    # Nullable so all existing audit_log rows remain valid.
    # Named `node_meta` per project convention -- never `metadata`.
    node_meta  = db.Column(db.JSON, nullable=True)

class SSOProvider(db.Model):
    __tablename__ = 'sso_providers'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name         = db.Column(db.String(50), nullable=False)
    client_id    = db.Column(db.Text)
    tenant_id    = db.Column(db.Text)
    metadata_url = db.Column(db.Text)
    enabled      = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)


class IssuedToken(db.Model):
    """JWT blocklist row written on every successful login. The
    `token_in_blocklist_loader` callback in app_cloud.py consults
    this table on every authenticated request -- a row with
    revoked=True flips the JWT to invalid even if its expiry hasn't
    elapsed. Tokens issued before this table existed (graceful
    upgrade path) are absent from the table; the loader treats
    "no row" as "valid" so live in-flight sessions are not killed
    by deploy."""
    __tablename__ = 'issued_tokens'
    id            = db.Column(db.String(36), primary_key=True,
                              default=lambda: str(uuid.uuid4()))
    jti           = db.Column(db.String(36), unique=True,
                              nullable=False, index=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'),
                              nullable=False, index=True)
    issued_at     = db.Column(db.DateTime,
                              default=datetime.utcnow, nullable=False)
    expires_at    = db.Column(db.DateTime, nullable=False)
    revoked       = db.Column(db.Boolean, default=False, nullable=False)
    revoked_at    = db.Column(db.DateTime, nullable=True)
    revoked_by    = db.Column(db.Integer, db.ForeignKey('users.id'),
                              nullable=True)
    revoke_reason = db.Column(db.String(50), nullable=True)
    # 'user.removed' | 'user.disabled' | 'manual.revoke' |
    # 'session.bulk_revoke' | 'logout'
