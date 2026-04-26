# =============================================================
# AIPET X — Agent API Key Model
# Per-device non-expiring keys for agent authentication.
# Keys hashed with bcrypt at rest; shown once at creation.
# =============================================================

from datetime import datetime, timezone
from ..models import db


class AgentApiKey(db.Model):
    __tablename__ = "agent_api_keys"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    label = db.Column(db.String(128), nullable=False)
    key_prefix = db.Column(db.String(20), nullable=False, index=True)  # "aipet_" + 8 chars
    key_hash = db.Column(db.String(255), nullable=False)               # bcrypt hash

    scope = db.Column(db.String(64), nullable=False, default="agent")
    permissions = db.Column(db.JSON, default=list)  # ["scan:write", "telemetry:write"]

    enabled = db.Column(db.Boolean, default=True, nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_reason = db.Column(db.String(256), nullable=True)

    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_used_ip = db.Column(db.String(64), nullable=True)
    use_count = db.Column(db.Integer, default=0)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # NULL = never expires
    node_meta = db.Column(db.JSON, default=dict)  # NEVER metadata

    __table_args__ = (
        db.Index("ix_agent_keys_prefix_enabled", "key_prefix", "enabled"),
        db.Index("ix_agent_keys_user_enabled", "user_id", "enabled"),
    )

    def to_dict(self, include_prefix=True):
        return {
            "id":           self.id,
            "label":        self.label,
            "key_prefix":   self.key_prefix if include_prefix else None,
            "scope":        self.scope,
            "permissions":  self.permissions or [],
            "enabled":      self.enabled,
            "revoked_at":   self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "last_used_ip": self.last_used_ip,
            "use_count":    self.use_count,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "expires_at":   self.expires_at.isoformat() if self.expires_at else None,
        }
