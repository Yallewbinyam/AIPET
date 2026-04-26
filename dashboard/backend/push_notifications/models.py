"""
AIPET X — Push Notification Subscription Model (Capability 12)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class PushSubscription(db.Model):
    __tablename__ = "push_subscriptions"

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    # Browser-supplied subscription data
    endpoint     = db.Column(db.Text, nullable=False, unique=True)
    p256dh_key   = db.Column(db.Text, nullable=False)
    auth_secret  = db.Column(db.Text, nullable=False)

    # Device context
    user_agent   = db.Column(db.String(512), nullable=True)
    device_label = db.Column(db.String(128), nullable=True)

    # State
    enabled          = db.Column(db.Boolean, default=True, nullable=False)
    last_sent_at     = db.Column(db.DateTime(timezone=True), nullable=True)
    last_failure_at  = db.Column(db.DateTime(timezone=True), nullable=True)
    failure_count    = db.Column(db.Integer, default=0, nullable=False)

    # Audit
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    node_meta = db.Column(db.JSON, default=dict)  # NEVER "metadata"

    __table_args__ = (
        db.Index("ix_push_user_enabled", "user_id", "enabled"),
    )

    def to_safe_dict(self):
        """Returns subscription info without the sensitive key material."""
        return {
            "id":           self.id,
            "device_label": self.device_label or "Browser",
            "user_agent":   (self.user_agent or "")[:80],
            "enabled":      self.enabled,
            "last_sent_at": self.last_sent_at.isoformat() if self.last_sent_at else None,
            "failure_count": self.failure_count,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
        }
