from datetime import datetime, timezone
from dashboard.backend.models import db


class ResponseThreshold(db.Model):
    __tablename__ = "response_thresholds"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name        = db.Column(db.String(64),  nullable=False)   # "notify", "high_alert", "emergency"
    description = db.Column(db.String(256), nullable=True)

    # Trigger condition
    min_score   = db.Column(db.Integer,  nullable=False)       # 0-100

    # Action — one playbook per threshold
    playbook_id = db.Column(db.Integer, db.ForeignKey("defense_playbooks.id"), nullable=True)

    # State
    enabled        = db.Column(db.Boolean, default=True, nullable=False)
    cooldown_hours = db.Column(db.Integer, default=4,    nullable=False)

    # Metadata
    node_meta        = db.Column(db.JSON, default=dict)   # NEVER "metadata"
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_modified_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_threshold_user_name"),
        db.Index("ix_threshold_user_score", "user_id", "min_score"),
    )

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "user_id":         self.user_id,
            "name":            self.name,
            "description":     self.description,
            "min_score":       self.min_score,
            "playbook_id":     self.playbook_id,
            "enabled":         self.enabled,
            "cooldown_hours":  self.cooldown_hours,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "last_modified_at":self.last_modified_at.isoformat() if self.last_modified_at else None,
        }


class ResponseHistory(db.Model):
    __tablename__ = "response_history"

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    entity       = db.Column(db.String(256), nullable=False)
    entity_type  = db.Column(db.String(32),  nullable=True)
    playbook_id  = db.Column(db.Integer, db.ForeignKey("defense_playbooks.id"), nullable=False)
    threshold_id = db.Column(db.Integer, db.ForeignKey("response_thresholds.id"), nullable=True)

    # What happened
    triggering_score     = db.Column(db.Integer, nullable=False)
    threshold_min_score  = db.Column(db.Integer, nullable=False)
    threshold_name       = db.Column(db.String(64), nullable=True)
    actions_executed     = db.Column(db.JSON, default=list)
    status               = db.Column(db.String(32), default="executed")

    # Notifications
    slack_sent          = db.Column(db.Boolean, default=False)
    teams_sent          = db.Column(db.Boolean, default=False)
    notification_error  = db.Column(db.Text, nullable=True)

    # Audit
    fired_at        = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False, index=True)
    central_event_id = db.Column(db.Integer, nullable=True)
    node_meta       = db.Column(db.JSON, default=dict)

    __table_args__ = (
        # Critical for cooldown query: "has (user, entity, playbook) fired within N hours?"
        db.Index("ix_history_cooldown", "user_id", "entity", "playbook_id", "fired_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id":                   self.id,
            "user_id":              self.user_id,
            "entity":               self.entity,
            "entity_type":          self.entity_type,
            "playbook_id":          self.playbook_id,
            "threshold_id":         self.threshold_id,
            "threshold_name":       self.threshold_name,
            "triggering_score":     self.triggering_score,
            "threshold_min_score":  self.threshold_min_score,
            "actions_executed":     self.actions_executed or [],
            "status":               self.status,
            "slack_sent":           self.slack_sent,
            "teams_sent":           self.teams_sent,
            "notification_error":   self.notification_error,
            "fired_at":             self.fired_at.isoformat() if self.fired_at else None,
            "central_event_id":     self.central_event_id,
        }
