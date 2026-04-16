"""
AIPET X — Autonomous Defense Models

Two tables:
  defense_playbooks — named response workflows
                      each playbook has a trigger condition
                      and a list of response actions to execute

  defense_actions   — immutable log of every autonomous
                      action taken — what, when, why, outcome
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class DefensePlaybook(db.Model):
    """
    A playbook is a named automated response workflow.

    trigger_field:    which event field to check (severity, event_type, source)
    trigger_op:       eq | contains | in
    trigger_value:    the value to match against
    actions:          JSON list of actions to execute on match
                      e.g. ["quarantine_device", "create_incident", "block_ip"]
    cooldown_minutes: minimum minutes between triggers (prevents storms)
    """
    __tablename__ = "defense_playbooks"

    id               = db.Column(db.Integer,     primary_key=True)
    name             = db.Column(db.String(200), nullable=False)
    description      = db.Column(db.Text,        nullable=True)
    enabled          = db.Column(db.Boolean,     default=True)
    trigger_field    = db.Column(db.String(50),  nullable=False)
    trigger_op       = db.Column(db.String(20),  nullable=False)
    trigger_value    = db.Column(db.String(200), nullable=False)
    actions          = db.Column(db.Text,        nullable=False)  # JSON list
    cooldown_minutes = db.Column(db.Integer,     default=5)
    trigger_count    = db.Column(db.Integer,     default=0)
    last_triggered   = db.Column(db.DateTime,    nullable=True)
    created_by       = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at       = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":               self.id,
            "name":             self.name,
            "description":      self.description,
            "enabled":          self.enabled,
            "trigger_field":    self.trigger_field,
            "trigger_op":       self.trigger_op,
            "trigger_value":    self.trigger_value,
            "actions":          self.actions,
            "cooldown_minutes": self.cooldown_minutes,
            "trigger_count":    self.trigger_count,
            "last_triggered":   str(self.last_triggered) if self.last_triggered else None,
            "created_at":       str(self.created_at),
        }


class DefenseAction(db.Model):
    """
    Immutable log of every autonomous action taken.
    Never updated — only inserted.
    Provides full audit trail of what AIPET did automatically.

    status: executed | failed | skipped (cooldown)
    """
    __tablename__ = "defense_actions"

    id           = db.Column(db.Integer,     primary_key=True)
    playbook_id  = db.Column(db.Integer,     db.ForeignKey("defense_playbooks.id"), nullable=True)
    playbook_name= db.Column(db.String(200), nullable=True)   # denormalised for fast reads
    action_type  = db.Column(db.String(100), nullable=False)  # quarantine_device | block_ip | create_incident | send_alert
    target       = db.Column(db.String(200), nullable=True)   # IP, event ID, etc.
    status       = db.Column(db.String(20),  default="executed")
    reason       = db.Column(db.Text,        nullable=True)
    outcome      = db.Column(db.Text,        nullable=True)   # what actually happened
    triggered_by = db.Column(db.String(100), nullable=True)   # event_id, manual, scan
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "playbook_id":   self.playbook_id,
            "playbook_name": self.playbook_name,
            "action_type":   self.action_type,
            "target":        self.target,
            "status":        self.status,
            "reason":        self.reason,
            "outcome":       self.outcome,
            "triggered_by":  self.triggered_by,
            "created_at":    str(self.created_at),
        }
