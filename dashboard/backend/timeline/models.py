"""
AIPET X — Unified Security Timeline Models

One table:
  timeline_events — every security event across the platform
                    populated by triggers from all modules
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class TimelineEvent(db.Model):
    """
    A single event in the unified security timeline.

    source:     which module generated this event
                scan | finding | siem | redteam | compliance |
                zerotrust | defense | watch | predict | user
    event_type: specific type within source
    severity:   Critical | High | Medium | Low | Info
    title:      short human-readable summary
    detail:     full description
    entity:     what was affected (device IP, user, campaign name)
    mitre_id:   MITRE ATT&CK ID if applicable
    resolved:   whether this event has been resolved
    """
    __tablename__ = "timeline_events"

    id         = db.Column(db.Integer,     primary_key=True)
    source     = db.Column(db.String(50),  nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    severity   = db.Column(db.String(20),  default="Info")
    title      = db.Column(db.String(300), nullable=False)
    detail     = db.Column(db.Text,        nullable=True)
    entity     = db.Column(db.String(200), nullable=True)
    mitre_id   = db.Column(db.String(50),  nullable=True)
    user_id    = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    resolved   = db.Column(db.Boolean,     default=False)
    created_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "source":     self.source,
            "event_type": self.event_type,
            "severity":   self.severity,
            "title":      self.title,
            "detail":     self.detail,
            "entity":     self.entity,
            "mitre_id":   self.mitre_id,
            "user_id":    self.user_id,
            "resolved":   self.resolved,
            "created_at": str(self.created_at),
        }
