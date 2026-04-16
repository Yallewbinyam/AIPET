from datetime import datetime, timezone
from dashboard.backend.models import db

class SiemIncident(db.Model):
    __tablename__ = "siem_incidents"
    id          = db.Column(db.Integer,  primary_key=True)
    title       = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text,     nullable=True)
    severity    = db.Column(db.String(20), nullable=False)
    status      = db.Column(db.String(50), default="open")
    assigned_to = db.Column(db.Integer,  db.ForeignKey("users.id"), nullable=True)
    created_by  = db.Column(db.Integer,  db.ForeignKey("users.id"), nullable=True)
    event_count = db.Column(db.Integer,  default=0)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    def to_dict(self):
        return {"id": self.id, "title": self.title, "description": self.description,
                "severity": self.severity, "status": self.status,
                "assigned_to": self.assigned_to, "event_count": self.event_count,
                "created_at": str(self.created_at), "updated_at": str(self.updated_at)}

class SiemEvent(db.Model):
    __tablename__ = "siem_events"
    id          = db.Column(db.Integer,  primary_key=True)
    event_type  = db.Column(db.String(100), nullable=False)
    source      = db.Column(db.String(200), nullable=False)
    severity    = db.Column(db.String(20), nullable=False)
    title       = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text,     nullable=True)
    raw_payload = db.Column(db.Text,     nullable=True)
    mitre_id    = db.Column(db.String(50), nullable=True)
    user_id     = db.Column(db.Integer,  db.ForeignKey("users.id"), nullable=True)
    incident_id = db.Column(db.Integer,  db.ForeignKey("siem_incidents.id"), nullable=True)
    acknowledged= db.Column(db.Boolean,  default=False)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    def to_dict(self):
        return {"id": self.id, "event_type": self.event_type, "source": self.source,
                "severity": self.severity, "title": self.title,
                "description": self.description, "mitre_id": self.mitre_id,
                "incident_id": self.incident_id, "acknowledged": self.acknowledged,
                "created_at": str(self.created_at)}

class SiemRule(db.Model):
    __tablename__ = "siem_rules"
    id            = db.Column(db.Integer,  primary_key=True)
    name          = db.Column(db.String(200), nullable=False)
    description   = db.Column(db.Text,     nullable=True)
    condition     = db.Column(db.Text,     nullable=False)
    action        = db.Column(db.String(50), default="alert")
    severity      = db.Column(db.String(20), default="High")
    enabled       = db.Column(db.Boolean,  default=True)
    trigger_count = db.Column(db.Integer,  default=0)
    created_by    = db.Column(db.Integer,  db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    def to_dict(self):
        return {"id": self.id, "name": self.name, "description": self.description,
                "condition": self.condition, "action": self.action,
                "severity": self.severity, "enabled": self.enabled,
                "trigger_count": self.trigger_count, "created_at": str(self.created_at)}
