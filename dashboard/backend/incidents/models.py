"""
AIPET X — Incident Response Models

Two tables:
  ir_incidents — security incidents with full lifecycle
  ir_tasks     — tasks within an incident
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class IrIncident(db.Model):
    """
    A security incident — a confirmed or suspected security event
    requiring investigation and response.

    status:   open | investigating | containing | resolved | closed
    priority: P1 (Critical) | P2 (High) | P3 (Medium) | P4 (Low)
    """
    __tablename__ = "ir_incidents"

    id            = db.Column(db.Integer,     primary_key=True)
    title         = db.Column(db.String(300), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    status        = db.Column(db.String(30),  default="open")
    priority      = db.Column(db.String(10),  default="P2")
    affected      = db.Column(db.Text,        nullable=True)
    attack_vector = db.Column(db.String(200), nullable=True)
    mitre_id      = db.Column(db.String(50),  nullable=True)
    assigned_to   = db.Column(db.String(200), nullable=True)
    timeline_ref  = db.Column(db.Integer,     nullable=True)
    resolution    = db.Column(db.Text,        nullable=True)
    lessons       = db.Column(db.Text,        nullable=True)
    created_by    = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    resolved_at   = db.Column(db.DateTime,    nullable=True)
    sla_hours     = db.Column(db.Integer,     default=24)

    def to_dict(self):
        now = datetime.now(timezone.utc)
        age = (now - self.created_at.replace(tzinfo=timezone.utc)
               if self.created_at else None)
        breached = (age.total_seconds()/3600 > self.sla_hours
                    if age and self.status not in ("resolved","closed") else False)
        return {
            "id":            self.id,
            "title":         self.title,
            "description":   self.description,
            "status":        self.status,
            "priority":      self.priority,
            "affected":      self.affected,
            "attack_vector": self.attack_vector,
            "mitre_id":      self.mitre_id,
            "assigned_to":   self.assigned_to,
            "resolution":    self.resolution,
            "lessons":       self.lessons,
            "created_at":    str(self.created_at),
            "resolved_at":   str(self.resolved_at) if self.resolved_at else None,
            "sla_hours":     self.sla_hours,
            "sla_breached":  breached,
            "age_hours":     round(age.total_seconds()/3600, 1) if age else 0,
        }


class IrTask(db.Model):
    """
    A task within an incident — investigation steps, containment actions.
    """
    __tablename__ = "ir_tasks"

    id          = db.Column(db.Integer,     primary_key=True)
    incident_id = db.Column(db.Integer,     db.ForeignKey("ir_incidents.id"), nullable=False)
    title       = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text,        nullable=True)
    status      = db.Column(db.String(20),  default="pending")
    assigned_to = db.Column(db.String(200), nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    completed_at= db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "incident_id":  self.incident_id,
            "title":        self.title,
            "description":  self.description,
            "status":       self.status,
            "assigned_to":  self.assigned_to,
            "created_at":   str(self.created_at),
            "completed_at": str(self.completed_at) if self.completed_at else None,
        }
