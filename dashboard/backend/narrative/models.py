"""
AIPET X — AI Risk Narrative Models

One table:
  risk_narratives — generated AI narratives stored for history
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class RiskNarrative(db.Model):
    """
    An AI-generated risk narrative for a specific audience and scope.

    audience:   executive | technical | board | compliance
    narrative:  the full generated text
    risk_score: overall risk score at time of generation
    findings:   number of findings included
    """
    __tablename__ = "risk_narratives"

    id          = db.Column(db.Integer,     primary_key=True)
    audience    = db.Column(db.String(50),  default="executive")
    narrative   = db.Column(db.Text,        nullable=False)
    risk_score  = db.Column(db.Integer,     default=0)
    findings    = db.Column(db.Integer,     default=0)
    devices     = db.Column(db.Integer,     default=0)
    tokens_used = db.Column(db.Integer,     default=0)
    created_by  = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "audience":    self.audience,
            "narrative":   self.narrative,
            "risk_score":  self.risk_score,
            "findings":    self.findings,
            "devices":     self.devices,
            "tokens_used": self.tokens_used,
            "created_at":  str(self.created_at),
        }
