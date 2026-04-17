"""
AIPET X — Attack Path Modelling Models

Two tables:
  ap_analyses — attack path analysis runs
  ap_paths    — individual attack paths found
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class ApAnalysis(db.Model):
    """An attack path analysis run."""
    __tablename__ = "ap_analyses"

    id           = db.Column(db.Integer,  primary_key=True)
    name         = db.Column(db.String(200), nullable=False)
    scope        = db.Column(db.String(200), nullable=True)
    total_paths  = db.Column(db.Integer,  default=0)
    critical_paths=db.Column(db.Integer,  default=0)
    max_depth    = db.Column(db.Integer,  default=0)
    created_by   = db.Column(db.Integer,  db.ForeignKey("users.id"), nullable=True)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "name":          self.name,
            "scope":         self.scope,
            "total_paths":   self.total_paths,
            "critical_paths":self.critical_paths,
            "max_depth":     self.max_depth,
            "created_at":    str(self.created_at),
        }


class ApPath(db.Model):
    """
    A single attack path from entry point to target.
    chain: JSON list of steps
    """
    __tablename__ = "ap_paths"

    id          = db.Column(db.Integer,     primary_key=True)
    analysis_id = db.Column(db.Integer,     db.ForeignKey("ap_analyses.id"), nullable=False)
    entry_point = db.Column(db.String(200), nullable=False)
    target      = db.Column(db.String(200), nullable=False)
    severity    = db.Column(db.String(20),  default="High")
    hops        = db.Column(db.Integer,     default=1)
    chain       = db.Column(db.Text,        nullable=True)  # JSON
    techniques  = db.Column(db.Text,        nullable=True)  # JSON list of MITRE IDs
    likelihood  = db.Column(db.Integer,     default=50)     # 0-100
    impact      = db.Column(db.String(200), nullable=True)
    blocked     = db.Column(db.Boolean,     default=False)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":          self.id,
            "analysis_id": self.analysis_id,
            "entry_point": self.entry_point,
            "target":      self.target,
            "severity":    self.severity,
            "hops":        self.hops,
            "chain":       json.loads(self.chain) if self.chain else [],
            "techniques":  json.loads(self.techniques) if self.techniques else [],
            "likelihood":  self.likelihood,
            "impact":      self.impact,
            "blocked":     self.blocked,
        }
