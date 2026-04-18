"""
AIPET X — Compliance Automation Models

Three tables:
  ca_frameworks  — compliance frameworks (NIS2, ISO27001, SOC2, NIST)
  ca_controls    — individual controls within each framework
  ca_assessments — assessment runs with scores
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class CaFramework(db.Model):
    """A compliance framework — NIS2, ISO 27001, SOC 2, NIST CSF."""
    __tablename__ = "ca_frameworks"

    id           = db.Column(db.Integer,     primary_key=True)
    name         = db.Column(db.String(100), nullable=False)
    version      = db.Column(db.String(50),  nullable=True)
    description  = db.Column(db.Text,        nullable=True)
    total_controls=db.Column(db.Integer,     default=0)
    passed       = db.Column(db.Integer,     default=0)
    failed       = db.Column(db.Integer,     default=0)
    partial      = db.Column(db.Integer,     default=0)
    score        = db.Column(db.Integer,     default=0)
    last_assessed= db.Column(db.DateTime,    nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "name":          self.name,
            "version":       self.version,
            "description":   self.description,
            "total_controls":self.total_controls,
            "passed":        self.passed,
            "failed":        self.failed,
            "partial":       self.partial,
            "score":         self.score,
            "last_assessed": str(self.last_assessed) if self.last_assessed else None,
        }


class CaControl(db.Model):
    """
    An individual compliance control within a framework.

    status:   pass | fail | partial | not_applicable | not_tested
    evidence: what AIPET found to support this status
    """
    __tablename__ = "ca_controls"

    id           = db.Column(db.Integer,     primary_key=True)
    framework_id = db.Column(db.Integer,     db.ForeignKey("ca_frameworks.id"), nullable=False)
    control_id   = db.Column(db.String(50),  nullable=False)
    title        = db.Column(db.String(300), nullable=False)
    description  = db.Column(db.Text,        nullable=True)
    category     = db.Column(db.String(100), nullable=True)
    status       = db.Column(db.String(30),  default="not_tested")
    evidence     = db.Column(db.Text,        nullable=True)
    gap          = db.Column(db.Text,        nullable=True)
    remediation  = db.Column(db.Text,        nullable=True)
    severity     = db.Column(db.String(20),  default="Medium")
    automated    = db.Column(db.Boolean,     default=True)
    last_tested  = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "framework_id": self.framework_id,
            "control_id":   self.control_id,
            "title":        self.title,
            "description":  self.description,
            "category":     self.category,
            "status":       self.status,
            "evidence":     self.evidence,
            "gap":          self.gap,
            "remediation":  self.remediation,
            "severity":     self.severity,
            "automated":    self.automated,
            "last_tested":  str(self.last_tested) if self.last_tested else None,
        }


class CaAssessment(db.Model):
    """A compliance assessment run — snapshot of scores at a point in time."""
    __tablename__ = "ca_assessments"

    id           = db.Column(db.Integer,  primary_key=True)
    framework_id = db.Column(db.Integer,  db.ForeignKey("ca_frameworks.id"), nullable=False)
    score        = db.Column(db.Integer,  default=0)
    passed       = db.Column(db.Integer,  default=0)
    failed       = db.Column(db.Integer,  default=0)
    partial      = db.Column(db.Integer,  default=0)
    triggered_by = db.Column(db.String(100), nullable=True)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "framework_id": self.framework_id,
            "score":        self.score,
            "passed":       self.passed,
            "failed":       self.failed,
            "partial":      self.partial,
            "triggered_by": self.triggered_by,
            "created_at":   str(self.created_at),
        }
