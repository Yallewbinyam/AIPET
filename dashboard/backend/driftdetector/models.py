"""
AIPET X — Cloud-Identity Drift Detector Models

Three tables:
  dd_baselines  — baseline snapshots of identity permissions
  dd_drifts     — detected permission changes from baseline
  dd_scans      — drift scan runs
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class DdBaseline(db.Model):
    """
    A baseline snapshot of an identity's permissions.
    This is the 'expected' state — what permissions should exist.

    identity_type: user | role | service_account | api_key
    provider:      aws | azure | gcp | on_premise
    permissions:   JSON list of permissions at baseline time
    drift_score:   0=no drift, 100=severely drifted
    """
    __tablename__ = "dd_baselines"

    id             = db.Column(db.Integer,     primary_key=True)
    identity_name  = db.Column(db.String(200), nullable=False)
    identity_type  = db.Column(db.String(50),  nullable=False)
    provider       = db.Column(db.String(50),  nullable=False)
    environment    = db.Column(db.String(50),  default="production")
    permissions    = db.Column(db.Text,        nullable=True)   # JSON
    permission_count = db.Column(db.Integer,   default=0)
    drift_score    = db.Column(db.Integer,     default=0)
    drift_count    = db.Column(db.Integer,     default=0)
    status         = db.Column(db.String(30),  default="active")
    last_scanned   = db.Column(db.DateTime,    nullable=True)
    baseline_set_at= db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":               self.id,
            "identity_name":    self.identity_name,
            "identity_type":    self.identity_type,
            "provider":         self.provider,
            "environment":      self.environment,
            "permissions":      json.loads(self.permissions) if self.permissions else [],
            "permission_count": self.permission_count,
            "drift_score":      self.drift_score,
            "drift_count":      self.drift_count,
            "status":           self.status,
            "last_scanned":     str(self.last_scanned) if self.last_scanned else None,
            "baseline_set_at":  str(self.baseline_set_at),
        }


class DdDrift(db.Model):
    """
    A detected permission drift from baseline.

    drift_type:  permission_added | permission_removed |
                 role_added | role_removed | policy_changed |
                 privilege_escalation | dormant_activation
    severity:    Critical | High | Medium | Low
    old_value:   what the permission/role was before
    new_value:   what it is now
    """
    __tablename__ = "dd_drifts"

    id            = db.Column(db.Integer,     primary_key=True)
    baseline_id   = db.Column(db.Integer,     db.ForeignKey("dd_baselines.id"), nullable=False)
    identity_name = db.Column(db.String(200), nullable=False)
    drift_type    = db.Column(db.String(100), nullable=False)
    severity      = db.Column(db.String(20),  default="Medium")
    title         = db.Column(db.String(300), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    old_value     = db.Column(db.Text,        nullable=True)
    new_value     = db.Column(db.Text,        nullable=True)
    remediation   = db.Column(db.Text,        nullable=True)
    regulation    = db.Column(db.String(200), nullable=True)
    status        = db.Column(db.String(30),  default="open")
    detected_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    resolved_at   = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":            self.id,
            "baseline_id":   self.baseline_id,
            "identity_name": self.identity_name,
            "drift_type":    self.drift_type,
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "old_value":     self.old_value,
            "new_value":     self.new_value,
            "remediation":   self.remediation,
            "regulation":    self.regulation,
            "status":        self.status,
            "detected_at":   str(self.detected_at),
            "resolved_at":   str(self.resolved_at) if self.resolved_at else None,
        }


class DdScan(db.Model):
    """A drift detection scan run."""
    __tablename__ = "dd_scans"

    id              = db.Column(db.Integer,  primary_key=True)
    identities_scanned = db.Column(db.Integer, default=0)
    drifts_found    = db.Column(db.Integer,  default=0)
    critical_drifts = db.Column(db.Integer,  default=0)
    duration_sec    = db.Column(db.Integer,  default=0)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":                  self.id,
            "identities_scanned":  self.identities_scanned,
            "drifts_found":        self.drifts_found,
            "critical_drifts":     self.critical_drifts,
            "duration_sec":        self.duration_sec,
            "created_at":          str(self.created_at),
        }
