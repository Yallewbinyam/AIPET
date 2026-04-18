"""
AIPET X — API Security Layer Models

Three tables:
  as_endpoints  — discovered API endpoints
  as_findings   — security findings per endpoint
  as_scans      — API security scan runs
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class AsEndpoint(db.Model):
    """
    A discovered API endpoint with security assessment.

    method:      GET | POST | PUT | DELETE | PATCH
    auth_type:   none | api_key | jwt | oauth2 | basic
    risk_score:  0-100
    """
    __tablename__ = "as_endpoints"

    id              = db.Column(db.Integer,     primary_key=True)
    path            = db.Column(db.String(500), nullable=False)
    method          = db.Column(db.String(10),  nullable=False)
    service         = db.Column(db.String(200), nullable=True)
    version         = db.Column(db.String(20),  nullable=True)
    auth_type       = db.Column(db.String(50),  default="none")
    authenticated   = db.Column(db.Boolean,     default=False)
    rate_limited    = db.Column(db.Boolean,     default=False)
    encrypted       = db.Column(db.Boolean,     default=True)
    has_cors        = db.Column(db.Boolean,     default=False)
    cors_wildcard   = db.Column(db.Boolean,     default=False)
    sensitive_data  = db.Column(db.Boolean,     default=False)
    deprecated      = db.Column(db.Boolean,     default=False)
    risk_score      = db.Column(db.Integer,     default=0)
    finding_count   = db.Column(db.Integer,     default=0)
    last_tested     = db.Column(db.DateTime,    nullable=True)
    created_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":             self.id,
            "path":           self.path,
            "method":         self.method,
            "service":        self.service,
            "version":        self.version,
            "auth_type":      self.auth_type,
            "authenticated":  self.authenticated,
            "rate_limited":   self.rate_limited,
            "encrypted":      self.encrypted,
            "has_cors":       self.has_cors,
            "cors_wildcard":  self.cors_wildcard,
            "sensitive_data": self.sensitive_data,
            "deprecated":     self.deprecated,
            "risk_score":     self.risk_score,
            "finding_count":  self.finding_count,
            "last_tested":    str(self.last_tested) if self.last_tested else None,
        }


class AsFinding(db.Model):
    """
    A security finding on an API endpoint.

    finding_type: broken_auth | excessive_exposure | no_rate_limit |
                  cors_misconfiguration | sensitive_in_url |
                  outdated_version | injection_risk | mass_assignment |
                  missing_encryption | info_disclosure
    owasp_id:     OWASP API Security Top 10 reference
    """
    __tablename__ = "as_findings"

    id           = db.Column(db.Integer,     primary_key=True)
    endpoint_id  = db.Column(db.Integer,     db.ForeignKey("as_endpoints.id"), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)
    severity     = db.Column(db.String(20),  default="Medium")
    owasp_id     = db.Column(db.String(20),  nullable=True)
    title        = db.Column(db.String(300), nullable=False)
    description  = db.Column(db.Text,        nullable=True)
    evidence     = db.Column(db.Text,        nullable=True)
    remediation  = db.Column(db.Text,        nullable=True)
    status       = db.Column(db.String(30),  default="open")
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "endpoint_id":  self.endpoint_id,
            "finding_type": self.finding_type,
            "severity":     self.severity,
            "owasp_id":     self.owasp_id,
            "title":        self.title,
            "description":  self.description,
            "evidence":     self.evidence,
            "remediation":  self.remediation,
            "status":       self.status,
            "created_at":   str(self.created_at),
        }


class AsScan(db.Model):
    """An API security scan run."""
    __tablename__ = "as_scans"

    id               = db.Column(db.Integer,  primary_key=True)
    endpoints_scanned= db.Column(db.Integer,  default=0)
    findings_found   = db.Column(db.Integer,  default=0)
    critical_count   = db.Column(db.Integer,  default=0)
    duration_sec     = db.Column(db.Integer,  default=0)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":                self.id,
            "endpoints_scanned": self.endpoints_scanned,
            "findings_found":    self.findings_found,
            "critical_count":    self.critical_count,
            "duration_sec":      self.duration_sec,
            "created_at":        str(self.created_at),
        }
