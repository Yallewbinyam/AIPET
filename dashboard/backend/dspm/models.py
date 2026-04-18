"""
AIPET X — Data Security Posture Management (DSPM-Lite) Models

Three tables:
  dspm_datastores  — discovered data stores and their sensitivity
  dspm_findings    — security issues with data stores
  dspm_scans       — DSPM scan runs
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class DspmDatastore(db.Model):
    """
    A discovered data store — database, S3 bucket, API, IoT stream.

    store_type:  database | object_storage | api | iot_stream |
                 file_share | message_queue | cache
    sensitivity: public | internal | confidential | restricted | secret
    data_types:  JSON list of detected data types (PII, PHI, PCI, etc.)
    risk_score:  0-100 composite risk
    """
    __tablename__ = "dspm_datastores"

    id            = db.Column(db.Integer,     primary_key=True)
    name          = db.Column(db.String(200), nullable=False)
    store_type    = db.Column(db.String(50),  nullable=False)
    location      = db.Column(db.String(200), nullable=True)
    cloud_provider= db.Column(db.String(50),  nullable=True)
    sensitivity   = db.Column(db.String(50),  default="internal")
    data_types    = db.Column(db.Text,        nullable=True)   # JSON
    size_gb       = db.Column(db.Float,       default=0.0)
    record_count  = db.Column(db.Integer,     default=0)
    encrypted_at_rest   = db.Column(db.Boolean, default=False)
    encrypted_in_transit= db.Column(db.Boolean, default=False)
    access_control      = db.Column(db.String(50), default="unknown")
    publicly_accessible = db.Column(db.Boolean, default=False)
    risk_score    = db.Column(db.Integer,     default=0)
    finding_count = db.Column(db.Integer,     default=0)
    last_scanned  = db.Column(db.DateTime,    nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":                   self.id,
            "name":                 self.name,
            "store_type":           self.store_type,
            "location":             self.location,
            "cloud_provider":       self.cloud_provider,
            "sensitivity":          self.sensitivity,
            "data_types":           json.loads(self.data_types) if self.data_types else [],
            "size_gb":              self.size_gb,
            "record_count":         self.record_count,
            "encrypted_at_rest":    self.encrypted_at_rest,
            "encrypted_in_transit": self.encrypted_in_transit,
            "access_control":       self.access_control,
            "publicly_accessible":  self.publicly_accessible,
            "risk_score":           self.risk_score,
            "finding_count":        self.finding_count,
            "last_scanned":         str(self.last_scanned) if self.last_scanned else None,
        }


class DspmFinding(db.Model):
    """A security finding on a data store."""
    __tablename__ = "dspm_findings"

    id           = db.Column(db.Integer,     primary_key=True)
    datastore_id = db.Column(db.Integer,     db.ForeignKey("dspm_datastores.id"), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)
    severity     = db.Column(db.String(20),  default="Medium")
    title        = db.Column(db.String(300), nullable=False)
    description  = db.Column(db.Text,        nullable=True)
    remediation  = db.Column(db.Text,        nullable=True)
    regulation   = db.Column(db.String(200), nullable=True)
    status       = db.Column(db.String(30),  default="open")
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "datastore_id": self.datastore_id,
            "finding_type": self.finding_type,
            "severity":     self.severity,
            "title":        self.title,
            "description":  self.description,
            "remediation":  self.remediation,
            "regulation":   self.regulation,
            "status":       self.status,
            "created_at":   str(self.created_at),
        }


class DspmScan(db.Model):
    """A DSPM scan run."""
    __tablename__ = "dspm_scans"

    id              = db.Column(db.Integer,  primary_key=True)
    datastores_found= db.Column(db.Integer,  default=0)
    findings_found  = db.Column(db.Integer,  default=0)
    critical_count  = db.Column(db.Integer,  default=0)
    duration_sec    = db.Column(db.Integer,  default=0)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":               self.id,
            "datastores_found": self.datastores_found,
            "findings_found":   self.findings_found,
            "critical_count":   self.critical_count,
            "duration_sec":     self.duration_sec,
            "created_at":       str(self.created_at),
        }
