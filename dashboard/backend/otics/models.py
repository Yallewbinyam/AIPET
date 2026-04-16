"""
AIPET X — OT/ICS Security Models

Three tables:
  ot_devices   — registered OT/ICS devices with protocol and zone info
  ot_scans     — OT-specific protocol scan sessions
  ot_findings  — vulnerabilities specific to industrial protocols
                 (exposed registers, unauthenticated access, insecure configs)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class OtDevice(db.Model):
    """
    An OT/ICS device in the industrial network.

    protocol:   modbus | dnp3 | iec61850 | ethernetip | bacnet
    zone:       purdue model zone — field | control | supervisory | enterprise
    criticality: how critical is this device to operations
                 critical = plant shutdown if compromised
                 high     = significant operational impact
                 medium   = degraded operations
                 low      = minimal impact
    """
    __tablename__ = "ot_devices"

    id            = db.Column(db.Integer,     primary_key=True)
    device_ip     = db.Column(db.String(100), nullable=False)
    device_name   = db.Column(db.String(200), nullable=True)
    protocol      = db.Column(db.String(50),  nullable=False)
    port          = db.Column(db.Integer,     nullable=True)
    vendor        = db.Column(db.String(200), nullable=True)
    model         = db.Column(db.String(200), nullable=True)
    firmware      = db.Column(db.String(100), nullable=True)
    zone          = db.Column(db.String(50),  default="field")
    criticality   = db.Column(db.String(20),  default="high")
    location      = db.Column(db.String(200), nullable=True)
    last_seen     = db.Column(db.DateTime,    nullable=True)
    online        = db.Column(db.Boolean,     default=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "device_ip":   self.device_ip,
            "device_name": self.device_name,
            "protocol":    self.protocol,
            "port":        self.port,
            "vendor":      self.vendor,
            "model":       self.model,
            "firmware":    self.firmware,
            "zone":        self.zone,
            "criticality": self.criticality,
            "location":    self.location,
            "last_seen":   str(self.last_seen) if self.last_seen else None,
            "online":      self.online,
            "created_at":  str(self.created_at),
        }


class OtScan(db.Model):
    """
    An OT/ICS protocol scan session.
    Scans are non-intrusive by design — read-only queries only.
    Writing to industrial control registers can cause physical damage.
    """
    __tablename__ = "ot_scans"

    id            = db.Column(db.Integer,     primary_key=True)
    target        = db.Column(db.String(200), nullable=False)
    protocol      = db.Column(db.String(50),  nullable=False)
    status        = db.Column(db.String(30),  default="pending")
    findings_count= db.Column(db.Integer,     default=0)
    risk_level    = db.Column(db.String(20),  nullable=True)
    scan_duration = db.Column(db.Float,       nullable=True)
    user_id       = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    completed_at  = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":             self.id,
            "target":         self.target,
            "protocol":       self.protocol,
            "status":         self.status,
            "findings_count": self.findings_count,
            "risk_level":     self.risk_level,
            "scan_duration":  self.scan_duration,
            "created_at":     str(self.created_at),
            "completed_at":   str(self.completed_at) if self.completed_at else None,
        }


class OtFinding(db.Model):
    """
    A vulnerability or security issue found in an OT/ICS device.

    finding_type categories:
      unauthenticated_access  — device accepts commands without auth
      exposed_registers       — sensitive Modbus/DNP3 registers readable
      default_credentials     — vendor default passwords unchanged
      unencrypted_comms       — plaintext industrial protocol traffic
      firmware_outdated       — known vulnerable firmware version
      insecure_config         — dangerous configuration detected
      network_exposure        — OT device reachable from IT network
      coil_write_enabled      — Modbus coil writing allowed (physical control)
    """
    __tablename__ = "ot_findings"

    id            = db.Column(db.Integer,     primary_key=True)
    scan_id       = db.Column(db.Integer,     db.ForeignKey("ot_scans.id"), nullable=True)
    device_ip     = db.Column(db.String(100), nullable=False)
    protocol      = db.Column(db.String(50),  nullable=False)
    finding_type  = db.Column(db.String(100), nullable=False)
    severity      = db.Column(db.String(20),  nullable=False)
    title         = db.Column(db.String(500), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    evidence      = db.Column(db.Text,        nullable=True)
    mitre_ics_id  = db.Column(db.String(50),  nullable=True)
    remediation   = db.Column(db.Text,        nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "scan_id":       self.scan_id,
            "device_ip":     self.device_ip,
            "protocol":      self.protocol,
            "finding_type":  self.finding_type,
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "evidence":      self.evidence,
            "mitre_ics_id":  self.mitre_ics_id,
            "remediation":   self.remediation,
            "created_at":    str(self.created_at),
        }
