"""
AIPET X — Zero-Trust Models

Three tables:
  zt_device_trust — per-device trust score and quarantine status
  zt_policies     — network access policies (who can talk to whom)
  zt_access_log   — every access decision ever made (allow/block/quarantine)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class ZtDeviceTrust(db.Model):
    """
    Trust profile for a single IoT device.

    trust_score: 0-100
      90-100 = Trusted    (all patches applied, no findings)
      70-89  = Monitored  (minor issues, watched closely)
      40-69  = Restricted (significant findings, limited access)
      0-39   = Quarantined (critical findings, isolated)

    status is derived from trust_score but can be manually overridden.
    """
    __tablename__ = "zt_device_trust"

    id            = db.Column(db.Integer,     primary_key=True)
    device_ip     = db.Column(db.String(100), nullable=False, unique=True)
    device_name   = db.Column(db.String(200), nullable=True)
    trust_score   = db.Column(db.Integer,     default=100)
    status        = db.Column(db.String(30),  default="trusted")
    # trusted | monitored | restricted | quarantined
    risk_factors  = db.Column(db.Text,        nullable=True)  # JSON list of reasons
    last_scan_id  = db.Column(db.Integer,     db.ForeignKey("scans.id"), nullable=True)
    last_assessed = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "device_ip":     self.device_ip,
            "device_name":   self.device_name,
            "trust_score":   self.trust_score,
            "status":        self.status,
            "risk_factors":  self.risk_factors,
            "last_scan_id":  self.last_scan_id,
            "last_assessed": str(self.last_assessed),
            "updated_at":    str(self.updated_at),
        }


class ZtPolicy(db.Model):
    """
    A network access policy — defines what a device is allowed to do.

    source/destination: IP address, CIDR, or "*" (any)
    action: allow | block | quarantine | alert
    priority: lower number = evaluated first (like firewall rules)
    """
    __tablename__ = "zt_policies"

    id          = db.Column(db.Integer,     primary_key=True)
    name        = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text,        nullable=True)
    source      = db.Column(db.String(200), nullable=False)   # IP, CIDR, or *
    destination = db.Column(db.String(200), nullable=False)   # IP, CIDR, or *
    port        = db.Column(db.String(50),  nullable=True)    # port or * for any
    protocol    = db.Column(db.String(20),  default="any")    # tcp | udp | any
    action      = db.Column(db.String(30),  nullable=False)   # allow | block | quarantine | alert
    priority    = db.Column(db.Integer,     default=100)
    enabled     = db.Column(db.Boolean,     default=True)
    hit_count   = db.Column(db.Integer,     default=0)
    created_by  = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "name":        self.name,
            "description": self.description,
            "source":      self.source,
            "destination": self.destination,
            "port":        self.port,
            "protocol":    self.protocol,
            "action":      self.action,
            "priority":    self.priority,
            "enabled":     self.enabled,
            "hit_count":   self.hit_count,
            "created_at":  str(self.created_at),
        }


class ZtAccessLog(db.Model):
    """
    Immutable audit log of every access decision.
    Written on every policy evaluation — never updated, only inserted.
    """
    __tablename__ = "zt_access_log"

    id          = db.Column(db.Integer,     primary_key=True)
    source_ip   = db.Column(db.String(100), nullable=False)
    dest_ip     = db.Column(db.String(100), nullable=True)
    port        = db.Column(db.String(50),  nullable=True)
    protocol    = db.Column(db.String(20),  nullable=True)
    action      = db.Column(db.String(30),  nullable=False)   # allow | block | quarantine
    policy_id   = db.Column(db.Integer,     db.ForeignKey("zt_policies.id"), nullable=True)
    policy_name = db.Column(db.String(200), nullable=True)    # denormalised for fast reads
    reason      = db.Column(db.Text,        nullable=True)
    trust_score = db.Column(db.Integer,     nullable=True)    # score at time of decision
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "source_ip":   self.source_ip,
            "dest_ip":     self.dest_ip,
            "port":        self.port,
            "protocol":    self.protocol,
            "action":      self.action,
            "policy_name": self.policy_name,
            "reason":      self.reason,
            "trust_score": self.trust_score,
            "created_at":  str(self.created_at),
        }
