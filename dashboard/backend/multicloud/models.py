"""
AIPET X — Multi-Cloud Security Models

Three tables:
  cloud_accounts  — registered cloud provider accounts
                    (AWS, Azure, GCP, on-premise)
  cloud_assets    — discovered cloud resources
                    (VMs, containers, IoT hubs, storage, functions)
  cloud_findings  — security misconfigurations found in cloud assets
                    (open buckets, exposed APIs, missing encryption)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class CloudAccount(db.Model):
    """
    A registered cloud provider account.

    provider: aws | azure | gcp | onprem
    status:   connected | disconnected | error
    region:   primary region for this account
    """
    __tablename__ = "cloud_accounts"

    id           = db.Column(db.Integer,     primary_key=True)
    name         = db.Column(db.String(200), nullable=False)
    provider     = db.Column(db.String(50),  nullable=False)
    account_id   = db.Column(db.String(200), nullable=True)
    region       = db.Column(db.String(100), nullable=True)
    status       = db.Column(db.String(30),  default="connected")
    asset_count  = db.Column(db.Integer,     default=0)
    finding_count= db.Column(db.Integer,     default=0)
    last_scan    = db.Column(db.DateTime,    nullable=True)
    created_by   = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "name":          self.name,
            "provider":      self.provider,
            "account_id":    self.account_id,
            "region":        self.region,
            "status":        self.status,
            "asset_count":   self.asset_count,
            "finding_count": self.finding_count,
            "last_scan":     str(self.last_scan) if self.last_scan else None,
            "created_at":    str(self.created_at),
        }


class CloudAsset(db.Model):
    """
    A discovered cloud resource.

    asset_type: vm | container | iot_hub | storage |
                function | database | network | kubernetes
    risk_score: 0-100 — calculated from findings
    """
    __tablename__ = "cloud_assets"

    id           = db.Column(db.Integer,     primary_key=True)
    account_id   = db.Column(db.Integer,     db.ForeignKey("cloud_accounts.id"), nullable=False)
    asset_id     = db.Column(db.String(200), nullable=False)   # cloud-native resource ID
    name         = db.Column(db.String(200), nullable=True)
    asset_type   = db.Column(db.String(50),  nullable=False)
    provider     = db.Column(db.String(50),  nullable=False)
    region       = db.Column(db.String(100), nullable=True)
    ip_address   = db.Column(db.String(100), nullable=True)
    tags         = db.Column(db.Text,        nullable=True)    # JSON dict of cloud tags
    risk_score   = db.Column(db.Integer,     default=0)
    public       = db.Column(db.Boolean,     default=False)    # publicly accessible
    encrypted    = db.Column(db.Boolean,     default=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "account_id":  self.account_id,
            "asset_id":    self.asset_id,
            "name":        self.name,
            "asset_type":  self.asset_type,
            "provider":    self.provider,
            "region":      self.region,
            "ip_address":  self.ip_address,
            "tags":        self.tags,
            "risk_score":  self.risk_score,
            "public":      self.public,
            "encrypted":   self.encrypted,
            "created_at":  str(self.created_at),
        }


class CloudFinding(db.Model):
    """
    A security misconfiguration or vulnerability in a cloud asset.

    finding_type categories:
      public_storage       — S3/blob storage publicly accessible
      unencrypted_storage  — storage without encryption at rest
      exposed_api          — API gateway without authentication
      missing_mfa          — account without MFA enabled
      overprivileged_role  — IAM role with excessive permissions
      unpatched_vm         — VM with missing security updates
      open_security_group  — firewall allowing 0.0.0.0/0
      no_logging           — CloudTrail/audit logging disabled
      weak_credentials     — default or weak service credentials
      iot_hub_exposed      — IoT hub management API exposed
    """
    __tablename__ = "cloud_findings"

    id           = db.Column(db.Integer,     primary_key=True)
    account_id   = db.Column(db.Integer,     db.ForeignKey("cloud_accounts.id"), nullable=True)
    asset_id     = db.Column(db.Integer,     db.ForeignKey("cloud_assets.id"),   nullable=True)
    provider     = db.Column(db.String(50),  nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)
    severity     = db.Column(db.String(20),  nullable=False)
    title        = db.Column(db.String(500), nullable=False)
    description  = db.Column(db.Text,        nullable=True)
    resource     = db.Column(db.String(300), nullable=True)    # affected resource name/ID
    remediation  = db.Column(db.Text,        nullable=True)
    mitre_id     = db.Column(db.String(50),  nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "account_id":    self.account_id,
            "asset_id":      self.asset_id,
            "provider":      self.provider,
            "finding_type":  self.finding_type,
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "resource":      self.resource,
            "remediation":   self.remediation,
            "mitre_id":      self.mitre_id,
            "created_at":    str(self.created_at),
        }
