# =============================================================
# AIPET Cloud — Database Models
# =============================================================
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id                     = db.Column(db.Integer, primary_key=True)
    email                  = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash          = db.Column(db.String(255), nullable=False)
    name                   = db.Column(db.String(255), nullable=False)
    plan                   = db.Column(db.String(50),  default="free")
    scans_used             = db.Column(db.Integer,     default=0)
    scans_limit            = db.Column(db.Integer,     default=5)
    created_at             = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    last_login             = db.Column(db.DateTime,    nullable=True)
    is_active              = db.Column(db.Boolean,     default=True)
    stripe_customer_id     = db.Column(db.String(100), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(100), unique=True, nullable=True)
    plan_expires_at        = db.Column(db.DateTime,    nullable=True)
    scans                  = db.relationship("Scan",   backref="user", lazy=True)
    api_keys               = db.relationship("APIKey", backref="user", lazy=True)

    def to_dict(self):
        return {
            "id":         self.id,
            "email":      self.email,
            "name":       self.name,
            "plan":       self.plan,
            "scans_used": self.scans_used,
            "created_at": str(self.created_at),
        }     

    def can_scan(self):
        if self.plan in ["professional", "enterprise"]:
            return True
        return self.scans_used < self.scans_limit

    def increment_scan(self):
        self.scans_used += 1
        db.session.commit()

    @property
    def scan_limit(self):
        limits = {'free': 5, 'professional': None, 'enterprise': None}
        return limits.get(self.plan, 5)

    @property
    def has_api_access(self):
        return self.plan == 'enterprise'

    @property
    def is_paid(self):
        return self.plan in ('professional', 'enterprise')


class Scan(db.Model):
    __tablename__ = "scans"
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    target       = db.Column(db.String(255), nullable=False)
    mode         = db.Column(db.String(50),  default="single")
    status       = db.Column(db.String(50),  default="queued")
    result_dir   = db.Column(db.String(500), nullable=True)
    report_path  = db.Column(db.String(500), nullable=True)
    started_at   = db.Column(db.DateTime,    nullable=True)
    completed_at = db.Column(db.DateTime,    nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    critical     = db.Column(db.Integer,     default=0)
    high         = db.Column(db.Integer,     default=0)
    medium       = db.Column(db.Integer,     default=0)
    low          = db.Column(db.Integer,     default=0)
    findings     = db.relationship("Finding", backref="scan", lazy=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "target":       self.target,
            "mode":         self.mode,
            "status":       self.status,
            "started_at":   str(self.started_at),
            "completed_at": str(self.completed_at),
            "findings": {
                "critical": self.critical,
                "high":     self.high,
                "medium":   self.medium,
                "low":      self.low,
                "total":    self.critical + self.high + self.medium + self.low,
            }
        }


class Finding(db.Model):
    __tablename__ = "findings"
    id          = db.Column(db.Integer, primary_key=True)
    scan_id     = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    module      = db.Column(db.String(100), nullable=False)
    attack      = db.Column(db.String(255), nullable=False)
    severity    = db.Column(db.String(50),  nullable=False)
    description = db.Column(db.Text,        nullable=True)
    target      = db.Column(db.String(255), nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    fix_status  = db.Column(db.String(50),  default="open")
    fix_notes   = db.Column(db.Text,        nullable=True)

    def to_dict(self):
        return {
            "id":          self.id,
            "module":      self.module,
            "attack":      self.attack,
            "severity":    self.severity,
            "description": self.description,
            "target":      self.target,
            "fix_status":  self.fix_status,
            "fix_notes":   self.fix_notes,
        }


class APIKey(db.Model):
    __tablename__ = "api_keys"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    key_hash   = db.Column(db.String(255), nullable=False, unique=True)
    name       = db.Column(db.String(255), nullable=True)
    last_used  = db.Column(db.DateTime,    nullable=True)
    created_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    is_active  = db.Column(db.Boolean,     default=True)

class RemediationKB(db.Model):
    __tablename__ = "remediation_kb"

    id                     = db.Column(db.Integer, primary_key=True)
    attack_type            = db.Column(db.String(255), nullable=False, unique=True)
    title                  = db.Column(db.String(255), nullable=False)
    severity               = db.Column(db.String(50),  nullable=False)
    explanation            = db.Column(db.Text,         nullable=False)
    fix_commands           = db.Column(db.Text,         nullable=False)
    time_estimate_minutes  = db.Column(db.Integer,      nullable=False)
    difficulty             = db.Column(db.String(50),   nullable=False)
    source                 = db.Column(db.String(255),  nullable=True)
    created_at             = db.Column(db.DateTime,     default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "name":       self.name,
            "last_used":  str(self.last_used),
            "created_at": str(self.created_at),
        }
class ExplainResult(db.Model):
    __tablename__ = "explain_results"

    id           = db.Column(db.Integer,     primary_key=True)
    scan_id      = db.Column(db.Integer,     db.ForeignKey("scans.id"),    nullable=True)
    finding_id   = db.Column(db.Integer,     db.ForeignKey("findings.id"), nullable=True)
    explain_type = db.Column(db.String(50),  nullable=False)
    content      = db.Column(db.Text,        nullable=False)
    model_used   = db.Column(db.String(100), nullable=False)
    tokens_used  = db.Column(db.Integer,     default=0)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "scan_id":      self.scan_id,
            "finding_id":   self.finding_id,
            "explain_type": self.explain_type,
            "content":      self.content,
            "model_used":   self.model_used,
            "tokens_used":  self.tokens_used,
            "created_at":   str(self.created_at),
        }
class DeviceTag(db.Model):
    __tablename__ = "device_tags"

    id                = db.Column(db.Integer,     primary_key=True)
    user_id           = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    device_ip         = db.Column(db.String(255), nullable=False)
    business_function = db.Column(db.String(100), nullable=False)
    industry          = db.Column(db.String(100), nullable=False, default="General Business")
    created_at        = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at        = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":                self.id,
            "device_ip":         self.device_ip,
            "business_function": self.business_function,
            "industry":          self.industry,
        }   


class ScoreResult(db.Model):
    __tablename__ = "score_results"

    id                  = db.Column(db.Integer,     primary_key=True)
    scan_id             = db.Column(db.Integer,     db.ForeignKey("scans.id"),  nullable=False)
    user_id             = db.Column(db.Integer,     db.ForeignKey("users.id"),  nullable=False)
    industry            = db.Column(db.String(100), nullable=False)
    total_exposure_gbp  = db.Column(db.BigInteger,  nullable=False, default=0)
    findings_breakdown  = db.Column(db.JSON,         nullable=True)
    created_at          = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":                 self.id,
            "scan_id":            self.scan_id,
            "industry":           self.industry,
            "total_exposure_gbp": self.total_exposure_gbp,
            "findings_breakdown": self.findings_breakdown,
            "created_at":         str(self.created_at),
        }
    
class PredictAlert(db.Model):
    __tablename__ = "predict_alerts"

    id                = db.Column(db.Integer,     primary_key=True)
    user_id           = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    cve_id            = db.Column(db.String(50),  nullable=False)
    title             = db.Column(db.String(500), nullable=False)
    description       = db.Column(db.Text,        nullable=False)
    severity          = db.Column(db.String(50),  nullable=False)
    cvss_score        = db.Column(db.Float,       default=0.0)
    affected_devices  = db.Column(db.JSON,        nullable=True)
    weaponisation_pct = db.Column(db.Integer,     default=0)
    published_date    = db.Column(db.DateTime,    nullable=False)
    nvd_url           = db.Column(db.String(500), nullable=True)
    is_reviewed       = db.Column(db.Boolean,     default=False)
    created_at        = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":                self.id,
            "cve_id":            self.cve_id,
            "title":             self.title,
            "description":       self.description,
            "severity":          self.severity,
            "cvss_score":        self.cvss_score,
            "affected_devices":  self.affected_devices,
            "weaponisation_pct": self.weaponisation_pct,
            "published_date":    str(self.published_date),
            "nvd_url":           self.nvd_url,
            "is_reviewed":       self.is_reviewed,
            "created_at":        str(self.created_at),
        }
class WatchBaseline(db.Model):
    __tablename__ = "watch_baselines"

    id              = db.Column(db.Integer,     primary_key=True)
    user_id         = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    device_ip       = db.Column(db.String(255), nullable=False)
    device_function = db.Column(db.String(100), default="Unknown")
    baseline_data   = db.Column(db.JSON,        nullable=False)
    first_seen      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    last_seen       = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    is_active       = db.Column(db.Boolean,     default=True)
    created_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":              self.id,
            "device_ip":       self.device_ip,
            "device_function": self.device_function,
            "baseline_data":   self.baseline_data,
            "first_seen":      str(self.first_seen),
            "last_seen":       str(self.last_seen),
            "is_active":       self.is_active,
        }


class WatchAlert(db.Model):
    __tablename__ = "watch_alerts"

    id               = db.Column(db.Integer,     primary_key=True)
    user_id          = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    device_ip        = db.Column(db.String(255), nullable=False)
    alert_type       = db.Column(db.String(100), nullable=False)
    severity         = db.Column(db.String(50),  nullable=False)
    description      = db.Column(db.Text,        nullable=False)
    details          = db.Column(db.JSON,        nullable=True)
    is_acknowledged  = db.Column(db.Boolean,     default=False)
    created_at       = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":              self.id,
            "device_ip":       self.device_ip,
            "alert_type":      self.alert_type,
            "severity":        self.severity,
            "description":     self.description,
            "details":         self.details,
            "is_acknowledged": self.is_acknowledged,
            "created_at":      str(self.created_at),
        }

PLAN_LIMITS = {
    "free": {
        "scans_per_month":  5,
        "parallel_workers": 1,
        "api_access":       False,
        "price_gbp":        0,
    },
    "professional": {
        "scans_per_month":  -1,
        "parallel_workers": 3,
        "api_access":       False,
        "price_gbp":        49,
    },
    "enterprise": {
        "scans_per_month":  -1,
        "parallel_workers": 10,
        "api_access":       True,
        "price_gbp":        499,
    },
}

class ComplianceResult(db.Model):
    __tablename__ = "compliance_results"

    id          = db.Column(db.Integer,     primary_key=True)
    user_id     = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    scan_id     = db.Column(db.Integer,     db.ForeignKey("scans.id"), nullable=False)
    framework   = db.Column(db.String(50),  nullable=False)  # nis2, nist, iso27001
    score       = db.Column(db.Integer,     nullable=False, default=0)
    total       = db.Column(db.Integer,     nullable=False, default=0)
    controls    = db.Column(db.JSON,        nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "scan_id":    self.scan_id,
            "framework":  self.framework,
            "score":      self.score,
            "total":      self.total,
            "controls":   self.controls,
            "created_at": str(self.created_at),
        }


class ProtocolScan(db.Model):
    __tablename__ = "protocol_scans"

    id           = db.Column(db.Integer,     primary_key=True)
    user_id      = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    protocol     = db.Column(db.String(50),  nullable=False)
    target       = db.Column(db.String(255), nullable=False)
    status       = db.Column(db.String(50),  default="running")
    findings     = db.Column(db.JSON,        nullable=True)
    device_count = db.Column(db.Integer,     default=0)
    risk_level   = db.Column(db.String(50),  default="unknown")
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "protocol":     self.protocol,
            "target":       self.target,
            "status":       self.status,
            "findings":     self.findings,
            "device_count": self.device_count,
            "risk_level":   self.risk_level,
            "created_at":   str(self.created_at),
            "completed_at": str(self.completed_at),
        }
