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
            "id":                    self.id,
            "email":                 self.email,
            "name":                  self.name,
            "plan":                  self.plan,
            "scans_used":            self.scans_used,
            "scans_limit":           self.scans_limit,
            "created_at":            str(self.created_at),
            "stripe_customer_id":    self.stripe_customer_id,
            "plan_expires_at":       str(self.plan_expires_at) if self.plan_expires_at else None,
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

    def to_dict(self):
        return {
            "id":          self.id,
            "module":      self.module,
            "attack":      self.attack,
            "severity":    self.severity,
            "description": self.description,
            "target":      self.target,
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

    def to_dict(self):
        return {
            "id":         self.id,
            "name":       self.name,
            "last_used":  str(self.last_used),
            "created_at": str(self.created_at),
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