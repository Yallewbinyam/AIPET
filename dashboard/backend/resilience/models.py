"""
AIPET X — Resilience Engine Models

Three tables:
  re_assets    — critical assets requiring DR coverage
  re_plans     — disaster recovery plans per asset
  re_tests     — failover test results
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class ReAsset(db.Model):
    """
    A critical asset that requires disaster recovery planning.
    rto_target:  Recovery Time Objective in hours (how fast must it recover)
    rpo_target:  Recovery Point Objective in hours (max data loss acceptable)
    rto_actual:  Actual measured recovery time
    rpo_actual:  Actual measured data loss window
    """
    __tablename__ = "re_assets"

    id              = db.Column(db.Integer,     primary_key=True)
    name            = db.Column(db.String(200), nullable=False)
    asset_type      = db.Column(db.String(50),  nullable=False)
    criticality     = db.Column(db.String(20),  default="High")
    location        = db.Column(db.String(200), nullable=True)
    rto_target      = db.Column(db.Float,       default=4.0)
    rpo_target      = db.Column(db.Float,       default=1.0)
    rto_actual      = db.Column(db.Float,       nullable=True)
    rpo_actual      = db.Column(db.Float,       nullable=True)
    has_dr_plan     = db.Column(db.Boolean,     default=False)
    has_backup      = db.Column(db.Boolean,     default=False)
    backup_tested   = db.Column(db.Boolean,     default=False)
    failover_ready  = db.Column(db.Boolean,     default=False)
    readiness_score = db.Column(db.Integer,     default=0)
    last_tested     = db.Column(db.DateTime,    nullable=True)
    created_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        rto_breach = (self.rto_actual or 0) > self.rto_target
        rpo_breach = (self.rpo_actual or 0) > self.rpo_target
        return {
            "id":              self.id,
            "name":            self.name,
            "asset_type":      self.asset_type,
            "criticality":     self.criticality,
            "location":        self.location,
            "rto_target":      self.rto_target,
            "rpo_target":      self.rpo_target,
            "rto_actual":      self.rto_actual,
            "rpo_actual":      self.rpo_actual,
            "rto_breach":      rto_breach,
            "rpo_breach":      rpo_breach,
            "has_dr_plan":     self.has_dr_plan,
            "has_backup":      self.has_backup,
            "backup_tested":   self.backup_tested,
            "failover_ready":  self.failover_ready,
            "readiness_score": self.readiness_score,
            "last_tested":     str(self.last_tested) if self.last_tested else None,
        }


class RePlan(db.Model):
    """
    A disaster recovery plan for a specific asset.
    Contains steps, contacts, and recovery procedures.
    """
    __tablename__ = "re_plans"

    id          = db.Column(db.Integer,     primary_key=True)
    asset_id    = db.Column(db.Integer,     db.ForeignKey("re_assets.id"), nullable=False)
    title       = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text,        nullable=True)
    steps       = db.Column(db.Text,        nullable=True)   # JSON list
    contacts    = db.Column(db.Text,        nullable=True)   # JSON list
    status      = db.Column(db.String(30),  default="draft")
    last_reviewed=db.Column(db.DateTime,    nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":           self.id,
            "asset_id":     self.asset_id,
            "title":        self.title,
            "description":  self.description,
            "steps":        json.loads(self.steps) if self.steps else [],
            "contacts":     json.loads(self.contacts) if self.contacts else [],
            "status":       self.status,
            "last_reviewed":str(self.last_reviewed) if self.last_reviewed else None,
        }


class ReTest(db.Model):
    """
    A failover test result — did the DR plan actually work?
    """
    __tablename__ = "re_tests"

    id           = db.Column(db.Integer,     primary_key=True)
    asset_id     = db.Column(db.Integer,     db.ForeignKey("re_assets.id"), nullable=False)
    test_type    = db.Column(db.String(50),  nullable=False)
    result       = db.Column(db.String(20),  default="pending")
    rto_achieved = db.Column(db.Float,       nullable=True)
    rpo_achieved = db.Column(db.Float,       nullable=True)
    notes        = db.Column(db.Text,        nullable=True)
    conducted_by = db.Column(db.String(200), nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "asset_id":     self.asset_id,
            "test_type":    self.test_type,
            "result":       self.result,
            "rto_achieved": self.rto_achieved,
            "rpo_achieved": self.rpo_achieved,
            "notes":        self.notes,
            "conducted_by": self.conducted_by,
            "created_at":   str(self.created_at),
        }
