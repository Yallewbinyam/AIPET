"""
AIPET X — Cloud-Cost Security Optimizer Models

Two tables:
  cs_resources  — cloud resources with cost + security data
  cs_recommendations — cost+security optimization recommendations
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class CsResource(db.Model):
    """
    A cloud resource with both cost and security attributes.

    resource_type: ec2 | rds | s3 | lambda | aks | gke | blob | etc.
    monthly_cost:  current monthly cost in GBP
    waste_pct:     estimated % of cost that is waste (0-100)
    security_score: 0-100 (100 = perfectly secure)
    """
    __tablename__ = "cs_resources"

    id             = db.Column(db.Integer,     primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    resource_type  = db.Column(db.String(50),  nullable=False)
    cloud_provider = db.Column(db.String(50),  nullable=False)
    region         = db.Column(db.String(100), nullable=True)
    monthly_cost   = db.Column(db.Float,       default=0.0)
    optimised_cost = db.Column(db.Float,       default=0.0)
    waste_pct      = db.Column(db.Integer,     default=0)
    security_score = db.Column(db.Integer,     default=100)
    security_issues= db.Column(db.Integer,     default=0)
    status         = db.Column(db.String(30),  default="active")
    tags           = db.Column(db.Text,        nullable=True)   # JSON
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        saving = self.monthly_cost - self.optimised_cost
        return {
            "id":              self.id,
            "name":            self.name,
            "resource_type":   self.resource_type,
            "cloud_provider":  self.cloud_provider,
            "region":          self.region,
            "monthly_cost":    self.monthly_cost,
            "optimised_cost":  self.optimised_cost,
            "monthly_saving":  round(saving, 2),
            "annual_saving":   round(saving * 12, 2),
            "waste_pct":       self.waste_pct,
            "security_score":  self.security_score,
            "security_issues": self.security_issues,
            "status":          self.status,
            "tags":            json.loads(self.tags) if self.tags else [],
        }


class CsRecommendation(db.Model):
    """
    A cost+security optimization recommendation.

    category: rightsizing | decommission | encryption |
              access_control | reserved_instance | storage_tier
    priority: critical | high | medium | low
    """
    __tablename__ = "cs_recommendations"

    id            = db.Column(db.Integer,     primary_key=True)
    resource_id   = db.Column(db.Integer,     db.ForeignKey("cs_resources.id"), nullable=False)
    category      = db.Column(db.String(50),  nullable=False)
    priority      = db.Column(db.String(20),  default="medium")
    title         = db.Column(db.String(300), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    action        = db.Column(db.Text,        nullable=True)
    monthly_saving= db.Column(db.Float,       default=0.0)
    security_gain = db.Column(db.String(100), nullable=True)
    effort        = db.Column(db.String(20),  default="medium")
    status        = db.Column(db.String(30),  default="open")
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":             self.id,
            "resource_id":    self.resource_id,
            "category":       self.category,
            "priority":       self.priority,
            "title":          self.title,
            "description":    self.description,
            "action":         self.action,
            "monthly_saving": self.monthly_saving,
            "annual_saving":  round(self.monthly_saving * 12, 2),
            "security_gain":  self.security_gain,
            "effort":         self.effort,
            "status":         self.status,
            "created_at":     str(self.created_at),
        }
