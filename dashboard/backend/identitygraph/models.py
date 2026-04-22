"""
AIPET X+ — Identity Graph Engine Models

Tables:
  ig_identities  — every identity: user, service, device, role
  ig_edges       — relationships between identities
  ig_risks       — risk findings per identity
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class IgIdentity(db.Model):
    """
    An identity entity in the graph.

    identity_type: user | service_account | device |
                   role | api_key | cloud_resource
    risk_score:    0-100 — higher = more dangerous if compromised
    blast_radius:  number of resources reachable from this identity
    """
    __tablename__ = "ig_identities"

    id             = db.Column(db.Integer,     primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    identity_type  = db.Column(db.String(50),  nullable=False)
    email          = db.Column(db.String(200), nullable=True)
    source         = db.Column(db.String(100), nullable=True)
    risk_score     = db.Column(db.Integer,     default=0)
    blast_radius   = db.Column(db.Integer,     default=0)
    is_privileged  = db.Column(db.Boolean,     default=False)
    is_dormant     = db.Column(db.Boolean,     default=False)
    is_overprivileged = db.Column(db.Boolean,  default=False)
    last_active    = db.Column(db.DateTime,    nullable=True)
    permissions    = db.Column(db.Text,        nullable=True)  # JSON
    tags           = db.Column(db.Text,        nullable=True)  # JSON
    created_at     = db.Column(db.DateTime,
                               default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":               self.id,
            "name":             self.name,
            "identity_type":    self.identity_type,
            "email":            self.email,
            "source":           self.source,
            "risk_score":       self.risk_score,
            "blast_radius":     self.blast_radius,
            "is_privileged":    self.is_privileged,
            "is_dormant":       self.is_dormant,
            "is_overprivileged":self.is_overprivileged,
            "last_active":      str(self.last_active) if self.last_active else None,
            "permissions":      self.permissions,
            "tags":             self.tags,
            "created_at":       str(self.created_at),
        }


class IgEdge(db.Model):
    """
    A directed relationship between two identities.
    e.g. user → has_role → admin_role
         service_account → accesses → cloud_resource

    relationship: has_role | accesses | owns | delegates_to |
                  inherits | manages | authenticates_via
    """
    __tablename__ = "ig_edges"

    id           = db.Column(db.Integer,     primary_key=True)
    source_id    = db.Column(db.Integer,
                             db.ForeignKey("ig_identities.id"),
                             nullable=False)
    target_id    = db.Column(db.Integer,
                             db.ForeignKey("ig_identities.id"),
                             nullable=False)
    relationship = db.Column(db.String(100), nullable=False)
    weight       = db.Column(db.Integer,     default=1)
    is_risky     = db.Column(db.Boolean,     default=False)
    created_at   = db.Column(db.DateTime,
                             default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "source_id":    self.source_id,
            "target_id":    self.target_id,
            "relationship": self.relationship,
            "weight":       self.weight,
            "is_risky":     self.is_risky,
        }


class IgRisk(db.Model):
    """
    A risk finding associated with an identity.
    """
    __tablename__ = "ig_risks"

    id          = db.Column(db.Integer,     primary_key=True)
    identity_id = db.Column(db.Integer,
                            db.ForeignKey("ig_identities.id"),
                            nullable=False)
    risk_type   = db.Column(db.String(100), nullable=False)
    severity    = db.Column(db.String(20),  default="Medium")
    description = db.Column(db.Text,        nullable=True)
    remediation = db.Column(db.Text,        nullable=True)
    resolved    = db.Column(db.Boolean,     default=False)
    created_at  = db.Column(db.DateTime,
                            default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "identity_id": self.identity_id,
            "risk_type":   self.risk_type,
            "severity":    self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "resolved":    self.resolved,
            "created_at":  str(self.created_at),
        }
