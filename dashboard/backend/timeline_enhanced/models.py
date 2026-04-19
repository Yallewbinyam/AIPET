"""
AIPET X — Unified Security Timeline Enhanced Models

Two tables:
  te_events    — enriched events from all 11 Phase 5B modules
  te_clusters  — AI-detected event clusters (correlated incidents)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class TeEvent(db.Model):
    """
    An enriched security event pulled from any AIPET module.
    Enhanced with correlation data and AI analysis.

    source_module: identity_graph | behavioral | compliance |
                   dspm | cost_security | api_security |
                   supply_chain | network | resilience |
                   drift | terminal | siem | scan | user
    cluster_id:    links related events into an incident cluster
    """
    __tablename__ = "te_events"

    id            = db.Column(db.Integer,     primary_key=True)
    source_module = db.Column(db.String(50),  nullable=False)
    event_type    = db.Column(db.String(100), nullable=False)
    severity      = db.Column(db.String(20),  default="Info")
    title         = db.Column(db.String(300), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    entity        = db.Column(db.String(200), nullable=True)
    entity_type   = db.Column(db.String(50),  nullable=True)
    mitre_id      = db.Column(db.String(50),  nullable=True)
    cluster_id    = db.Column(db.Integer,     db.ForeignKey("te_clusters.id"), nullable=True)
    correlated    = db.Column(db.Boolean,     default=False)
    risk_score    = db.Column(db.Integer,     default=0)
    raw_ref_id    = db.Column(db.Integer,     nullable=True)
    resolved      = db.Column(db.Boolean,     default=False)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "source_module": self.source_module,
            "event_type":    self.event_type,
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "entity":        self.entity,
            "entity_type":   self.entity_type,
            "mitre_id":      self.mitre_id,
            "cluster_id":    self.cluster_id,
            "correlated":    self.correlated,
            "risk_score":    self.risk_score,
            "resolved":      self.resolved,
            "created_at":    str(self.created_at),
        }


class TeCluster(db.Model):
    """
    An AI-detected cluster of correlated events.
    Multiple events from different modules that are related.

    cluster_type: attack_chain | policy_violation |
                  anomaly_group | compliance_breach | data_incident
    ai_summary:   Claude-generated plain-English summary
    """
    __tablename__ = "te_clusters"

    id            = db.Column(db.Integer,     primary_key=True)
    title         = db.Column(db.String(300), nullable=False)
    cluster_type  = db.Column(db.String(50),  nullable=False)
    severity      = db.Column(db.String(20),  default="High")
    event_count   = db.Column(db.Integer,     default=0)
    modules_involved = db.Column(db.Text,     nullable=True)  # JSON
    ai_summary    = db.Column(db.Text,        nullable=True)
    status        = db.Column(db.String(30),  default="active")
    started_at    = db.Column(db.DateTime,    nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":               self.id,
            "title":            self.title,
            "cluster_type":     self.cluster_type,
            "severity":         self.severity,
            "event_count":      self.event_count,
            "modules_involved": json.loads(self.modules_involved) if self.modules_involved else [],
            "ai_summary":       self.ai_summary,
            "status":           self.status,
            "started_at":       str(self.started_at) if self.started_at else None,
            "created_at":       str(self.created_at),
        }
