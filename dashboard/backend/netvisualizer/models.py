"""
AIPET X — Cloud-Network Visualizer Models
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class NvNode(db.Model):
    __tablename__ = "nv_nodes"
    id              = db.Column(db.Integer,     primary_key=True)
    name            = db.Column(db.String(200), nullable=False)
    node_type       = db.Column(db.String(50),  nullable=False)
    zone            = db.Column(db.String(50),  nullable=False)
    cloud_provider  = db.Column(db.String(50),  nullable=True)
    ip_address      = db.Column(db.String(50),  nullable=True)
    region          = db.Column(db.String(100), nullable=True)
    risk_score      = db.Column(db.Integer,     default=0)
    internet_facing = db.Column(db.Boolean,     default=False)
    encrypted       = db.Column(db.Boolean,     default=True)
    issue_count     = db.Column(db.Integer,     default=0)
    status          = db.Column(db.String(30),  default="active")
    node_meta       = db.Column(db.Text,        nullable=True)
    created_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":             self.id,
            "name":           self.name,
            "node_type":      self.node_type,
            "zone":           self.zone,
            "cloud_provider": self.cloud_provider,
            "ip_address":     self.ip_address,
            "region":         self.region,
            "risk_score":     self.risk_score,
            "internet_facing":self.internet_facing,
            "encrypted":      self.encrypted,
            "issue_count":    self.issue_count,
            "status":         self.status,
            "metadata":       json.loads(self.node_meta) if self.node_meta else {},
        }


class NvEdge(db.Model):
    __tablename__ = "nv_edges"
    id           = db.Column(db.Integer,     primary_key=True)
    source_id    = db.Column(db.Integer,     db.ForeignKey("nv_nodes.id"), nullable=False)
    target_id    = db.Column(db.Integer,     db.ForeignKey("nv_nodes.id"), nullable=False)
    protocol     = db.Column(db.String(50),  nullable=False)
    port         = db.Column(db.Integer,     nullable=True)
    encrypted    = db.Column(db.Boolean,     default=True)
    risk_level   = db.Column(db.String(20),  default="safe")
    cross_zone   = db.Column(db.Boolean,     default=False)
    bidirectional= db.Column(db.Boolean,     default=False)
    traffic_gbday= db.Column(db.Float,       default=0.0)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "source":        self.source_id,
            "target":        self.target_id,
            "protocol":      self.protocol,
            "port":          self.port,
            "encrypted":     self.encrypted,
            "risk_level":    self.risk_level,
            "cross_zone":    self.cross_zone,
            "bidirectional": self.bidirectional,
            "traffic_gbday": self.traffic_gbday,
        }


class NvIssue(db.Model):
    __tablename__ = "nv_issues"
    id          = db.Column(db.Integer,     primary_key=True)
    node_id     = db.Column(db.Integer,     db.ForeignKey("nv_nodes.id"), nullable=True)
    edge_id     = db.Column(db.Integer,     db.ForeignKey("nv_edges.id"), nullable=True)
    severity    = db.Column(db.String(20),  default="Medium")
    title       = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text,        nullable=True)
    remediation = db.Column(db.Text,        nullable=True)
    status      = db.Column(db.String(30),  default="open")
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "node_id":     self.node_id,
            "edge_id":     self.edge_id,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "remediation": self.remediation,
            "status":      self.status,
            "created_at":  str(self.created_at),
        }
