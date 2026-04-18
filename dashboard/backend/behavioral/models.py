"""
AIPET X — Behavioral AI Engine Models

Three tables:
  ba_baselines  — normal behaviour profile per entity
  ba_anomalies  — detected deviations from baseline
  ba_patterns   — historical behaviour data points
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class BaBaseline(db.Model):
    """
    Behavioural baseline for a device, user, or service.
    Built from historical data — defines what "normal" looks like.

    entity_type: device | user | service | api_key
    baseline:    JSON object with normal behaviour metrics
    confidence:  0-100 — how confident we are in the baseline
    """
    __tablename__ = "ba_baselines"

    id            = db.Column(db.Integer,     primary_key=True)
    entity_id     = db.Column(db.String(200), nullable=False)
    entity_type   = db.Column(db.String(50),  nullable=False)
    entity_name   = db.Column(db.String(200), nullable=False)
    baseline      = db.Column(db.Text,        nullable=True)   # JSON
    confidence    = db.Column(db.Integer,     default=0)
    risk_score    = db.Column(db.Integer,     default=0)
    anomaly_count = db.Column(db.Integer,     default=0)
    last_updated  = db.Column(db.DateTime,    nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":            self.id,
            "entity_id":     self.entity_id,
            "entity_type":   self.entity_type,
            "entity_name":   self.entity_name,
            "baseline":      json.loads(self.baseline) if self.baseline else {},
            "confidence":    self.confidence,
            "risk_score":    self.risk_score,
            "anomaly_count": self.anomaly_count,
            "last_updated":  str(self.last_updated) if self.last_updated else None,
            "created_at":    str(self.created_at),
        }


class BaAnomaly(db.Model):
    """
    A detected behavioural anomaly — deviation from baseline.

    anomaly_type: traffic_spike | new_connection | unusual_hours |
                  geo_anomaly | protocol_change | data_exfil |
                  lateral_movement | privilege_escalation
    deviation:    how many standard deviations from normal (sigma)
    mitre_id:     mapped MITRE ATT&CK technique
    status:       new | investigating | resolved | false_positive
    """
    __tablename__ = "ba_anomalies"

    id           = db.Column(db.Integer,     primary_key=True)
    baseline_id  = db.Column(db.Integer,     db.ForeignKey("ba_baselines.id"), nullable=False)
    entity_name  = db.Column(db.String(200), nullable=False)
    anomaly_type = db.Column(db.String(100), nullable=False)
    severity     = db.Column(db.String(20),  default="Medium")
    title        = db.Column(db.String(300), nullable=False)
    description  = db.Column(db.Text,        nullable=True)
    deviation    = db.Column(db.Float,       default=0.0)
    observed     = db.Column(db.Text,        nullable=True)   # JSON — what was seen
    expected     = db.Column(db.Text,        nullable=True)   # JSON — what was normal
    mitre_id     = db.Column(db.String(50),  nullable=True)
    status       = db.Column(db.String(30),  default="new")
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    resolved_at  = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        import json
        return {
            "id":           self.id,
            "baseline_id":  self.baseline_id,
            "entity_name":  self.entity_name,
            "anomaly_type": self.anomaly_type,
            "severity":     self.severity,
            "title":        self.title,
            "description":  self.description,
            "deviation":    self.deviation,
            "observed":     json.loads(self.observed) if self.observed else {},
            "expected":     json.loads(self.expected) if self.expected else {},
            "mitre_id":     self.mitre_id,
            "status":       self.status,
            "created_at":   str(self.created_at),
            "resolved_at":  str(self.resolved_at) if self.resolved_at else None,
        }


class BaPattern(db.Model):
    """
    Historical behaviour data point for trend analysis.
    One record per entity per hour.
    """
    __tablename__ = "ba_patterns"

    id          = db.Column(db.Integer,     primary_key=True)
    baseline_id = db.Column(db.Integer,     db.ForeignKey("ba_baselines.id"), nullable=False)
    entity_name = db.Column(db.String(200), nullable=False)
    hour        = db.Column(db.Integer,     nullable=False)   # 0-23
    day_of_week = db.Column(db.Integer,     nullable=False)   # 0=Mon, 6=Sun
    metrics     = db.Column(db.Text,        nullable=True)    # JSON
    recorded_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":          self.id,
            "baseline_id": self.baseline_id,
            "entity_name": self.entity_name,
            "hour":        self.hour,
            "day_of_week": self.day_of_week,
            "metrics":     json.loads(self.metrics) if self.metrics else {},
            "recorded_at": str(self.recorded_at),
        }
