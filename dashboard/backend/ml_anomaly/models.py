"""
AIPET X — ML Anomaly Detection Models

Tables:
  ml_anomaly_model_versions  — versioned Isolation Forest model registry
  ml_anomaly_detections      — per-sample anomaly detection results
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class AnomalyModelVersion(db.Model):
    __tablename__ = "ml_anomaly_model_versions"

    id               = db.Column(db.Integer,     primary_key=True)
    version_tag      = db.Column(db.String(100), nullable=False, unique=True)
    algorithm        = db.Column(db.String(50),  nullable=False, default="isolation_forest")
    contamination    = db.Column(db.Float,       nullable=False, default=0.05)
    n_estimators     = db.Column(db.Integer,     nullable=False, default=100)
    feature_names    = db.Column(db.Text,        nullable=True)   # JSON list
    training_samples = db.Column(db.Integer,     nullable=True)
    precision_score  = db.Column(db.Float,       nullable=True)
    recall_score     = db.Column(db.Float,       nullable=True)
    f1_score         = db.Column(db.Float,       nullable=True)
    model_path       = db.Column(db.String(500), nullable=True)
    is_active        = db.Column(db.Boolean,     default=False)
    node_meta        = db.Column(db.Text,        nullable=True)   # JSON
    created_at       = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":               self.id,
            "version_tag":      self.version_tag,
            "algorithm":        self.algorithm,
            "contamination":    self.contamination,
            "n_estimators":     self.n_estimators,
            "feature_names":    json.loads(self.feature_names) if self.feature_names else [],
            "training_samples": self.training_samples,
            "precision_score":  self.precision_score,
            "recall_score":     self.recall_score,
            "f1_score":         self.f1_score,
            "model_path":       self.model_path,
            "is_active":        self.is_active,
            "node_meta":        json.loads(self.node_meta) if self.node_meta else {},
            "created_at":       str(self.created_at),
        }


class AnomalyDetection(db.Model):
    __tablename__ = "ml_anomaly_detections"

    id               = db.Column(db.Integer,     primary_key=True)
    model_version_id = db.Column(db.Integer,     db.ForeignKey("ml_anomaly_model_versions.id"), nullable=False)
    user_id          = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    target_ip        = db.Column(db.String(100), nullable=True)
    target_device    = db.Column(db.String(200), nullable=True)
    is_anomaly       = db.Column(db.Boolean,     nullable=False, default=False)
    anomaly_score    = db.Column(db.Float,       nullable=False, default=0.0)
    severity         = db.Column(db.String(20),  nullable=False, default="low")
    feature_vector   = db.Column(db.Text,        nullable=True)   # JSON
    top_contributors = db.Column(db.Text,        nullable=True)   # JSON
    node_meta        = db.Column(db.Text,        nullable=True)   # JSON
    detected_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":               self.id,
            "model_version_id": self.model_version_id,
            "user_id":          self.user_id,
            "target_ip":        self.target_ip,
            "target_device":    self.target_device,
            "is_anomaly":       self.is_anomaly,
            "anomaly_score":    self.anomaly_score,
            "severity":         self.severity,
            "feature_vector":   json.loads(self.feature_vector) if self.feature_vector else {},
            "top_contributors": json.loads(self.top_contributors) if self.top_contributors else [],
            "node_meta":        json.loads(self.node_meta) if self.node_meta else {},
            "detected_at":      str(self.detected_at),
        }
