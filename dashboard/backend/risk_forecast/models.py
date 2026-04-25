from datetime import datetime, timezone
from dashboard.backend.models import db


class DeviceRiskScoreHistory(db.Model):
    __tablename__ = "device_risk_score_history"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    entity      = db.Column(db.String(256), nullable=False, index=True)
    entity_type = db.Column(db.String(32),  nullable=True)

    score                = db.Column(db.Integer, nullable=False)
    event_count_24h      = db.Column(db.Integer, default=0)
    contributing_modules = db.Column(db.JSON, default=list)

    snapshot_at = db.Column(
        db.DateTime, nullable=False, index=True,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    node_meta = db.Column(db.JSON, default=dict)  # NEVER "metadata"

    __table_args__ = (
        db.Index("ix_history_entity_time", "user_id", "entity", "entity_type", "snapshot_at"),
        db.Index("ix_history_snapshot_at", "snapshot_at"),
    )


class ForecastAlert(db.Model):
    __tablename__ = "forecast_alerts"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    entity      = db.Column(db.String(256), nullable=False, index=True)
    entity_type = db.Column(db.String(32),  nullable=True)

    threshold_name           = db.Column(db.String(64), nullable=False)
    threshold_value          = db.Column(db.Integer, nullable=False)
    current_score            = db.Column(db.Integer, nullable=False)
    predicted_crossing_date  = db.Column(db.DateTime, nullable=False)
    probability              = db.Column(db.Float,   nullable=False)

    model_used     = db.Column(db.String(32))
    history_points = db.Column(db.Integer)
    horizon_days   = db.Column(db.Integer, default=7)

    status          = db.Column(db.String(32), default="active")
    acknowledged_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(
        db.DateTime, nullable=False, index=True,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    node_meta = db.Column(db.JSON, default=dict)

    __table_args__ = (
        db.UniqueConstraint("user_id", "entity", "threshold_name", "status",
                            name="uq_forecast_active"),
        db.Index("ix_forecast_user_status", "user_id", "status"),
    )

    def to_dict(self) -> dict:
        return {
            "id":                      self.id,
            "user_id":                 self.user_id,
            "entity":                  self.entity,
            "entity_type":             self.entity_type,
            "threshold_name":          self.threshold_name,
            "threshold_value":         self.threshold_value,
            "current_score":           self.current_score,
            "predicted_crossing_date": self.predicted_crossing_date.isoformat() if self.predicted_crossing_date else None,
            "probability":             round(self.probability, 3),
            "model_used":              self.model_used,
            "history_points":          self.history_points,
            "horizon_days":            self.horizon_days,
            "status":                  self.status,
            "acknowledged_at":         self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "created_at":              self.created_at.isoformat() if self.created_at else None,
        }
