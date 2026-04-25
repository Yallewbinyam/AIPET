from datetime import datetime, timezone
from dashboard.backend.models import db


class DeviceRiskScore(db.Model):
    __tablename__ = "device_risk_scores"

    id = db.Column(db.Integer, primary_key=True)

    # Composite identity — matches central_events pivot pattern
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    entity      = db.Column(db.String(256), nullable=False, index=True)
    entity_type = db.Column(db.String(32),  nullable=True)

    # The score
    score = db.Column(db.Integer, nullable=False, default=0)  # 0-100

    # Diagnostic data
    event_count_24h      = db.Column(db.Integer, default=0)
    contributing_modules = db.Column(db.JSON,    default=list)
    top_contributors     = db.Column(db.JSON,    default=list)

    # Timestamps
    last_updated_at    = db.Column(
        db.DateTime, nullable=False, index=True,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    last_recomputed_at = db.Column(
        db.DateTime, nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    node_meta = db.Column(db.JSON, default=dict)  # NEVER "metadata"

    __table_args__ = (
        db.UniqueConstraint("user_id", "entity", "entity_type",
                            name="uq_device_risk_user_entity"),
        # Capability 8: "all devices for user with score >= N"
        db.Index("ix_device_risk_user_score", "user_id", "score"),
        # Global high-risk reports
        db.Index("ix_device_risk_score_updated", "score", "last_updated_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id":                   self.id,
            "user_id":              self.user_id,
            "entity":               self.entity,
            "entity_type":          self.entity_type,
            "score":                self.score,
            "event_count_24h":      self.event_count_24h,
            "contributing_modules": self.contributing_modules or [],
            "top_contributors":     self.top_contributors or [],
            "last_updated_at":      self.last_updated_at.isoformat() if self.last_updated_at else None,
            "last_recomputed_at":   self.last_recomputed_at.isoformat() if self.last_recomputed_at else None,
        }
