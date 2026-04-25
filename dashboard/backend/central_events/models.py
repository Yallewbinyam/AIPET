# ============================================================
# AIPET X — Central Event Pipeline Model
# ============================================================
from datetime import datetime, timezone
from dashboard.backend.models import db


_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_ENTITY_TYPES = {"device", "user", "service", "endpoint", "cve", "indicator", "none"}


class CentralEvent(db.Model):
    __tablename__ = "central_events"

    id            = db.Column(db.Integer, primary_key=True)

    # Source attribution — mandatory; identifies the originating module and row
    source_module = db.Column(db.String(64),  nullable=False, index=True)
    source_table  = db.Column(db.String(64),  nullable=False)
    source_row_id = db.Column(db.String(64),  nullable=False)   # coerced to str; int/uuid both fit

    # Categorisation — mandatory
    event_type    = db.Column(db.String(128), nullable=False, index=True)
    severity      = db.Column(db.String(16),  nullable=False, index=True)   # info|low|medium|high|critical

    # Subject — the thing the event is about
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    entity        = db.Column(db.String(256), nullable=True, index=True)    # e.g. "10.0.3.11"
    entity_type   = db.Column(db.String(32),  nullable=True)                # device|user|service|…

    # Human-readable enrichment
    title         = db.Column(db.String(512), nullable=True)
    description   = db.Column(db.Text,        nullable=True)

    # Optional structured enrichment
    mitre_techniques = db.Column(db.JSON, nullable=True)    # [{technique_id, confidence}]
    risk_score       = db.Column(db.Integer, nullable=True)  # 0-100

    # Module-specific flexible data
    payload  = db.Column(db.JSON, nullable=True, default=dict)

    # Internal housekeeping — NEVER name this 'metadata'
    node_meta  = db.Column(db.JSON, nullable=True, default=dict)
    created_at = db.Column(
        db.DateTime, nullable=False, index=True,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    __table_args__ = (
        db.Index("ix_central_events_created_severity", "created_at", "severity"),
        db.Index("ix_central_events_user_created",     "user_id",    "created_at"),
        db.Index("ix_central_events_entity_created",   "entity",     "created_at"),
        db.Index("ix_central_events_module_type",      "source_module", "event_type"),
    )

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "source_module":    self.source_module,
            "source_table":     self.source_table,
            "source_row_id":    self.source_row_id,
            "event_type":       self.event_type,
            "severity":         self.severity,
            "user_id":          self.user_id,
            "entity":           self.entity,
            "entity_type":      self.entity_type,
            "title":            self.title,
            "description":      self.description,
            "mitre_techniques": self.mitre_techniques,
            "risk_score":       self.risk_score,
            "payload":          self.payload or {},
            "created_at":       self.created_at.isoformat() if self.created_at else None,
        }
