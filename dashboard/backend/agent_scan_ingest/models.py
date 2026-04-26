# =============================================================
# AIPET X — Agent Scan Submission (idempotency tracking)
# Maps agent scan_id → real_scan_results.id to prevent duplicates.
# =============================================================

from datetime import datetime, timezone
from ..models import db


class AgentScanSubmission(db.Model):
    __tablename__ = "agent_scan_submissions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    scan_id = db.Column(db.String(256), nullable=False)   # agent-provided idempotency key
    real_scan_id = db.Column(db.String(64), nullable=False)  # FK to real_scan_results.id
    agent_key_id = db.Column(db.Integer, db.ForeignKey("agent_api_keys.id"), nullable=True)
    ingested_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "scan_id", name="uq_agent_scan_user_scan_id"),
        db.Index("ix_agent_scan_sub_user_id", "user_id"),
    )
