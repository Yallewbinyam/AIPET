"""
AIPET Ask — Per-user daily usage tracking and quota enforcement.

Soft limits per plan:
  Professional  — 50 queries / day
  Enterprise    — 500 queries / day

Quotas reset at midnight UTC.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from dashboard.backend.models import db

_LOG = logging.getLogger("aipet.ask_usage")

# ── Configurable plan limits ──────────────────────────────────────────────────

DAILY_LIMITS: dict[str, int] = {
    "professional": 50,
    "enterprise":   500,
}

_UNLIMITED_PLANS = set()  # no plan gets truly unlimited; keep empty for now


# ── Model ─────────────────────────────────────────────────────────────────────

class AskUsageLog(db.Model):
    __tablename__ = "ask_usage_log"

    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey("users.id"),
                                    nullable=False, index=True)
    date                = db.Column(db.Date, nullable=False)
    query_count         = db.Column(db.Integer, default=0, nullable=False)
    total_input_tokens  = db.Column(db.Integer, default=0, nullable=False)
    total_output_tokens = db.Column(db.Integer, default=0, nullable=False)
    updated_at          = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "date", name="uq_ask_usage_user_date"),
    )

    def to_dict(self) -> dict:
        return {
            "date":                str(self.date),
            "query_count":         self.query_count,
            "total_input_tokens":  self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "updated_at":          self.updated_at.isoformat() if self.updated_at else None,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _today_utc():
    """Return today's date in UTC."""
    return datetime.now(timezone.utc).date()


def _midnight_utc_iso() -> str:
    """Return ISO string for the next midnight UTC (when the quota resets)."""
    now  = datetime.now(timezone.utc)
    next_midnight = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return next_midnight.isoformat()


def _get_or_create_today(user_id: int, today=None):
    """Return (row, created) for (user_id, today). Never raises."""
    if today is None:
        today = _today_utc()
    row = AskUsageLog.query.filter_by(user_id=user_id, date=today).first()
    if row:
        return row, False
    row = AskUsageLog(user_id=user_id, date=today,
                      query_count=0, total_input_tokens=0, total_output_tokens=0)
    db.session.add(row)
    db.session.flush()   # get an id without a full commit
    return row, True


def get_today_usage(user_id: int) -> dict:
    """
    Return today's usage for this user.
    Safe to call without an active write transaction.
    """
    today = _today_utc()
    row   = AskUsageLog.query.filter_by(user_id=user_id, date=today).first()
    return {
        "date":          str(today),
        "query_count":   row.query_count   if row else 0,
        "input_tokens":  row.total_input_tokens  if row else 0,
        "output_tokens": row.total_output_tokens if row else 0,
    }


def check_daily_limit(user_id: int, plan: str) -> dict:
    """
    Check whether this user is within their daily query quota.

    Returns:
        {"allowed": True,  "used": N, "limit": M, "remaining": M-N}  — under limit
        {"allowed": False, "used": N, "limit": M, "resets_at": iso}  — over limit
    """
    limit = DAILY_LIMITS.get(plan, 0)
    used  = get_today_usage(user_id)["query_count"]

    if used < limit:
        return {"allowed": True,  "used": used, "limit": limit, "remaining": limit - used}
    return {
        "allowed":   False,
        "used":      used,
        "limit":     limit,
        "resets_at": _midnight_utc_iso(),
    }


def check_and_record_usage(
    user_id:       int,
    plan:          str,
    input_tokens:  int,
    output_tokens: int,
) -> dict:
    """
    Increment today's usage row after a successful Claude API call.

    Performs a belt-and-suspenders limit check — if the user somehow
    reached the limit between the pre-check and the Claude call, this
    will flag it in the return value (but won't 429 — that was the
    pre-check's job).

    Returns the updated usage dict.
    """
    today = _today_utc()
    try:
        row, _ = _get_or_create_today(user_id, today)
        row.query_count         += 1
        row.total_input_tokens  += max(0, int(input_tokens))
        row.total_output_tokens += max(0, int(output_tokens))
        row.updated_at           = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()

        limit = DAILY_LIMITS.get(plan, 0)
        return {
            "date":          str(today),
            "query_count":   row.query_count,
            "limit":         limit,
            "remaining":     max(0, limit - row.query_count),
            "input_tokens":  row.total_input_tokens,
            "output_tokens": row.total_output_tokens,
        }
    except Exception:
        _LOG.exception("check_and_record_usage: DB write failed uid=%s", user_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        return {"query_count": -1, "error": "usage_record_failed"}
