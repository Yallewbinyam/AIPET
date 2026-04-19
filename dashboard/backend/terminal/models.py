"""
AIPET X Terminal — Models

Two tables:
  terminal_sessions  — active terminal sessions per user
  terminal_audit_log — every command executed (audit trail)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class TerminalSession(db.Model):
    """
    A terminal session — tracks context between commands.
    Context allows commands like "show more" or "filter by critical"
    to remember what the previous command returned.
    """
    __tablename__ = "terminal_sessions"

    id         = db.Column(db.Integer,     primary_key=True)
    user_id    = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    session_key= db.Column(db.String(100), nullable=False, unique=True)
    last_command=db.Column(db.String(500), nullable=True)
    context    = db.Column(db.Text,        nullable=True)  # JSON
    created_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":           self.id,
            "user_id":      self.user_id,
            "session_key":  self.session_key,
            "last_command": self.last_command,
            "context":      json.loads(self.context) if self.context else {},
            "updated_at":   str(self.updated_at),
        }


class TerminalAuditLog(db.Model):
    """
    Every command executed in the terminal — full audit trail.
    Required for Zero-Trust compliance and NIS2 Art.21 logging.
    """
    __tablename__ = "terminal_audit_log"

    id          = db.Column(db.Integer,     primary_key=True)
    user_id     = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=False)
    session_key = db.Column(db.String(100), nullable=True)
    raw_input   = db.Column(db.String(500), nullable=False)
    parsed_cmd  = db.Column(db.String(200), nullable=True)
    module      = db.Column(db.String(100), nullable=True)
    success     = db.Column(db.Boolean,     default=True)
    error       = db.Column(db.Text,        nullable=True)
    duration_ms = db.Column(db.Integer,     default=0)
    ip_address  = db.Column(db.String(50),  nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "user_id":    self.user_id,
            "raw_input":  self.raw_input,
            "parsed_cmd": self.parsed_cmd,
            "module":     self.module,
            "success":    self.success,
            "duration_ms":self.duration_ms,
            "created_at": str(self.created_at),
        }
