# ============================================================
# AIPET X — Live CVE Feed Models
# ============================================================

import datetime
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, Boolean, Index


class LiveCve(db.Model):
    __tablename__ = "live_cves"

    cve_id        = Column(String(32), primary_key=True)
    description   = Column(Text, default="")
    cvss_score    = Column(Float, nullable=True)
    severity      = Column(String(16), default="UNKNOWN")
    published     = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    cpe_list      = Column(Text, default="[]")   # JSON list of CPE strings
    keywords      = Column(Text, default="[]")   # JSON list of extracted product keywords
    synced_at     = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    url           = Column(String(256), default="")

    __table_args__ = (
        Index("ix_live_cves_severity", "severity"),
        Index("ix_live_cves_cvss",     "cvss_score"),
        Index("ix_live_cves_published","published"),
    )

    def to_dict(self):
        return {
            "cve_id":        self.cve_id,
            "description":   self.description,
            "cvss_score":    self.cvss_score,
            "severity":      self.severity,
            "published":     self.published.isoformat() if self.published else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "keywords":      self.keywords,
            "url":           self.url,
            "synced_at":     self.synced_at.isoformat() if self.synced_at else None,
        }


class CveSyncLog(db.Model):
    __tablename__ = "cve_sync_logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    started_at  = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    cves_added  = Column(Integer, default=0)
    cves_updated= Column(Integer, default=0)
    status      = Column(String(32), default="running")   # running | complete | error
    error       = Column(Text, nullable=True)
    source      = Column(String(64), default="nvd_api")

    def to_dict(self):
        return {
            "id":           self.id,
            "started_at":   self.started_at.isoformat(),
            "finished_at":  self.finished_at.isoformat() if self.finished_at else None,
            "cves_added":   self.cves_added,
            "cves_updated": self.cves_updated,
            "status":       self.status,
            "error":        self.error,
        }
