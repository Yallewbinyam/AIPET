"""
AIPET X — Threat Intel Models

Three tables:
  ioc_feeds    — registered threat feed sources (AbuseIPDB, local, custom)
  ioc_entries  — individual indicators of compromise (IPs, domains, hashes)
  threat_matches — when a scan target matched a known bad indicator
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class IocFeed(db.Model):
    """A threat intelligence feed source."""
    __tablename__ = "ioc_feeds"

    id           = db.Column(db.Integer,     primary_key=True)
    name         = db.Column(db.String(200), nullable=False)
    feed_type    = db.Column(db.String(50),  nullable=False)  # local | abuseipdb | custom
    description  = db.Column(db.Text,        nullable=True)
    enabled      = db.Column(db.Boolean,     default=True)
    api_key      = db.Column(db.Text,        nullable=True)   # encrypted in production
    last_sync    = db.Column(db.DateTime,    nullable=True)
    entry_count  = db.Column(db.Integer,     default=0)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "name":        self.name,
            "feed_type":   self.feed_type,
            "description": self.description,
            "enabled":     self.enabled,
            "last_sync":   str(self.last_sync) if self.last_sync else None,
            "entry_count": self.entry_count,
        }


class IocEntry(db.Model):
    """
    A single Indicator of Compromise.
    ioc_type: ip | domain | hash | url
    confidence: 0-100 (100 = definitely malicious)
    """
    __tablename__ = "ioc_entries"

    id           = db.Column(db.Integer,     primary_key=True)
    feed_id      = db.Column(db.Integer,     db.ForeignKey("ioc_feeds.id"), nullable=False)
    ioc_type     = db.Column(db.String(20),  nullable=False)   # ip | domain | hash | url
    value        = db.Column(db.String(500), nullable=False)   # the actual IP / domain / hash
    threat_type  = db.Column(db.String(100), nullable=True)    # malware | c2 | phishing etc
    confidence   = db.Column(db.Integer,     default=75)       # 0-100
    severity     = db.Column(db.String(20),  default="High")
    description  = db.Column(db.Text,        nullable=True)
    source_ref   = db.Column(db.String(500), nullable=True)    # external reference URL
    active       = db.Column(db.Boolean,     default=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    expires_at   = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":          self.id,
            "feed_id":     self.feed_id,
            "ioc_type":    self.ioc_type,
            "value":       self.value,
            "threat_type": self.threat_type,
            "confidence":  self.confidence,
            "severity":    self.severity,
            "description": self.description,
            "source_ref":  self.source_ref,
            "active":      self.active,
            "created_at":  str(self.created_at),
        }


class ThreatMatch(db.Model):
    """
    Records when a scan target matched a known IOC.
    This is the critical table — links scans to threat intel.
    """
    __tablename__ = "threat_matches"

    id           = db.Column(db.Integer,     primary_key=True)
    ioc_entry_id = db.Column(db.Integer,     db.ForeignKey("ioc_entries.id"), nullable=True)
    scan_id      = db.Column(db.Integer,     db.ForeignKey("scans.id"),       nullable=True)
    matched_value= db.Column(db.String(500), nullable=False)   # the IP/domain that matched
    match_source = db.Column(db.String(100), nullable=False)   # local | abuseipdb
    threat_type  = db.Column(db.String(100), nullable=True)
    confidence   = db.Column(db.Integer,     default=75)
    severity     = db.Column(db.String(20),  default="High")
    details      = db.Column(db.Text,        nullable=True)    # JSON blob of raw API response
    user_id      = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "matched_value": self.matched_value,
            "match_source":  self.match_source,
            "threat_type":   self.threat_type,
            "confidence":    self.confidence,
            "severity":      self.severity,
            "details":       self.details,
            "scan_id":       self.scan_id,
            "created_at":    str(self.created_at),
        }
