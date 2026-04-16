"""
AIPET X — AI Red Team Models

Three tables:
  rt_campaigns — named red team engagements
                 each campaign targets specific scope
                 and uses selected attack techniques
  rt_attacks   — individual attack technique executions
                 within a campaign
  rt_results   — findings from each attack attempt
                 (success/partial/blocked + evidence)
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class RtCampaign(db.Model):
    """
    A red team campaign — a named autonomous attack simulation.

    scope:       what is being tested (network CIDR, device list)
    objectives:  what the simulation is trying to achieve
    status:      draft | running | completed | aborted
    overall_score: 0-100 defence score (100 = all attacks blocked)
    """
    __tablename__ = "rt_campaigns"

    id            = db.Column(db.Integer,     primary_key=True)
    name          = db.Column(db.String(200), nullable=False)
    description   = db.Column(db.Text,        nullable=True)
    scope         = db.Column(db.Text,        nullable=True)
    objectives    = db.Column(db.Text,        nullable=True)
    status        = db.Column(db.String(30),  default="draft")
    attack_count  = db.Column(db.Integer,     default=0)
    success_count = db.Column(db.Integer,     default=0)
    blocked_count = db.Column(db.Integer,     default=0)
    overall_score = db.Column(db.Integer,     default=0)
    duration_sec  = db.Column(db.Integer,     default=0)
    created_by    = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    completed_at  = db.Column(db.DateTime,    nullable=True)

    def to_dict(self):
        return {
            "id":            self.id,
            "name":          self.name,
            "description":   self.description,
            "scope":         self.scope,
            "objectives":    self.objectives,
            "status":        self.status,
            "attack_count":  self.attack_count,
            "success_count": self.success_count,
            "blocked_count": self.blocked_count,
            "overall_score": self.overall_score,
            "duration_sec":  self.duration_sec,
            "created_at":    str(self.created_at),
            "completed_at":  str(self.completed_at) if self.completed_at else None,
        }


class RtAttack(db.Model):
    """
    A single attack technique execution within a campaign.

    mitre_id:    MITRE ATT&CK technique ID (e.g. T1078)
    tactic:      which ATT&CK tactic this belongs to
    technique:   human-readable technique name
    target:      the device/system being attacked
    result:      success | partial | blocked | error
    impact:      what was achieved if successful
    """
    __tablename__ = "rt_attacks"

    id          = db.Column(db.Integer,     primary_key=True)
    campaign_id = db.Column(db.Integer,     db.ForeignKey("rt_campaigns.id"), nullable=False)
    mitre_id    = db.Column(db.String(50),  nullable=False)
    tactic      = db.Column(db.String(100), nullable=False)
    technique   = db.Column(db.String(200), nullable=False)
    target      = db.Column(db.String(200), nullable=True)
    result      = db.Column(db.String(30),  default="pending")
    impact      = db.Column(db.Text,        nullable=True)
    evidence    = db.Column(db.Text,        nullable=True)
    blocked_by  = db.Column(db.String(200), nullable=True)
    severity    = db.Column(db.String(20),  default="High")
    executed_at = db.Column(db.DateTime,    nullable=True)
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":          self.id,
            "campaign_id": self.campaign_id,
            "mitre_id":    self.mitre_id,
            "tactic":      self.tactic,
            "technique":   self.technique,
            "target":      self.target,
            "result":      self.result,
            "impact":      self.impact,
            "evidence":    self.evidence,
            "blocked_by":  self.blocked_by,
            "severity":    self.severity,
            "executed_at": str(self.executed_at) if self.executed_at else None,
        }
