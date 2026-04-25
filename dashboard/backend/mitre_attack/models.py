# ============================================================
# AIPET X — MITRE ATT&CK Catalog Model
# ============================================================
from datetime import datetime, timezone
from dashboard.backend.models import db


class MitreTechnique(db.Model):
    __tablename__ = "mitre_techniques"

    technique_id        = db.Column(db.String(16),  primary_key=True)  # natural key e.g. "T1110"
    name                = db.Column(db.String(256),  nullable=True)
    tactic              = db.Column(db.String(128),  nullable=True)
    tactic_id           = db.Column(db.String(16),   nullable=True)
    description         = db.Column(db.Text,         nullable=True)
    url                 = db.Column(db.String(512),   nullable=True)
    platforms           = db.Column(db.JSON,          nullable=True)
    is_subtechnique     = db.Column(db.Boolean,       default=False)
    parent_technique_id = db.Column(db.String(16),    nullable=True)
    node_meta           = db.Column(db.JSON,          default=dict)   # NEVER 'metadata'
    last_updated        = db.Column(db.DateTime,      nullable=True)

    def to_dict(self):
        return {
            "technique_id":        self.technique_id,
            "name":                self.name,
            "tactic":              self.tactic,
            "tactic_id":           self.tactic_id,
            "description":         self.description,
            "url":                 self.url,
            "platforms":           self.platforms,
            "is_subtechnique":     self.is_subtechnique,
            "parent_technique_id": self.parent_technique_id,
            "last_updated":        self.last_updated.isoformat() if self.last_updated else None,
        }


def seed_catalog_from_dict() -> int:
    """
    Upsert all TECHNIQUE_CATALOG entries into mitre_techniques.
    Idempotent — safe to call on every startup.
    Returns the number of techniques upserted.
    """
    from dashboard.backend.mitre_attack.catalog import TECHNIQUE_CATALOG
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    upserted = 0
    for tid, entry in TECHNIQUE_CATALOG.items():
        obj = MitreTechnique(
            technique_id        = tid,
            name                = entry.get("name"),
            tactic              = entry.get("tactic"),
            tactic_id           = entry.get("tactic_id"),
            description         = entry.get("description"),
            url                 = entry.get("url"),
            platforms           = entry.get("platforms"),
            is_subtechnique     = entry.get("is_subtechnique", False),
            parent_technique_id = entry.get("parent_technique"),
            node_meta           = {},
            last_updated        = now,
        )
        db.session.merge(obj)
        upserted += 1
    db.session.commit()
    return upserted
