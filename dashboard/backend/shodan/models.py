"""
AIPET X — Shodan integration models (Capability 16).

Single table: shodan_lookups. Acts as a 24-hour cache to avoid
burning the free-tier 100-lookups-per-month quota on repeated
queries for the same IP.

Cache shape decisions:
- One row per IP (PK is `ip`). Updates overwrite the prior row;
  no historical record of how a Shodan host record changed over
  time (deferred to v1.1 if a "Shodan history" view is requested).
- Negative results (Shodan returned 404 "no information") ARE
  cached, with `node_meta.found=False`, to prevent quota burn on
  repeated probes of unindexed IPs.
- Cache is global, not per-user. Shodan returns the same data
  regardless of who asks; sharing the cache across users is the
  whole point. The `node_meta.first_looked_up_by` field records
  which user triggered the initial lookup, for audit only.

The table name `shodan_lookups` does NOT collide with the PyPI
`shodan` package; the package is imported as a top-level name in
routes.py via `from shodan import Shodan`.
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class ShodanLookup(db.Model):
    __tablename__ = "shodan_lookups"

    # IP is the natural key. Free-tier lookups are by IP only;
    # /shodan/host/<ip> doesn't accept hostnames.
    ip = db.Column(db.String(64), primary_key=True)

    # Raw JSON-serialised Shodan response, OR the empty-shape
    # placeholder for negative-cached entries. Stored as Text so
    # we can roundtrip via json.loads in routes.py.
    raw_json = db.Column(db.Text, default="{}", nullable=False)

    looked_up_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    # Free-form JSON-text bucket for {"found": bool,
    # "first_looked_up_by": int, "lookup_count": int, ...}.
    # Named node_meta per project convention — never "metadata".
    node_meta = db.Column(db.Text, nullable=True)

    def to_dict(self):
        import json
        return {
            "ip":           self.ip,
            "raw_json":     self.raw_json,
            "looked_up_at": self.looked_up_at.isoformat() if self.looked_up_at
                            else None,
            "node_meta":    json.loads(self.node_meta) if self.node_meta
                            else {},
        }
