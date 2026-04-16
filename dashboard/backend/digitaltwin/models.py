"""
AIPET X — Digital Twin Models

Three tables:
  twin_nodes      — virtual replicas of physical devices
                    tracks expected vs actual state
  twin_edges      — connections between nodes
                    (data flows, protocols, dependencies)
  twin_snapshots  — point-in-time state captures
                    used for divergence detection and simulation
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class TwinNode(db.Model):
    """
    A virtual replica of a physical IoT device.

    node_type:       sensor | gateway | plc | server |
                     router | camera | actuator | hub
    expected_state:  JSON — what this device should look like
                     (firmware, open ports, traffic patterns)
    actual_state:    JSON — what AIPET last observed
    diverged:        True if actual != expected
    risk_score:      0-100 — calculated from findings + divergence
    """
    __tablename__ = "twin_nodes"

    id             = db.Column(db.Integer,     primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    node_type      = db.Column(db.String(50),  nullable=False)
    ip_address     = db.Column(db.String(100), nullable=True)
    mac_address    = db.Column(db.String(50),  nullable=True)
    vendor         = db.Column(db.String(200), nullable=True)
    firmware       = db.Column(db.String(100), nullable=True)
    location       = db.Column(db.String(200), nullable=True)
    zone           = db.Column(db.String(50),  default="operations")
    expected_state = db.Column(db.Text,        nullable=True)   # JSON
    actual_state   = db.Column(db.Text,        nullable=True)   # JSON
    diverged       = db.Column(db.Boolean,     default=False)
    risk_score     = db.Column(db.Integer,     default=0)
    online         = db.Column(db.Boolean,     default=True)
    x_pos          = db.Column(db.Float,       default=0.0)     # canvas position
    y_pos          = db.Column(db.Float,       default=0.0)
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":             self.id,
            "name":           self.name,
            "node_type":      self.node_type,
            "ip_address":     self.ip_address,
            "mac_address":    self.mac_address,
            "vendor":         self.vendor,
            "firmware":       self.firmware,
            "location":       self.location,
            "zone":           self.zone,
            "expected_state": self.expected_state,
            "actual_state":   self.actual_state,
            "diverged":       self.diverged,
            "risk_score":     self.risk_score,
            "online":         self.online,
            "x_pos":          self.x_pos,
            "y_pos":          self.y_pos,
            "updated_at":     str(self.updated_at),
        }


class TwinEdge(db.Model):
    """
    A connection between two twin nodes.
    Represents a data flow, protocol communication,
    or logical dependency between devices.

    edge_type:  data_flow | control | management |
                monitoring | dependency
    protocol:   the communication protocol used
    encrypted:  whether the connection is encrypted
    """
    __tablename__ = "twin_edges"

    id           = db.Column(db.Integer,     primary_key=True)
    source_id    = db.Column(db.Integer,     db.ForeignKey("twin_nodes.id"), nullable=False)
    target_id    = db.Column(db.Integer,     db.ForeignKey("twin_nodes.id"), nullable=False)
    edge_type    = db.Column(db.String(50),  default="data_flow")
    protocol     = db.Column(db.String(50),  nullable=True)
    port         = db.Column(db.Integer,     nullable=True)
    encrypted    = db.Column(db.Boolean,     default=True)
    bandwidth    = db.Column(db.String(50),  nullable=True)   # e.g. "1Mbps"
    latency_ms   = db.Column(db.Integer,     nullable=True)
    active       = db.Column(db.Boolean,     default=True)
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "source_id":  self.source_id,
            "target_id":  self.target_id,
            "edge_type":  self.edge_type,
            "protocol":   self.protocol,
            "port":       self.port,
            "encrypted":  self.encrypted,
            "bandwidth":  self.bandwidth,
            "latency_ms": self.latency_ms,
            "active":     self.active,
        }


class TwinSnapshot(db.Model):
    """
    A point-in-time capture of the entire twin network state.
    Used for:
      - Historical comparison (what changed?)
      - Attack simulation (what would happen if X was compromised?)
      - Divergence detection (actual vs expected)
      - Compliance audit trail
    """
    __tablename__ = "twin_snapshots"

    id            = db.Column(db.Integer,     primary_key=True)
    label         = db.Column(db.String(200), nullable=True)
    snapshot_type = db.Column(db.String(50),  default="auto")
    # auto | manual | pre_simulation | post_simulation
    node_count    = db.Column(db.Integer,     default=0)
    edge_count    = db.Column(db.Integer,     default=0)
    diverged_count= db.Column(db.Integer,     default=0)
    risk_avg      = db.Column(db.Float,       default=0.0)
    data          = db.Column(db.Text,        nullable=True)   # Full JSON snapshot
    created_by    = db.Column(db.Integer,     db.ForeignKey("users.id"), nullable=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":             self.id,
            "label":          self.label,
            "snapshot_type":  self.snapshot_type,
            "node_count":     self.node_count,
            "edge_count":     self.edge_count,
            "diverged_count": self.diverged_count,
            "risk_avg":       self.risk_avg,
            "created_at":     str(self.created_at),
        }
