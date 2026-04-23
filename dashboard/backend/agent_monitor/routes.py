# ============================================================
# AIPET X — Agent Monitor Backend
# Receives telemetry from installed Python agents
# ============================================================

import uuid, datetime, json
from flask import Blueprint, request, jsonify
from dashboard.backend.validation import validate_body, TELEMETRY_SCHEMA
from flask_jwt_extended import jwt_required, get_jwt_identity, decode_token
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, Index

agent_monitor_bp = Blueprint("agent_monitor", __name__)


# ── Models ────────────────────────────────────────────────

class AgentDevice(db.Model):
    __tablename__ = "agent_devices"
    id          = Column(String(64), primary_key=True)           # agent_id set by agent
    user_id     = Column(Integer, nullable=False, index=True)
    hostname    = Column(String(256), default="")
    platform    = Column(String(64), default="")
    ip_address  = Column(String(64), default="")
    agent_version = Column(String(32), default="1.0.0")
    first_seen  = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.datetime.utcnow)
    status      = Column(String(16), default="online")           # online | offline | stale

    def to_dict(self):
        return {
            "id":            self.id,
            "hostname":      self.hostname,
            "platform":      self.platform,
            "ip_address":    self.ip_address,
            "agent_version": self.agent_version,
            "first_seen":    self.first_seen.isoformat(),
            "last_seen":     self.last_seen.isoformat(),
            "status":        self.status,
        }


class AgentTelemetry(db.Model):
    __tablename__ = "agent_telemetry"
    id          = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id    = Column(String(64), nullable=False, index=True)
    user_id     = Column(Integer, nullable=False, index=True)
    collected_at= Column(DateTime, default=datetime.datetime.utcnow, index=True)

    # System metrics
    cpu_percent     = Column(Float, default=0.0)
    cpu_count       = Column(Integer, default=0)
    mem_total_gb    = Column(Float, default=0.0)
    mem_used_gb     = Column(Float, default=0.0)
    mem_percent     = Column(Float, default=0.0)
    disk_total_gb   = Column(Float, default=0.0)
    disk_used_gb    = Column(Float, default=0.0)
    disk_percent    = Column(Float, default=0.0)

    # JSON blobs
    processes_json  = Column(Text, default="[]")   # top 20 by CPU
    connections_json= Column(Text, default="[]")   # active network connections
    disks_json      = Column(Text, default="[]")   # per-partition breakdown

    __table_args__ = (
        Index("ix_agent_telemetry_agent_time", "agent_id", "collected_at"),
    )

    def to_dict(self):
        return {
            "id":           self.id,
            "agent_id":     self.agent_id,
            "collected_at": self.collected_at.isoformat(),
            "cpu_percent":  self.cpu_percent,
            "cpu_count":    self.cpu_count,
            "mem_total_gb": self.mem_total_gb,
            "mem_used_gb":  self.mem_used_gb,
            "mem_percent":  self.mem_percent,
            "disk_total_gb":self.disk_total_gb,
            "disk_used_gb": self.disk_used_gb,
            "disk_percent": self.disk_percent,
            "processes":    json.loads(self.processes_json or "[]"),
            "connections":  json.loads(self.connections_json or "[]"),
            "disks":        json.loads(self.disks_json or "[]"),
        }


# ── Routes ────────────────────────────────────────────────

@agent_monitor_bp.route("/api/agent/telemetry", methods=["POST"])
@jwt_required()
@validate_body(TELEMETRY_SCHEMA)
def receive_telemetry():
    uid  = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    agent_id = data.get("agent_id", "").strip()
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    now = datetime.datetime.utcnow()

    # Upsert device record
    device = AgentDevice.query.get(agent_id)
    if not device:
        device = AgentDevice(
            id=agent_id,
            user_id=uid,
            hostname=data.get("hostname", ""),
            platform=data.get("platform", ""),
            ip_address=request.remote_addr,
            agent_version=data.get("agent_version", "1.0.0"),
            first_seen=now,
        )
        db.session.add(device)
    else:
        device.last_seen   = now
        device.status      = "online"
        device.hostname    = data.get("hostname", device.hostname)
        device.ip_address  = request.remote_addr

    # Store telemetry snapshot
    snap = AgentTelemetry(
        agent_id=agent_id,
        user_id=uid,
        collected_at=now,
        cpu_percent    =float(data.get("cpu_percent", 0)),
        cpu_count      =int(data.get("cpu_count", 0)),
        mem_total_gb   =float(data.get("mem_total_gb", 0)),
        mem_used_gb    =float(data.get("mem_used_gb", 0)),
        mem_percent    =float(data.get("mem_percent", 0)),
        disk_total_gb  =float(data.get("disk_total_gb", 0)),
        disk_used_gb   =float(data.get("disk_used_gb", 0)),
        disk_percent   =float(data.get("disk_percent", 0)),
        processes_json =json.dumps(data.get("processes", [])[:20]),
        connections_json=json.dumps(data.get("connections", [])[:50]),
        disks_json     =json.dumps(data.get("disks", [])),
    )
    db.session.add(snap)
    db.session.commit()

    return jsonify({"ok": True, "snapshot_id": snap.id}), 200


@agent_monitor_bp.route("/api/agent/devices", methods=["GET"])
@jwt_required()
def list_devices():
    uid = get_jwt_identity()
    # Mark devices stale if not seen in 90 seconds
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=90)
    devices = AgentDevice.query.filter_by(user_id=uid).all()
    for d in devices:
        if d.last_seen and d.last_seen < cutoff:
            d.status = "offline"
    db.session.commit()
    return jsonify({"devices": [d.to_dict() for d in devices]}), 200


@agent_monitor_bp.route("/api/agent/devices/<agent_id>/latest", methods=["GET"])
@jwt_required()
def latest_telemetry(agent_id):
    uid  = get_jwt_identity()
    snap = AgentTelemetry.query.filter_by(agent_id=agent_id, user_id=uid)\
               .order_by(AgentTelemetry.collected_at.desc()).first()
    if not snap:
        return jsonify({"error": "No telemetry yet"}), 404
    return jsonify(snap.to_dict()), 200


@agent_monitor_bp.route("/api/agent/devices/<agent_id>/history", methods=["GET"])
@jwt_required()
def telemetry_history(agent_id):
    uid    = get_jwt_identity()
    limit  = min(int(request.args.get("limit", 60)), 360)
    snaps  = AgentTelemetry.query.filter_by(agent_id=agent_id, user_id=uid)\
                 .order_by(AgentTelemetry.collected_at.desc()).limit(limit).all()
    return jsonify({"history": [s.to_dict() for s in reversed(snaps)]}), 200


@agent_monitor_bp.route("/api/agent/devices/<agent_id>", methods=["DELETE"])
@jwt_required()
def delete_device(agent_id):
    uid    = get_jwt_identity()
    device = AgentDevice.query.filter_by(id=agent_id, user_id=uid).first()
    if not device:
        return jsonify({"error": "Not found"}), 404
    AgentTelemetry.query.filter_by(agent_id=agent_id, user_id=uid).delete()
    db.session.delete(device)
    db.session.commit()
    return jsonify({"deleted": True}), 200
