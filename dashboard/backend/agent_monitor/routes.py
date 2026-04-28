# ============================================================
# AIPET X — Agent Monitor Backend
# Receives telemetry from installed Python agents
# ============================================================

import uuid, datetime, json
from flask import Blueprint, request, jsonify, g
from dashboard.backend.validation import validate_body, TELEMETRY_SCHEMA
from flask_jwt_extended import jwt_required, get_jwt_identity, decode_token
from dashboard.backend.agent_keys.auth import agent_or_jwt_required
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
    # Soft-delete: NULL = active, non-NULL = deleted at this UTC instant.
    # Indexed because every active-device query filters on `deleted_at IS NULL`.
    # Naming note: project convention elsewhere uses `first_seen`/`last_seen`
    # (no _at suffix), but `deleted_at` is the universal soft-delete idiom and
    # consistent with what most SQLAlchemy ecosystem helpers expect.
    deleted_at  = Column(DateTime, nullable=True, index=True)

    # -- Soft-delete query helpers -----------------------------------
    # Convention: every NEW Device query in this codebase MUST pick one
    # of these explicitly:
    #   AgentDevice.active()         -- excludes soft-deleted (default
    #                                   for normal app paths)
    #   AgentDevice.with_deleted()   -- includes soft-deleted (admin /
    #                                   audit / lifecycle ops only)
    # Bare `AgentDevice.query` is a code smell. If you find yourself
    # writing it, you almost always want one of the above.

    @classmethod
    def active(cls):
        """Query that excludes soft-deleted rows. Default for app paths."""
        return cls.query.filter(cls.deleted_at.is_(None))

    @classmethod
    def with_deleted(cls):
        """Unfiltered query. Use ONLY where soft-deleted rows are wanted
        (admin views, audit, lifecycle ops like restore/re-delete-prevention)."""
        return cls.query

    # -- Lifecycle ops -----------------------------------------------

    def soft_delete(self, actor_user_id, reason=None):
        """
        Mark this device as soft-deleted. Idempotent: a no-op (and no
        audit entry) if already deleted -- returns False in that case.
        Returns True on transition from active -> deleted.

        Caller is responsible for db.session.commit(); this method
        modifies state but does not commit, so the caller can include
        it in a larger transaction.
        """
        if self.deleted_at is not None:
            return False
        from dashboard.backend.iam.routes import log_action
        self.deleted_at = datetime.datetime.utcnow()
        # Detached audit row -- self.id and self.hostname captured even
        # if the device row is later hard-deleted.
        log_action(
            user_id=actor_user_id,
            action="device.soft_deleted",
            resource=self.id,
            details={
                "device_hostname": self.hostname,
                "device_platform": self.platform,
                "reason": reason,
                "deleted_at": self.deleted_at.isoformat() + "Z",
            },
        )
        return True

    def restore(self, actor_user_id, reason=None):
        """
        Clear deleted_at. Idempotent: no-op + no audit entry if already
        active. Returns True on transition from deleted -> active.
        """
        if self.deleted_at is None:
            return False
        from dashboard.backend.iam.routes import log_action
        previously_deleted_at = self.deleted_at.isoformat() + "Z"
        self.deleted_at = None
        log_action(
            user_id=actor_user_id,
            action="device.restored",
            resource=self.id,
            details={
                "device_hostname": self.hostname,
                "device_platform": self.platform,
                "reason": reason,
                "previously_deleted_at": previously_deleted_at,
            },
        )
        return True

    def record_telemetry_after_delete(self, telemetry_at):
        """
        Audit-only: device received telemetry while soft-deleted. Per
        Decision 2 in the soft-delete brief: accept the telemetry
        (preserve forensic data), DO NOT auto-restore (admin intent
        wins), and emit an auditable signal. Useful for spotting
        either a user who hasn't uninstalled yet OR an attacker
        reusing a key the legitimate owner thought was retired.
        """
        from dashboard.backend.iam.routes import log_action
        log_action(
            # No human actor -- this is a system-emitted event. Use
            # the device's owning user_id as the closest meaningful
            # actor (the audit row will show "this user's device sent
            # telemetry while soft-deleted"). NULL would also work
            # but the schema has user_id as a nullable FK so we keep
            # it populated when we can.
            user_id=self.user_id,
            action="device.telemetry_after_delete",
            resource=self.id,
            details={
                "device_hostname": self.hostname,
                "telemetry_at": telemetry_at.isoformat() + "Z",
                "originally_deleted_at": (
                    self.deleted_at.isoformat() + "Z" if self.deleted_at else None
                ),
            },
            status="warning",
        )

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
            "deleted_at":    (self.deleted_at.isoformat() + "Z" if self.deleted_at else None),
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
@agent_or_jwt_required(scope="agent", permissions=["telemetry:write"])
@validate_body(TELEMETRY_SCHEMA)
def receive_telemetry():
    # Hybrid auth: g.current_user_id populated by @agent_or_jwt_required
    # for both X-Agent-Key (systemd-managed agent) and JWT (dashboard) callers.
    uid  = g.current_user_id
    data = request.get_json(silent=True) or {}

    agent_id = data.get("agent_id", "").strip()
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    now = datetime.datetime.utcnow()

    # CALLSITE 1/3 (soft-delete audit): telemetry upsert.
    # Use with_deleted() so we see the row even if soft-deleted -- that
    # is the only way the telemetry-after-delete audit branch can fire.
    # Decision 2 from the soft-delete brief: accept the telemetry,
    # do NOT auto-restore, emit an auditable signal.
    device = AgentDevice.with_deleted().filter_by(id=agent_id).first()
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
        if device.deleted_at is not None:
            # Telemetry from a soft-deleted device. Audit but do NOT
            # restore. The hostname/platform/last_seen on the row may
            # also be stale by design -- we don't want a deleted row
            # to "come alive" cosmetically in any admin view.
            device.record_telemetry_after_delete(telemetry_at=now)
            # Keep last_seen up to date so security ops can correlate
            # post-delete telemetry timestamps. Status stays 'online'
            # internally but the dashboard view filters on
            # deleted_at IS NULL so it won't render.
            device.last_seen = now
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

    # ?include_deleted=true is admin-only: gates on the canonical
    # `audit:read` permission (the same permission name the IAM
    # blueprint uses for "view audit-grade data"). Tenant scope
    # (filter_by(user_id=uid)) is enforced regardless -- even an
    # admin only sees deleted rows for their own user_id.
    include_deleted = (request.args.get("include_deleted", "").lower()
                       in ("1", "true", "yes"))

    if include_deleted:
        from dashboard.backend.iam.models import UserRole, Role
        from dashboard.backend.models import User
        user = db.session.get(User, int(uid))
        has_perm = False
        if user:
            user_roles = UserRole.query.filter_by(user_id=user.id).all()
            role_ids = [ur.role_id for ur in user_roles]
            roles = Role.query.filter(Role.id.in_(role_ids)).all() if role_ids else []
            role_names = [r.name for r in roles]
            if "owner" in role_names:
                has_perm = True
            else:
                for role in roles:
                    if any(p.name == "audit:read" for p in (role.permissions or [])):
                        has_perm = True
                        break
        if not has_perm:
            return jsonify({
                "error": "Insufficient permissions",
                "required": "audit:read",
            }), 403

    # CALLSITE 2/3 (soft-delete audit): list endpoint. Default path
    # uses .active() (excludes soft-deleted). The admin
    # ?include_deleted=true path uses .with_deleted() -- still scoped
    # to user_id so we never leak across tenants.
    base_q = AgentDevice.with_deleted() if include_deleted else AgentDevice.active()
    devices = base_q.filter_by(user_id=uid).all()

    # Mark devices stale if not seen in 90 seconds (skip for soft-
    # deleted rows -- their status display is irrelevant).
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=90)
    for d in devices:
        if d.deleted_at is None and d.last_seen and d.last_seen < cutoff:
            d.status = "offline"
    db.session.commit()
    return jsonify({
        "devices": [d.to_dict() for d in devices],
        "include_deleted": include_deleted,
    }), 200


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
    """
    Soft-delete a device. Tenant-scoped: a user can only soft-delete
    their own devices. Idempotent: deleting an already-deleted device
    returns 200 with {already_deleted: true}.

    PRE-PLB-1 NOTE (preserved as an incident in the closure report):
    this endpoint previously did a HARD delete of the device row AND
    cascade-deleted every AgentTelemetry row. That destroyed forensic
    history on every delete -- unacceptable for a security platform.
    Now: device.soft_delete() flips deleted_at; telemetry is preserved.
    """
    uid    = int(get_jwt_identity())
    body   = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip()[:500] or None

    # CALLSITE 3/3 (soft-delete audit): delete endpoint. with_deleted()
    # so we can find an already-soft-deleted row and respond with the
    # idempotent already_deleted=true rather than a confusing 404.
    device = (AgentDevice.with_deleted()
              .filter_by(id=agent_id, user_id=uid)
              .first())
    if not device:
        return jsonify({"error": "Not found"}), 404

    if device.deleted_at is not None:
        return jsonify({
            "deleted": True,
            "already_deleted": True,
            "deleted_at": device.deleted_at.isoformat() + "Z",
        }), 200

    device.soft_delete(actor_user_id=uid, reason=reason)
    db.session.commit()
    return jsonify({
        "deleted": True,
        "deleted_at": device.deleted_at.isoformat() + "Z",
    }), 200


@agent_monitor_bp.route("/api/agent/devices/<agent_id>/restore", methods=["POST"])
@jwt_required()
def restore_device(agent_id):
    """
    Undo a soft-delete. Same auth as DELETE -- per-tenant scoping.
    Idempotent: restoring an already-active device returns 200 with
    {already_active: true}.
    """
    uid    = int(get_jwt_identity())
    body   = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip()[:500] or None

    device = (AgentDevice.with_deleted()
              .filter_by(id=agent_id, user_id=uid)
              .first())
    if not device:
        return jsonify({"error": "Not found"}), 404

    if device.deleted_at is None:
        return jsonify({
            "restored": True,
            "already_active": True,
            "device": device.to_dict(),
        }), 200

    device.restore(actor_user_id=uid, reason=reason)
    db.session.commit()
    return jsonify({
        "restored": True,
        "device": device.to_dict(),
    }), 200
