# ============================================================
# AIPET X — Live CVE Feed API
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.live_cves.models import LiveCve, CveSyncLog
import json

live_cves_bp = Blueprint("live_cves", __name__)


@live_cves_bp.route("/api/live-cves/feed", methods=["GET"])
@jwt_required()
def feed():
    severity = request.args.get("severity")
    limit    = min(int(request.args.get("limit", 50)), 200)
    offset   = int(request.args.get("offset", 0))
    q        = LiveCve.query
    if severity:
        q = q.filter_by(severity=severity.upper())
    cves = q.order_by(LiveCve.published.desc()).offset(offset).limit(limit).all()
    total = LiveCve.query.count()
    return jsonify({"cves": [c.to_dict() for c in cves], "total": total}), 200


@live_cves_bp.route("/api/live-cves/stats", methods=["GET"])
@jwt_required()
def stats():
    from sqlalchemy import func
    from dashboard.backend.models import db
    counts = db.session.query(LiveCve.severity, func.count(LiveCve.cve_id)).group_by(LiveCve.severity).all()
    last_sync = CveSyncLog.query.order_by(CveSyncLog.started_at.desc()).first()
    total = LiveCve.query.count()
    return jsonify({
        "total": total,
        "by_severity": {sev: cnt for sev, cnt in counts},
        "last_sync": last_sync.to_dict() if last_sync else None,
    }), 200


@live_cves_bp.route("/api/live-cves/sync-logs", methods=["GET"])
@jwt_required()
def sync_logs():
    logs = CveSyncLog.query.order_by(CveSyncLog.started_at.desc()).limit(20).all()
    return jsonify({"logs": [l.to_dict() for l in logs]}), 200


@live_cves_bp.route("/api/live-cves/trigger-sync", methods=["POST"])
@jwt_required()
def trigger_sync():
    from dashboard.backend.tasks import sync_nvd_cves
    result = sync_nvd_cves.delay()
    return jsonify({"task_id": result.id, "status": "queued"}), 202


@live_cves_bp.route("/api/live-cves/search", methods=["GET"])
@jwt_required()
def search():
    q_str = request.args.get("q", "").strip().lower()
    if not q_str:
        return jsonify({"cves": []}), 200
    cves = LiveCve.query.filter(
        LiveCve.keywords.ilike(f"%{q_str}%") |
        LiveCve.description.ilike(f"%{q_str}%") |
        LiveCve.cve_id.ilike(f"%{q_str}%")
    ).order_by(LiveCve.cvss_score.desc()).limit(20).all()
    return jsonify({"cves": [c.to_dict() for c in cves]}), 200
