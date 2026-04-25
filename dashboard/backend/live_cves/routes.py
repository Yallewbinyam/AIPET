# ============================================================
# AIPET X — Live CVE Feed API
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from celery.result import AsyncResult
from dashboard.backend.live_cves.models import LiveCve, CveSyncLog, KevCatalogEntry
from dashboard.backend.validation import KEV_CHECK_HOST_SCHEMA, validate_body
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


# ── Capability 5: CISA KEV endpoints ────────────────────────────────────────

@live_cves_bp.route("/api/live-cves/kev/sync_now", methods=["POST"])
@jwt_required()
def kev_sync_now():
    """Trigger a CISA KEV catalog sync as a Celery task. Rate-limited 1/hour via app_cloud.py."""
    from dashboard.backend.tasks import sync_cisa_kev
    task = sync_cisa_kev.delay()
    return jsonify({"status": "queued", "task_id": task.id}), 202


@live_cves_bp.route("/api/live-cves/kev/sync_status/<task_id>", methods=["GET"])
@jwt_required()
def kev_sync_status(task_id):
    """Poll Celery task state for a KEV sync started by kev_sync_now."""
    result = AsyncResult(task_id)
    payload = {"task_id": task_id, "state": result.state}
    if result.state == "SUCCESS":
        payload["result"] = result.result
    elif result.state == "FAILURE":
        payload["error"] = str(result.result)
    return jsonify(payload)


@live_cves_bp.route("/api/live-cves/kev/check_host", methods=["POST"])
@jwt_required()
@validate_body(KEV_CHECK_HOST_SCHEMA)
def kev_check_host():
    """Cross-reference a host's scan CVEs against the local kev_catalog."""
    from dashboard.backend.live_cves.kev_cross_reference import check_host_cves_against_kev
    user_id = int(get_jwt_identity())
    host_ip = (request.get_json(silent=True) or {}).get("host_ip", "").strip()
    result = check_host_cves_against_kev(user_id, host_ip)
    return jsonify(result)


@live_cves_bp.route("/api/live-cves/kev/catalog", methods=["GET"])
@jwt_required()
def kev_catalog():
    """Paginated KEV catalog browser with optional ransomware_only filter."""
    limit           = min(int(request.args.get("limit", 50)), 200)
    offset          = int(request.args.get("offset", 0))
    ransomware_only = request.args.get("ransomware_only", "false").lower() == "true"

    q = KevCatalogEntry.query
    if ransomware_only:
        q = q.filter_by(known_ransomware_use="Known")
    q = q.order_by(KevCatalogEntry.date_added.desc())

    total   = q.count()
    entries = q.offset(offset).limit(limit).all()
    return jsonify({
        "entries": [e.to_dict() for e in entries],
        "total":   total,
        "offset":  offset,
        "limit":   limit,
    })


@live_cves_bp.route("/api/live-cves/kev/stats", methods=["GET"])
@jwt_required()
def kev_stats():
    """KEV catalog statistics."""
    from sqlalchemy import func
    from dashboard.backend.models import db

    total        = KevCatalogEntry.query.count()
    ransomware   = KevCatalogEntry.query.filter_by(known_ransomware_use="Known").count()
    oldest       = db.session.query(func.min(KevCatalogEntry.date_added)).scalar()
    newest       = db.session.query(func.max(KevCatalogEntry.date_added)).scalar()
    last_synced  = db.session.query(func.max(KevCatalogEntry.last_synced_at)).scalar()

    return jsonify({
        "total":                 total,
        "ransomware_associated": ransomware,
        "oldest_entry":          oldest.isoformat()     if oldest     else None,
        "newest_entry":          newest.isoformat()     if newest     else None,
        "last_synced_at":        last_synced.isoformat() if last_synced else None,
    })
