"""
AIPET X — Threat Intel Routes

Endpoints:
  GET  /api/threatintel/feeds          — list all feeds + health
  GET  /api/threatintel/iocs           — paginated IOC list
  POST /api/threatintel/iocs           — add manual IOC
  DEL  /api/threatintel/iocs/<id>      — remove IOC
  POST /api/threatintel/lookup         — lookup single IP/domain
  GET  /api/threatintel/matches        — all threat matches history
  GET  /api/threatintel/stats          — dashboard metrics
  POST /api/threatintel/scan/<scan_id> — check scan IPs against all feeds
"""
import os
import json
import requests
from datetime import datetime, timezone, timedelta
from celery.result import AsyncResult
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Scan, Finding
from dashboard.backend.threatintel.models import IocFeed, IocEntry, ThreatMatch
from dashboard.backend.siem.models import SiemEvent
from dashboard.backend.validation import CHECK_HOST_TI_SCHEMA, validate_body

threatintel_bp = Blueprint("threatintel", __name__)


# ── Internal helpers ─────────────────────────────────────────

def _check_local(value):
    """
    Check a single value against the local IOC database.
    Returns the matching IocEntry or None.
    Fast — pure DB query, no external calls.
    """
    return IocEntry.query.filter_by(value=value, active=True).first()


def _check_abuseipdb(ip):
    """
    Check an IP against AbuseIPDB free tier API.
    Requires ABUSEIPDB_API_KEY in environment.
    Returns dict with threat data or None if key missing / not found.

    AbuseIPDB free tier: 1,000 lookups/day — sufficient for IoT scanning.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None  # Graceful fallback — no key, no call

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        if resp.status_code != 200:
            return None

        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        # Only flag if abuse confidence >= 25
        if score < 25:
            return None

        # Map score to AIPET severity
        if score >= 75:
            severity = "Critical"
        elif score >= 50:
            severity = "High"
        else:
            severity = "Medium"

        return {
            "confidence":  score,
            "severity":    severity,
            "threat_type": "malicious_ip",
            "details": json.dumps({
                "abuse_score":     score,
                "country":         data.get("countryCode"),
                "isp":             data.get("isp"),
                "total_reports":   data.get("totalReports"),
                "last_reported":   data.get("lastReportedAt"),
                "usage_type":      data.get("usageType"),
            })
        }
    except Exception:
        return None  # Network error — fail silently, never block scans


def _ingest_siem_threat(matched_value, severity, threat_type, source):
    """
    Push a threat match into the SIEM event feed automatically.
    This is the integration point between Threat Intel and SIEM.
    """
    try:
        mitre_map = {
            "malicious_ip": "T1071",
            "c2":           "T1071.001",
            "phishing":     "T1566",
            "malware":      "T1204",
            "scanner":      "T1046",
            "botnet":       "T1583",
        }
        event = SiemEvent(
            event_type  = "threat_intel",
            source      = f"AIPET Threat Intel ({source})",
            severity    = severity,
            title       = f"Threat Intel match: {matched_value}",
            description = f"Device IP matched {threat_type} indicator in {source} feed.",
            mitre_id    = mitre_map.get(threat_type, "T1071"),
        )
        db.session.add(event)
        # Note: caller must commit
    except Exception:
        pass  # Never let SIEM ingestion failure block the main response


# ── Feed endpoints ───────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/feeds", methods=["GET"])
@jwt_required()
def list_feeds():
    """List all registered threat intel feeds with health status."""
    feeds = IocFeed.query.order_by(IocFeed.created_at).all()
    return jsonify({"feeds": [f.to_dict() for f in feeds]})


# ── IOC endpoints ────────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/iocs", methods=["GET"])
@jwt_required()
def list_iocs():
    """Paginated list of all IOC entries with optional type filter."""
    ioc_type = request.args.get("type")
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))

    q = IocEntry.query.order_by(IocEntry.created_at.desc())
    if ioc_type:
        q = q.filter_by(ioc_type=ioc_type)

    total   = q.count()
    entries = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        "iocs":  [e.to_dict() for e in entries],
        "total": total, "page": page,
        "pages": (total + per_page - 1) // per_page,
    })


@threatintel_bp.route("/api/threatintel/iocs", methods=["POST"])
@jwt_required()
def add_ioc():
    """
    Manually add an IOC to the local feed.
    Use this to add IPs from your own threat hunting,
    incident response, or ISAC feeds.
    """
    data = request.get_json(silent=True) or {}
    if not data.get("value") or not data.get("ioc_type"):
        return jsonify({"error": "value and ioc_type required"}), 400

    # Find or create the local feed
    local_feed = IocFeed.query.filter_by(feed_type="local").first()
    if not local_feed:
        local_feed = IocFeed(
            name="Local IOC Database",
            feed_type="local",
            description="Manually curated indicators of compromise",
            enabled=True)
        db.session.add(local_feed)
        db.session.flush()

    # Prevent duplicates
    existing = IocEntry.query.filter_by(
        value=data["value"], feed_id=local_feed.id).first()
    if existing:
        return jsonify({"error": "IOC already exists", "ioc": existing.to_dict()}), 409

    entry = IocEntry(
        feed_id     = local_feed.id,
        ioc_type    = data["ioc_type"],
        value       = data["value"],
        threat_type = data.get("threat_type", "unknown"),
        confidence  = data.get("confidence", 90),
        severity    = data.get("severity", "High"),
        description = data.get("description"),
        source_ref  = data.get("source_ref"),
    )
    db.session.add(entry)
    local_feed.entry_count = IocEntry.query.filter_by(
        feed_id=local_feed.id).count() + 1
    db.session.commit()
    return jsonify({"success": True, "ioc": entry.to_dict()}), 201


@threatintel_bp.route("/api/threatintel/iocs/<int:ioc_id>", methods=["DELETE"])
@jwt_required()
def delete_ioc(ioc_id):
    """Remove an IOC from the local database."""
    entry = IocEntry.query.get_or_404(ioc_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True})


# ── Lookup endpoint ──────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/lookup", methods=["POST"])
@jwt_required()
def lookup():
    """
    Lookup a single IP or domain against all enabled feeds.
    Used by the UI lookup widget and by automated scan checking.

    Checks in order:
      1. Local IOC database (instant — no API call)
      2. AbuseIPDB (if key present and ioc_type is ip)
    """
    data  = request.get_json(silent=True) or {}
    value = data.get("value", "").strip()
    if not value:
        return jsonify({"error": "value required"}), 400

    results  = []
    matched  = False

    # Check 1 — local IOC database
    local_match = _check_local(value)
    if local_match:
        matched = True
        results.append({
            "source":      "Local IOC Database",
            "matched":     True,
            "confidence":  local_match.confidence,
            "severity":    local_match.severity,
            "threat_type": local_match.threat_type,
            "description": local_match.description,
        })

    # Check 2 — AbuseIPDB (IPs only)
    abuse_result = _check_abuseipdb(value)
    if abuse_result:
        matched = True
        results.append({
            "source":      "AbuseIPDB",
            "matched":     True,
            **abuse_result,
        })

    if not results:
        results.append({
            "source":  "All feeds",
            "matched": False,
            "message": "No threat intel matches found. IP appears clean.",
        })

    # Record match in threat_matches table if found
    if matched:
        best   = max(results, key=lambda r: r.get("confidence", 0))
        match  = ThreatMatch(
            matched_value = value,
            match_source  = best["source"],
            threat_type   = best.get("threat_type", "unknown"),
            confidence    = best.get("confidence", 75),
            severity      = best.get("severity", "High"),
            details       = json.dumps(results),
            user_id       = int(get_jwt_identity()),
        )
        db.session.add(match)
        _ingest_siem_threat(value, best["severity"],
                            best.get("threat_type", "unknown"), best["source"])
        db.session.commit()

    return jsonify({"value": value, "matched": matched, "results": results})


# ── Matches history ──────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/matches", methods=["GET"])
@jwt_required()
def list_matches():
    """All historical threat matches — newest first."""
    matches = ThreatMatch.query.order_by(
        ThreatMatch.created_at.desc()).limit(100).all()
    return jsonify({"matches": [m.to_dict() for m in matches]})


# ── Scan checker ─────────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/scan/<int:scan_id>", methods=["POST"])
@jwt_required()
def check_scan(scan_id):
    """
    Check all IPs discovered in a scan against threat intel feeds.
    Called automatically after every scan completes, or manually
    from the UI to recheck a historical scan.

    Returns a list of any matches found.
    """
    scan = Scan.query.get_or_404(scan_id)

    # Extract unique IPs from scan findings
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    ips = list({f.target for f in findings if f.target})
    if not ips:
        return jsonify({"message": "No IPs found in scan", "matches": []})

    matches_found = []
    for ip in ips:
        # Local check
        local_match = _check_local(ip)
        if local_match:
            match = ThreatMatch(
                ioc_entry_id  = local_match.id,
                scan_id       = scan_id,
                matched_value = ip,
                match_source  = "local",
                threat_type   = local_match.threat_type,
                confidence    = local_match.confidence,
                severity      = local_match.severity,
                user_id       = int(get_jwt_identity()),
            )
            db.session.add(match)
            _ingest_siem_threat(ip, local_match.severity,
                                local_match.threat_type, "Local IOC")
            matches_found.append(match.to_dict())

        # AbuseIPDB check
        abuse = _check_abuseipdb(ip)
        if abuse:
            match = ThreatMatch(
                scan_id       = scan_id,
                matched_value = ip,
                match_source  = "abuseipdb",
                threat_type   = abuse.get("threat_type", "malicious_ip"),
                confidence    = abuse["confidence"],
                severity      = abuse["severity"],
                details       = abuse.get("details"),
                user_id       = int(get_jwt_identity()),
            )
            db.session.add(match)
            _ingest_siem_threat(ip, abuse["severity"],
                                "malicious_ip", "AbuseIPDB")
            matches_found.append(match.to_dict())

    db.session.commit()
    return jsonify({
        "scan_id":    scan_id,
        "ips_checked": len(ips),
        "matches":    matches_found,
        "clean":      len(matches_found) == 0,
    })


# ── Stats ────────────────────────────────────────────────────

@threatintel_bp.route("/api/threatintel/stats", methods=["GET"])
@jwt_required()
def stats():
    """Dashboard metrics for the Threat Intel page header."""
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)

    total_iocs      = IocEntry.query.filter_by(active=True).count()
    active_feeds    = IocFeed.query.filter_by(enabled=True).count()
    matches_today   = ThreatMatch.query.filter(
        ThreatMatch.created_at >= today).count()
    critical_matches= ThreatMatch.query.filter(
        ThreatMatch.created_at >= today,
        ThreatMatch.severity == "Critical").count()
    total_matches   = ThreatMatch.query.count()
    abuseipdb_active= bool(os.environ.get("ABUSEIPDB_API_KEY"))

    otx_feed    = IocFeed.query.filter_by(feed_type="otx").first()
    otx_active  = bool(os.environ.get("OTX_API_KEY"))
    otx_last_sync = str(otx_feed.last_sync) if (otx_feed and otx_feed.last_sync) else None
    otx_ioc_count = otx_feed.entry_count if otx_feed else 0

    return jsonify({
        "total_iocs":       total_iocs,
        "active_feeds":     active_feeds,
        "matches_today":    matches_today,
        "critical_matches": critical_matches,
        "total_matches":    total_matches,
        "abuseipdb_active": abuseipdb_active,
        "otx_active":       otx_active,
        "otx_last_sync":    otx_last_sync,
        "otx_ioc_count":    otx_ioc_count,
    })


# ── OTX / Capability-4 endpoints ────────────────────────────

@threatintel_bp.route("/api/threatintel/sync_now", methods=["POST"])
@jwt_required()
def sync_now():
    """Trigger an OTX sync as a Celery task. Rate-limited 1/hour via app_cloud.py."""
    from dashboard.backend.tasks import sync_otx_threat_intel
    task = sync_otx_threat_intel.delay()
    return jsonify({"status": "queued", "task_id": task.id}), 202


@threatintel_bp.route("/api/threatintel/sync_status/<task_id>", methods=["GET"])
@jwt_required()
def sync_status(task_id):
    """Poll Celery task state for a sync started by sync_now."""
    result = AsyncResult(task_id)
    payload = {"task_id": task_id, "state": result.state}
    if result.state == "SUCCESS":
        payload["result"] = result.result
    elif result.state == "FAILURE":
        payload["error"] = str(result.result)
    return jsonify(payload)


@threatintel_bp.route("/api/threatintel/check_host", methods=["POST"])
@jwt_required()
@validate_body(CHECK_HOST_TI_SCHEMA)
def check_host():
    """On-demand cross-reference of a host IP against the local IOC database."""
    from dashboard.backend.threatintel.cross_reference import check_host_against_threat_intel
    user_id = int(get_jwt_identity())
    host_ip = (request.get_json(silent=True) or {}).get("host_ip", "").strip()
    result = check_host_against_threat_intel(user_id, host_ip)
    return jsonify(result)


@threatintel_bp.route("/api/threatintel/iocs/recent", methods=["GET"])
@jwt_required()
def recent_iocs():
    """Most recent N active IOC entries — useful for 'what's in the DB' panel."""
    limit = min(int(request.args.get("limit", 50)), 200)
    entries = (
        IocEntry.query
        .filter_by(active=True)
        .order_by(IocEntry.created_at.desc())
        .limit(limit)
        .all()
    )
    return jsonify({"iocs": [e.to_dict() for e in entries], "count": len(entries)})
