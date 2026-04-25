"""
AIPET X — Behavioral AI Engine Routes

Endpoints:
  GET  /api/behavioral/baselines          — list all baselines
  GET  /api/behavioral/baselines/<id>     — baseline detail + patterns
  POST /api/behavioral/analyse            — run behavioral analysis
  GET  /api/behavioral/anomalies          — list anomalies
  PUT  /api/behavioral/anomalies/<id>     — update anomaly status
  GET  /api/behavioral/stats              — engine metrics
  GET  /api/behavioral/timeline           — anomaly timeline (24h)
"""
import json
import math
import random
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.behavioral.models import BaBaseline, BaAnomaly, BaPattern
from dashboard.backend.validation import BUILD_DEVICE_BASELINE_SCHEMA, validate_body

behavioral_bp = Blueprint("behavioral", __name__)

# Anomaly type definitions with MITRE mappings
ANOMALY_TYPES = {
    "traffic_spike": {
        "label":    "Traffic Volume Spike",
        "mitre":    "T1071",
        "icon":     "📈",
        "description": "Significant increase in network traffic volume above baseline",
    },
    "new_connection": {
        "label":    "New Destination Connection",
        "mitre":    "T1071",
        "icon":     "🔗",
        "description": "Connection to IP/domain never seen in baseline period",
    },
    "unusual_hours": {
        "label":    "Activity Outside Normal Hours",
        "mitre":    "T1078",
        "icon":     "🌙",
        "description": "Entity active at hours outside its established pattern",
    },
    "geo_anomaly": {
        "label":    "Geographic Anomaly",
        "mitre":    "T1078",
        "icon":     "🌍",
        "description": "Authentication or access from unexpected geographic location",
    },
    "protocol_change": {
        "label":    "Protocol Behaviour Change",
        "mitre":    "T1040",
        "icon":     "🔄",
        "description": "Entity using protocols not observed in baseline",
    },
    "data_exfil": {
        "label":    "Potential Data Exfiltration",
        "mitre":    "T1041",
        "icon":     "📤",
        "description": "Unusually large outbound data transfer detected",
    },
    "lateral_movement": {
        "label":    "Lateral Movement Pattern",
        "mitre":    "T1021",
        "icon":     "↔️",
        "description": "Entity accessing systems it has not communicated with before",
    },
    "privilege_escalation": {
        "label":    "Privilege Escalation Attempt",
        "mitre":    "T1548",
        "icon":     "⬆️",
        "description": "Entity attempting actions beyond its normal privilege level",
    },
    "beacon": {
        "label":    "C2 Beaconing Pattern",
        "mitre":    "T1071",
        "icon":     "📡",
        "description": "Regular periodic outbound connections suggesting C2 communication",
    },
    "dormant_activation": {
        "label":    "Dormant Account Activated",
        "mitre":    "T1078",
        "icon":     "👻",
        "description": "Previously inactive account or device showing sudden activity",
    },
}


def _calculate_deviation(observed_val, baseline_mean, baseline_std):
    """Calculate sigma deviation from baseline."""
    if baseline_std == 0:
        return 0
    return abs(observed_val - baseline_mean) / baseline_std


def _severity_from_deviation(deviation):
    """Map sigma deviation to severity level."""
    if deviation >= 5:   return "Critical"
    if deviation >= 3.5: return "High"
    if deviation >= 2.5: return "Medium"
    return "Low"


@behavioral_bp.route("/api/behavioral/baselines", methods=["GET"])
@jwt_required()
def list_baselines():
    entity_type = request.args.get("entity_type")
    q = BaBaseline.query
    if entity_type:
        q = q.filter_by(entity_type=entity_type)
    baselines = q.order_by(BaBaseline.risk_score.desc()).all()
    return jsonify({"baselines": [b.to_dict() for b in baselines]})


@behavioral_bp.route("/api/behavioral/baselines/<int:bid>", methods=["GET"])
@jwt_required()
def baseline_detail(bid):
    baseline = BaBaseline.query.get_or_404(bid)
    anomalies = BaAnomaly.query.filter_by(
        baseline_id=bid).order_by(
        BaAnomaly.created_at.desc()).limit(20).all()
    patterns  = BaPattern.query.filter_by(
        baseline_id=bid).all()
    data = baseline.to_dict()
    data["anomalies"] = [a.to_dict() for a in anomalies]
    data["patterns"]  = [p.to_dict() for p in patterns]
    return jsonify(data)


@behavioral_bp.route("/api/behavioral/analyse", methods=["POST"])
@jwt_required()
def run_analysis():
    """
    Run behavioral analysis across all monitored entities.
    Compares current behaviour against established baselines.
    Generates anomaly alerts for significant deviations.
    """
    from dashboard.backend.models import Finding

    baselines = BaBaseline.query.all()
    new_anomalies = []

    for baseline in baselines:
        bl_data = json.loads(baseline.baseline) if baseline.baseline else {}

        # Simulate current observation vs baseline
        random.seed(hash(baseline.entity_id + str(datetime.now(timezone.utc).hour)))

        # Check each behavioral dimension
        checks = [
            {
                "type":     "traffic_spike",
                "observed": bl_data.get("avg_bytes_per_hour", 1000) * random.uniform(0.5, 8.0),
                "baseline": bl_data.get("avg_bytes_per_hour", 1000),
                "std":      bl_data.get("avg_bytes_per_hour", 1000) * 0.3,
                "unit":     "bytes/hour",
            },
            {
                "type":     "unusual_hours",
                "observed": datetime.now(timezone.utc).hour,
                "baseline": bl_data.get("active_hours_mean", 12),
                "std":      bl_data.get("active_hours_std", 4),
                "unit":     "hour",
            },
        ]

        for check in checks:
            deviation = _calculate_deviation(
                check["observed"], check["baseline"], check["std"])

            # Only flag if deviation is significant (>2.5 sigma)
            if deviation >= 2.5:
                atype    = ANOMALY_TYPES.get(check["type"], {})
                severity = _severity_from_deviation(deviation)

                # Check if we already have a recent anomaly of this type
                existing = BaAnomaly.query.filter_by(
                    baseline_id  = baseline.id,
                    anomaly_type = check["type"],
                    status       = "new"
                ).first()

                if not existing:
                    anomaly = BaAnomaly(
                        baseline_id  = baseline.id,
                        entity_name  = baseline.entity_name,
                        anomaly_type = check["type"],
                        severity     = severity,
                        title        = f"{atype.get('label','Anomaly')} — {baseline.entity_name}",
                        description  = f"{atype.get('description','')} "
                                       f"Observed: {check['observed']:.1f} {check['unit']} "
                                       f"({deviation:.1f}σ above baseline)",
                        deviation    = round(deviation, 2),
                        observed     = json.dumps({"value": round(check["observed"],2),
                                                   "unit": check["unit"]}),
                        expected     = json.dumps({"mean": check["baseline"],
                                                   "std":  round(check["std"],2),
                                                   "unit": check["unit"]}),
                        mitre_id     = atype.get("mitre"),
                        status       = "new",
                    )
                    db.session.add(anomaly)
                    new_anomalies.append(anomaly)
                    baseline.anomaly_count += 1
                    baseline.risk_score = min(100,
                        baseline.risk_score + int(deviation * 5))

        baseline.last_updated = datetime.now(timezone.utc)

    db.session.commit()
    return jsonify({
        "success":        True,
        "baselines_checked": len(baselines),
        "new_anomalies":  len(new_anomalies),
        "anomalies":      [a.to_dict() for a in new_anomalies],
    })


@behavioral_bp.route("/api/behavioral/anomalies", methods=["GET"])
@jwt_required()
def list_anomalies():
    status   = request.args.get("status")
    severity = request.args.get("severity")
    days     = int(request.args.get("days", 7))
    since    = datetime.now(timezone.utc) - timedelta(days=days)

    q = BaAnomaly.query.filter(BaAnomaly.created_at >= since)
    if status:   q = q.filter_by(status=status)
    if severity: q = q.filter_by(severity=severity)
    anomalies = q.order_by(BaAnomaly.created_at.desc()).all()
    return jsonify({"anomalies": [a.to_dict() for a in anomalies]})


@behavioral_bp.route("/api/behavioral/anomalies/<int:aid>", methods=["PUT"])
@jwt_required()
def update_anomaly(aid):
    anomaly = BaAnomaly.query.get_or_404(aid)
    data    = request.get_json(silent=True) or {}
    if "status" in data:
        anomaly.status = data["status"]
        if data["status"] == "resolved":
            anomaly.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "anomaly": anomaly.to_dict()})


@behavioral_bp.route("/api/behavioral/stats", methods=["GET"])
@jwt_required()
def behavioral_stats():
    baselines  = BaBaseline.query.all()
    anomalies  = BaAnomaly.query.all()
    new_count  = sum(1 for a in anomalies if a.status == "new")
    crit_count = sum(1 for a in anomalies if a.severity == "Critical")
    high_risk  = sum(1 for b in baselines if b.risk_score >= 70)
    avg_conf   = round(sum(b.confidence for b in baselines) /
                       max(len(baselines), 1), 1)

    by_type = {}
    for a in anomalies:
        by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1

    return jsonify({
        "total_baselines":  len(baselines),
        "total_anomalies":  len(anomalies),
        "new_anomalies":    new_count,
        "critical":         crit_count,
        "high_risk_entities": high_risk,
        "avg_confidence":   avg_conf,
        "by_type":          by_type,
    })


@behavioral_bp.route("/api/behavioral/timeline", methods=["GET"])
@jwt_required()
def anomaly_timeline():
    """Anomaly counts per hour for the last 24 hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    anomalies = BaAnomaly.query.filter(
        BaAnomaly.created_at >= since).all()

    by_hour = {}
    for a in anomalies:
        h = a.created_at.strftime("%H:00")
        by_hour[h] = by_hour.get(h, 0) + 1

    return jsonify({"timeline": by_hour})


# ── Per-device baseline endpoints (Capability 2) ─────────────────────────────

@behavioral_bp.route("/api/behavioral/device/baseline/build", methods=["POST"])
@jwt_required()
@validate_body(BUILD_DEVICE_BASELINE_SCHEMA)
def build_device_baseline_endpoint():
    """Build a per-device baseline from real scan history for one host."""
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline
    user_id = int(get_jwt_identity())
    host_ip = request.get_json(silent=True).get("host_ip", "").strip()

    result = upsert_device_baseline(user_id, host_ip)
    if result is None:
        return jsonify({
            "status":  "insufficient_data",
            "host_ip": host_ip,
            "message": "Fewer than 5 completed scans contain this host — run more scans first.",
        }), 400

    return jsonify({"status": "ok", "host_ip": host_ip, "baseline": result}), 200


@behavioral_bp.route("/api/behavioral/device/<host_ip>/baseline", methods=["GET"])
@jwt_required()
def get_device_baseline(host_ip):
    """Return the stored per-device baseline for host_ip."""
    baseline = BaBaseline.query.filter_by(
        entity_id   = host_ip,
        entity_type = "device",
    ).order_by(BaBaseline.last_updated.desc()).first()

    if baseline is None:
        return jsonify({"error": "no baseline for this host"}), 404

    return jsonify({"baseline": baseline.to_dict()}), 200


@behavioral_bp.route("/api/behavioral/device/baselines/build_all", methods=["POST"])
@jwt_required()
def build_all_device_baselines():
    """
    Build baselines for every distinct host across this user's completed scans.
    Rate-limited to 5 per hour (applied via app_cloud.py view_functions pattern).
    """
    import json as _json
    from dashboard.backend.behavioral.device_baseline_builder import upsert_device_baseline
    from dashboard.backend.real_scanner.routes import RealScanResult

    user_id = int(get_jwt_identity())

    scans = RealScanResult.query.filter_by(
        user_id = user_id,
        status  = "complete",
    ).all()

    # Collect distinct host IPs across all scan results
    host_ips: set[str] = set()
    for scan in scans:
        try:
            hosts = _json.loads(scan.results_json or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        for host in hosts:
            ip = host.get("ip")
            if ip:
                host_ips.add(ip)

    built, skipped, errors = [], [], []

    for ip in sorted(host_ips):
        try:
            result = upsert_device_baseline(user_id, ip)
            if result is None:
                skipped.append(ip)
            else:
                built.append({
                    "host_ip":          ip,
                    "observations":     result["observations"],
                    "confidence_level": result["confidence_level"],
                })
        except Exception as e:
            errors.append({"host_ip": ip, "error": str(e)})

    return jsonify({
        "built":                len(built),
        "skipped_cold_start":   len(skipped),
        "errors":               len(errors),
        "total_hosts":          len(host_ips),
        "baselines":            built,
        "cold_start_hosts":     skipped,
    }), 200


@behavioral_bp.route("/api/behavioral/device/baselines/list", methods=["GET"])
@jwt_required()
def list_device_baselines():
    """List all per-device baselines with ml_anomaly_v1 vocabulary."""
    rows = BaBaseline.query.filter_by(entity_type="device").order_by(
        BaBaseline.last_updated.desc()
    ).all()

    result = []
    for row in rows:
        d = row.to_dict()
        bl = d.get("baseline", {})
        if isinstance(bl, dict) and bl.get("feature_vocabulary") == "ml_anomaly_v1":
            result.append(d)

    return jsonify({"device_baselines": result, "count": len(result)}), 200
