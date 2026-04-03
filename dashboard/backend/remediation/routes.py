"""
AIPET Fix — Remediation Routes
Handles all API endpoints for the AIPET Fix module.

Endpoints:
    GET  /api/remediation/<finding_id>     — Get fix for a specific finding
    PATCH /api/findings/<finding_id>/status — Update fix status of a finding
    GET  /api/findings/<scan_id>/summary   — Get fix progress summary for a scan
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Finding, RemediationKB, Scan

remediation_bp = Blueprint("remediation", __name__)


def normalize_attack_type(attack_string):
    """
    Converts a raw attack string from a finding into a knowledge base key.

    The findings table stores attack names like:
        "Telnet Open", "Default Credentials", "MQTT No Auth"

    The remediation_kb stores keys like:
        "open_telnet", "default_credentials", "mqtt_no_auth"

    This function maps between the two formats so we can look up
    the correct fix even when the attack name doesn't exactly match.
    """
    attack_lower = attack_string.lower().strip()

    mapping = {
        "telnet":                   "open_telnet",
        "open_telnet":              "open_telnet",
        "default_credentials":      "default_credentials",
        "default credential":       "default_credentials",
        "default password":         "default_credentials",
        "mqtt":                     "unencrypted_mqtt",
        "unencrypted_mqtt":         "unencrypted_mqtt",
        "mqtt no auth":             "mqtt_no_auth",
        "mqtt_no_auth":             "mqtt_no_auth",
        "anonymous mqtt":           "mqtt_no_auth",
        "ftp":                      "open_ftp",
        "open_ftp":                 "open_ftp",
        "ssh root":                 "open_ssh_root",
        "open_ssh_root":            "open_ssh_root",
        "root login":               "open_ssh_root",
        "http":                     "http_no_https",
        "http_no_https":            "http_no_https",
        "no https":                 "http_no_https",
        "vnc":                      "open_vnc",
        "open_vnc":                 "open_vnc",
        "snmp":                     "open_snmp",
        "open_snmp":                "open_snmp",
        "firmware":                 "outdated_firmware",
        "outdated_firmware":        "outdated_firmware",
        "outdated firmware":        "outdated_firmware",
        "password policy":          "weak_password_policy",
        "weak_password_policy":     "weak_password_policy",
        "account lockout":          "no_account_lockout",
        "no_account_lockout":       "no_account_lockout",
        "brute force":              "no_account_lockout",
        "redis":                    "open_redis",
        "open_redis":               "open_redis",
        "coap":                     "coap_no_dtls",
        "coap_no_dtls":             "coap_no_dtls",
        "database port":            "open_database_port",
        "open_database_port":       "open_database_port",
        "ssl":                      "ssl_expired_certificate",
        "ssl_expired_certificate":  "ssl_expired_certificate",
        "expired certificate":      "ssl_expired_certificate",
        "unnecessary services":     "unnecessary_services",
        "unnecessary_services":     "unnecessary_services",
        "firewall":                 "no_firewall",
        "no_firewall":              "no_firewall",
        "api":                      "insecure_api",
        "insecure_api":             "insecure_api",
        "hardcoded":                "hardcoded_credentials",
        "hardcoded_credentials":    "hardcoded_credentials",
        "rsync":                    "open_rsync",
        "open_rsync":               "open_rsync",
        "cleartext":                "cleartext_storage",
        "cleartext_storage":        "cleartext_storage",
        "plaintext":                "cleartext_storage",
        "update":                   "no_update_mechanism",
        "no_update_mechanism":      "no_update_mechanism",
        "upnp":                     "open_upnp",
        "open_upnp":                "open_upnp",
        "nfs":                      "open_nfs",
        "open_nfs":                 "open_nfs",
        "debug":                    "debug_interface_exposed",
        "debug_interface_exposed":  "debug_interface_exposed",
        "logging":                  "no_logging",
        "no_logging":               "no_logging",
        "deserialization":          "insecure_deserialization",
        "insecure_deserialization": "insecure_deserialization",
        "memcached":                "open_memcached",
        "open_memcached":           "open_memcached",
        "privilege":                "privilege_escalation_risk",
        "privilege_escalation_risk":"privilege_escalation_risk",
    }

    # First try exact match
    if attack_lower in mapping:
        return mapping[attack_lower]

    # Then try partial match — checks if any key appears in the attack string
    for key, value in mapping.items():
        if key in attack_lower:
            return value

    # No match found — return None so caller can handle gracefully
    return None


@remediation_bp.route("/api/remediation/<int:finding_id>", methods=["GET"])
@jwt_required()
def get_remediation(finding_id):
    """
    Returns the remediation fix for a specific finding.

    The frontend calls this when the user clicks View Fix on a finding.
    We look up the finding, map its attack type to the KB, and return
    everything the Fix Panel needs to display.
    """
    current_user_id = get_jwt_identity()

    # Fetch the finding and verify it belongs to this user
    finding = Finding.query.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404

    # Verify the finding belongs to a scan owned by this user
    scan = Scan.query.filter_by(id=finding.scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Unauthorised"}), 403

    # Map attack type to KB key
    kb_key = normalize_attack_type(finding.attack)

    remediation = None
    if kb_key:
        remediation = RemediationKB.query.filter_by(attack_type=kb_key).first()

    # Build response
    response = {
        "finding": {
            "id":         finding.id,
            "attack":     finding.attack,
            "severity":   finding.severity,
            "module":     finding.module,
            "description":finding.description,
            "target":     finding.target,
            "fix_status": finding.fix_status,
            "fix_notes":  finding.fix_notes,
        },
        "remediation": None
    }

    if remediation:
        response["remediation"] = {
            "title":                 remediation.title,
            "explanation":           remediation.explanation,
            "fix_commands":          remediation.fix_commands,
            "time_estimate_minutes": remediation.time_estimate_minutes,
            "difficulty":            remediation.difficulty,
            "source":                remediation.source,
        }
    else:
        # No KB entry found — return a generic response
        response["remediation"] = {
            "title":                 f"Fix for {finding.attack}",
            "explanation":           "No specific remediation guide available for this finding. Please consult your security team or refer to the CVE database for guidance.",
            "fix_commands":          "# No automated fix commands available\n# Please consult your security team",
            "time_estimate_minutes": 60,
            "difficulty":            "Complex",
            "source":                "Manual review required",
        }

    return jsonify(response), 200


@remediation_bp.route("/api/findings/<int:finding_id>/status", methods=["PATCH"])
@jwt_required()
def update_fix_status(finding_id):
    """
    Updates the fix_status and optionally fix_notes of a finding.

    Called when the user marks a finding as Fixed, In Progress,
    or Accepted Risk in the Fix Panel.

    Valid statuses: open, in_progress, fixed, accepted_risk
    """
    current_user_id = get_jwt_identity()

    finding = Finding.query.get(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404

    scan = Scan.query.filter_by(id=finding.scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Unauthorised"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    valid_statuses = ["open", "in_progress", "fixed", "accepted_risk"]
    new_status = data.get("fix_status")

    if not new_status:
        return jsonify({"error": "fix_status is required"}), 400

    if new_status not in valid_statuses:
        return jsonify({
            "error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        }), 400

    finding.fix_status = new_status
    if "fix_notes" in data:
        finding.fix_notes = data["fix_notes"]

    db.session.commit()

    return jsonify({
        "message":    "Fix status updated successfully",
        "finding_id": finding_id,
        "fix_status": finding.fix_status,
        "fix_notes":  finding.fix_notes,
    }), 200


@remediation_bp.route("/api/scans/<int:scan_id>/fix-summary", methods=["GET"])
@jwt_required()
def get_fix_summary(scan_id):
    """
    Returns a fix progress summary for all findings in a scan.

    Used by the dashboard to show the risk reduction score and
    progress bar — how many findings are fixed vs open.
    """
    current_user_id = get_jwt_identity()

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = Finding.query.filter_by(scan_id=scan_id).all()

    total        = len(findings)
    fixed        = sum(1 for f in findings if f.fix_status == "fixed")
    in_progress  = sum(1 for f in findings if f.fix_status == "in_progress")
    accepted     = sum(1 for f in findings if f.fix_status == "accepted_risk")
    open_count   = sum(1 for f in findings if f.fix_status == "open")

    # Risk reduction score
    # Each fixed Critical = 20 points, High = 10, Medium = 5, Low = 2
    severity_weights = {"critical": 20, "high": 10, "medium": 5, "low": 2}

    total_risk   = 0
    reduced_risk = 0

    for f in findings:
        weight = severity_weights.get(f.severity.lower(), 5)
        total_risk += weight
        if f.fix_status in ["fixed", "accepted_risk"]:
            reduced_risk += weight

    risk_reduction_pct = round((reduced_risk / total_risk * 100), 1) if total_risk > 0 else 0

    return jsonify({
        "scan_id":            scan_id,
        "total_findings":     total,
        "fixed":              fixed,
        "in_progress":        in_progress,
        "accepted_risk":      accepted,
        "open":               open_count,
        "risk_reduction_pct": risk_reduction_pct,
    }), 200