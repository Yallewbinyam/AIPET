from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone

from ..models import db, User, Scan, Finding, ComplianceResult

compliance_bp = Blueprint('compliance', __name__, url_prefix='/api/compliance')

# =============================================================
# Framework control mappings
# =============================================================

NIS2_CONTROLS = [
    {"id": "NIS2-1",  "article": "Article 21a", "title": "Risk analysis",                "severity": ["critical", "high", "medium", "low"]},
    {"id": "NIS2-2",  "article": "Article 21b", "title": "Incident handling",             "severity": ["critical", "high"]},
    {"id": "NIS2-3",  "article": "Article 21c", "title": "Business continuity",           "severity": ["critical", "high"]},
    {"id": "NIS2-4",  "article": "Article 21d", "title": "Supply chain security",         "severity": ["high", "medium"]},
    {"id": "NIS2-5",  "article": "Article 21e", "title": "Network security",              "severity": ["critical", "high", "medium"]},
    {"id": "NIS2-6",  "article": "Article 21f", "title": "Access control",                "severity": ["critical", "high"]},
    {"id": "NIS2-7",  "article": "Article 21g", "title": "Cryptography",                  "severity": ["high", "medium"]},
    {"id": "NIS2-8",  "article": "Article 21h", "title": "Human resources security",      "severity": ["medium", "low"]},
    {"id": "NIS2-9",  "article": "Article 21i", "title": "Authentication",                "severity": ["critical", "high"]},
    {"id": "NIS2-10", "article": "Article 21j", "title": "Vulnerability disclosure",      "severity": ["critical", "high", "medium"]},
]

NIST_CONTROLS = [
    {"id": "NIST-GV1", "function": "GOVERN",   "title": "Organisational context",         "severity": ["medium", "low"]},
    {"id": "NIST-ID1", "function": "IDENTIFY",  "title": "Asset management",               "severity": ["critical", "high", "medium", "low"]},
    {"id": "NIST-ID2", "function": "IDENTIFY",  "title": "Risk assessment",                "severity": ["critical", "high", "medium"]},
    {"id": "NIST-PR1", "function": "PROTECT",   "title": "Identity management",            "severity": ["critical", "high"]},
    {"id": "NIST-PR2", "function": "PROTECT",   "title": "Awareness and training",         "severity": ["medium", "low"]},
    {"id": "NIST-PR3", "function": "PROTECT",   "title": "Data security",                  "severity": ["critical", "high"]},
    {"id": "NIST-PR4", "function": "PROTECT",   "title": "Platform security",              "severity": ["critical", "high", "medium"]},
    {"id": "NIST-DE1", "function": "DETECT",    "title": "Continuous monitoring",          "severity": ["critical", "high", "medium"]},
    {"id": "NIST-RS1", "function": "RESPOND",   "title": "Incident management",            "severity": ["critical", "high"]},
    {"id": "NIST-RC1", "function": "RECOVER",   "title": "Incident recovery",              "severity": ["critical", "high"]},
]

ISO_CONTROLS = [
    {"id": "ISO-5.1",  "clause": "5.1",  "title": "Information security policies",        "severity": ["medium", "low"]},
    {"id": "ISO-5.15", "clause": "5.15", "title": "Access control",                       "severity": ["critical", "high"]},
    {"id": "ISO-5.23", "clause": "5.23", "title": "Cloud services security",              "severity": ["high", "medium"]},
    {"id": "ISO-6.8",  "clause": "6.8",  "title": "Information security events",          "severity": ["critical", "high"]},
    {"id": "ISO-8.7",  "clause": "8.7",  "title": "Protection against malware",           "severity": ["critical", "high"]},
    {"id": "ISO-8.8",  "clause": "8.8",  "title": "Management of vulnerabilities",        "severity": ["critical", "high", "medium"]},
    {"id": "ISO-8.12", "clause": "8.12", "title": "Data leakage prevention",              "severity": ["high", "medium"]},
    {"id": "ISO-8.20", "clause": "8.20", "title": "Network security",                     "severity": ["critical", "high", "medium"]},
    {"id": "ISO-8.22", "clause": "8.22", "title": "Web filtering",                        "severity": ["medium", "low"]},
    {"id": "ISO-8.29", "clause": "8.29", "title": "Secure coding",                        "severity": ["high", "medium"]},
]

FRAMEWORKS = {
    "nis2":    {"name": "NIS2",         "controls": NIS2_CONTROLS},
    "nist":    {"name": "NIST CSF 2.0", "controls": NIST_CONTROLS},
    "iso27001":{"name": "ISO 27001",    "controls": ISO_CONTROLS},
}

# =============================================================
# Helper — map findings to controls
# =============================================================

def map_findings_to_controls(findings, controls):
    finding_severities = [f.severity.lower() for f in findings]
    has_critical = "critical" in finding_severities
    has_high     = "high"     in finding_severities
    has_medium   = "medium"   in finding_severities

    result = []
    passed = 0

    for control in controls:
        affected = any(s in finding_severities for s in control["severity"])
        status   = "fail" if affected else "pass"
        if status == "pass":
            passed += 1

        result.append({
            **control,
            "status":  status,
            "impact":  "high" if has_critical and "critical" in control["severity"]
                       else "medium" if has_high and "high" in control["severity"]
                       else "low",
        })

    return result, passed


# =============================================================
# Routes
# =============================================================

@compliance_bp.route('/generate', methods=['POST'])
@jwt_required()
def generate_report():
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.plan == 'free':
        return jsonify({'error': 'Compliance reports require Professional or Enterprise plan'}), 403

    data      = request.get_json()
    scan_id   = data.get('scan_id')
    framework = data.get('framework', 'nis2').lower()

    if framework not in FRAMEWORKS:
        return jsonify({'error': 'Invalid framework'}), 400

    scan = Scan.query.filter_by(id=scan_id, user_id=int(user_id)).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    findings = Finding.query.filter_by(scan_id=scan_id).all()
    controls, passed = map_findings_to_controls(findings, FRAMEWORKS[framework]['controls'])
    total  = len(controls)
    score  = round((passed / total) * 100) if total > 0 else 0

    result = ComplianceResult(
        user_id   = int(user_id),
        scan_id   = scan_id,
        framework = framework,
        score     = score,
        total     = total,
        controls  = controls,
    )
    db.session.add(result)
    db.session.commit()

    return jsonify({
        'id':        result.id,
        'framework': FRAMEWORKS[framework]['name'],
        'score':     score,
        'total':     total,
        'passed':    passed,
        'failed':    total - passed,
        'controls':  controls,
        'scan_id':   scan_id,
        'created_at': str(result.created_at),
    }), 200


@compliance_bp.route('/results/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_results(scan_id):
    user_id = get_jwt_identity()
    results = ComplianceResult.query.filter_by(
        scan_id=scan_id, user_id=int(user_id)
    ).order_by(ComplianceResult.created_at.desc()).all()

    return jsonify([r.to_dict() for r in results]), 200


@compliance_bp.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    results = ComplianceResult.query.filter_by(
        user_id=int(user_id)
    ).order_by(ComplianceResult.created_at.desc()).limit(20).all()

    return jsonify([r.to_dict() for r in results]), 200
