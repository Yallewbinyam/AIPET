# ============================================================
# AIPET X — Module #37: Autonomous Compliance Fabric
# NIS2 | ISO 27001 | NIST CSF 2.0 | SOC2 | GDPR | PCI-DSS
# Phase 5C | v6.2.0
# ============================================================

import re, json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

compliance_fabric_bp = Blueprint("compliance_fabric", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class ComplianceFabricReport(db.Model):
    __tablename__ = "compliance_fabric_reports"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    framework     = Column(String(64))
    score         = Column(Float, default=0.0)
    status        = Column(String(32), default="complete")
    total_controls= Column(Integer, default=0)
    passed        = Column(Integer, default=0)
    failed        = Column(Integer, default=0)
    partial       = Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    controls      = relationship("ComplianceFabricControl", backref="report", lazy=True, cascade="all, delete-orphan")

class ComplianceFabricControl(db.Model):
    __tablename__ = "compliance_fabric_controls"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id     = Column(String(64), ForeignKey("compliance_fabric_reports.id"), nullable=False)
    control_id    = Column(String(32))
    title         = Column(String(256))
    status        = Column(String(16))   # PASS | FAIL | PARTIAL
    severity      = Column(String(16))   # CRITICAL | HIGH | MEDIUM | LOW
    description   = Column(Text, nullable=True)
    remediation   = Column(Text, nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# COMPLIANCE FRAMEWORKS
# ============================================================

FRAMEWORKS = {
    "NIS2": {
        "name": "NIS2 Directive",
        "description": "EU Network and Information Security Directive 2022/2555",
        "controls": [
            {"id":"NIS2-1","title":"Risk Management Policy","keywords":["risk","policy","management","assessment"],"severity":"CRITICAL","remediation":"Establish a formal risk management policy with regular reviews."},
            {"id":"NIS2-2","title":"Incident Handling Procedures","keywords":["incident","response","handling","procedure","siem"],"severity":"CRITICAL","remediation":"Define and document incident response procedures with escalation paths."},
            {"id":"NIS2-3","title":"Business Continuity & Disaster Recovery","keywords":["backup","recovery","continuity","disaster","resilience","rto","rpo"],"severity":"HIGH","remediation":"Implement and test business continuity and DR plans annually."},
            {"id":"NIS2-4","title":"Supply Chain Security","keywords":["supply chain","vendor","third party","supplier","sbom"],"severity":"HIGH","remediation":"Assess and monitor all third-party suppliers and maintain an SBOM."},
            {"id":"NIS2-5","title":"Network Security Controls","keywords":["firewall","network","segmentation","vlan","zero trust","ids","ips"],"severity":"HIGH","remediation":"Deploy network segmentation, firewalls, and intrusion detection systems."},
            {"id":"NIS2-6","title":"Access Control & MFA","keywords":["mfa","multi-factor","access control","iam","rbac","authentication"],"severity":"CRITICAL","remediation":"Enforce MFA for all privileged accounts and implement RBAC."},
            {"id":"NIS2-7","title":"Encryption of Data","keywords":["encrypt","tls","ssl","aes","at rest","in transit"],"severity":"HIGH","remediation":"Encrypt all sensitive data at rest and in transit using AES-256 and TLS 1.3."},
            {"id":"NIS2-8","title":"Vulnerability Management","keywords":["vulnerability","patch","scan","cve","pentest","remediat"],"severity":"HIGH","remediation":"Implement a vulnerability management programme with monthly scanning."},
            {"id":"NIS2-9","title":"Security Awareness Training","keywords":["training","awareness","phishing","education","user"],"severity":"MEDIUM","remediation":"Conduct mandatory security awareness training for all staff annually."},
            {"id":"NIS2-10","title":"Logging & Monitoring","keywords":["log","monitor","audit","siem","alert","detection"],"severity":"HIGH","remediation":"Enable centralised logging and 24/7 monitoring with alerting."},
        ]
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "International Standard for Information Security Management Systems",
        "controls": [
            {"id":"ISO-A5","title":"Information Security Policies","keywords":["policy","information security","management","governance"],"severity":"CRITICAL","remediation":"Document and approve an information security policy signed by leadership."},
            {"id":"ISO-A6","title":"Organisation of Information Security","keywords":["role","responsibility","segregation","remote","mobile"],"severity":"HIGH","remediation":"Define security roles and responsibilities across the organisation."},
            {"id":"ISO-A7","title":"Human Resource Security","keywords":["hr","background","onboarding","offboarding","training","nda"],"severity":"MEDIUM","remediation":"Implement background checks and security training for all staff."},
            {"id":"ISO-A8","title":"Asset Management","keywords":["asset","inventory","classification","owner","register"],"severity":"HIGH","remediation":"Maintain a complete asset inventory with classification and ownership."},
            {"id":"ISO-A9","title":"Access Control","keywords":["access","password","privilege","mfa","rbac","iam","least privilege"],"severity":"CRITICAL","remediation":"Enforce least-privilege access and MFA across all systems."},
            {"id":"ISO-A10","title":"Cryptography","keywords":["encrypt","crypto","key management","tls","aes","certificate"],"severity":"HIGH","remediation":"Implement a cryptography policy covering key management and algorithm standards."},
            {"id":"ISO-A12","title":"Operations Security","keywords":["patch","change management","malware","backup","capacity","monitor"],"severity":"HIGH","remediation":"Establish operational procedures for patching, backups and change management."},
            {"id":"ISO-A13","title":"Communications Security","keywords":["network","firewall","segmentation","transfer","nda","agreement"],"severity":"HIGH","remediation":"Secure all network communications and enforce data transfer agreements."},
            {"id":"ISO-A16","title":"Information Security Incident Management","keywords":["incident","response","report","siem","forensic","breach"],"severity":"CRITICAL","remediation":"Establish an incident management process with clear reporting and escalation."},
            {"id":"ISO-A17","title":"Business Continuity Management","keywords":["continuity","disaster","backup","recovery","rto","rpo","test"],"severity":"HIGH","remediation":"Test business continuity plans at least annually."},
        ]
    },
    "NIST_CSF": {
        "name": "NIST CSF 2.0",
        "description": "NIST Cybersecurity Framework Version 2.0",
        "controls": [
            {"id":"CSF-GV","title":"Govern — Cybersecurity Risk Strategy","keywords":["governance","strategy","policy","risk","leadership","board"],"severity":"CRITICAL","remediation":"Establish cybersecurity governance with board-level oversight and risk strategy."},
            {"id":"CSF-ID","title":"Identify — Asset & Risk Management","keywords":["asset","inventory","risk","identify","classify","business environment"],"severity":"HIGH","remediation":"Maintain asset inventory and perform regular risk assessments."},
            {"id":"CSF-PR1","title":"Protect — Access Control","keywords":["access","mfa","identity","rbac","privilege","zero trust"],"severity":"CRITICAL","remediation":"Enforce identity-first access controls with MFA and least privilege."},
            {"id":"CSF-PR2","title":"Protect — Data Security","keywords":["encrypt","data","protection","dlp","backup","classification"],"severity":"HIGH","remediation":"Classify and encrypt sensitive data. Implement DLP controls."},
            {"id":"CSF-PR3","title":"Protect — Awareness & Training","keywords":["training","awareness","phishing","education"],"severity":"MEDIUM","remediation":"Deliver role-based security awareness training annually."},
            {"id":"CSF-DE1","title":"Detect — Anomaly Detection","keywords":["detect","anomaly","siem","monitor","ids","alert","log"],"severity":"HIGH","remediation":"Deploy SIEM with anomaly detection and automated alerting."},
            {"id":"CSF-DE2","title":"Detect — Continuous Monitoring","keywords":["monitor","continuous","scan","vulnerability","endpoint","edr"],"severity":"HIGH","remediation":"Implement continuous monitoring across endpoints, network, and cloud."},
            {"id":"CSF-RS","title":"Respond — Incident Response","keywords":["incident","response","plan","contain","forensic","recover"],"severity":"CRITICAL","remediation":"Maintain and exercise an incident response plan quarterly."},
            {"id":"CSF-RC","title":"Recover — Recovery Planning","keywords":["recover","restore","backup","rto","rpo","continuity","resilience"],"severity":"HIGH","remediation":"Define and test recovery procedures with defined RTO and RPO targets."},
        ]
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "AICPA Trust Services Criteria for Security, Availability, Confidentiality",
        "controls": [
            {"id":"SOC2-CC1","title":"Control Environment — Security Policies","keywords":["policy","governance","security","management","board"],"severity":"CRITICAL","remediation":"Document security policies reviewed and approved by senior management."},
            {"id":"SOC2-CC2","title":"Communication & Information","keywords":["communication","log","audit","report","inform","notify"],"severity":"MEDIUM","remediation":"Establish clear communication channels for security information."},
            {"id":"SOC2-CC3","title":"Risk Assessment","keywords":["risk","assessment","threat","vulnerability","analyse"],"severity":"HIGH","remediation":"Perform formal risk assessments at least annually."},
            {"id":"SOC2-CC6","title":"Logical & Physical Access Controls","keywords":["access","mfa","rbac","physical","badge","iam","privilege"],"severity":"CRITICAL","remediation":"Enforce MFA, RBAC and physical access controls for all systems."},
            {"id":"SOC2-CC7","title":"System Operations & Monitoring","keywords":["monitor","siem","alert","log","incident","detect","patch"],"severity":"HIGH","remediation":"Monitor systems 24/7 with automated alerting and incident response."},
            {"id":"SOC2-CC8","title":"Change Management","keywords":["change","deploy","cicd","release","test","approval","pipeline"],"severity":"HIGH","remediation":"Implement a formal change management process with testing and approval gates."},
            {"id":"SOC2-A1","title":"Availability — Performance Monitoring","keywords":["availability","uptime","sla","performance","capacity","redundancy"],"severity":"HIGH","remediation":"Monitor system availability and maintain SLA commitments with redundancy."},
            {"id":"SOC2-C1","title":"Confidentiality — Data Protection","keywords":["encrypt","confidential","classify","dlp","data protection","privacy"],"severity":"CRITICAL","remediation":"Classify and protect confidential data with encryption and DLP controls."},
        ]
    },
    "GDPR": {
        "name": "GDPR",
        "description": "EU General Data Protection Regulation 2016/679",
        "controls": [
            {"id":"GDPR-A5","title":"Lawful Basis for Processing","keywords":["consent","lawful","basis","purpose","legal","processing"],"severity":"CRITICAL","remediation":"Document lawful basis for all personal data processing activities."},
            {"id":"GDPR-A13","title":"Privacy Notices & Transparency","keywords":["privacy","notice","transparency","inform","policy","cookie"],"severity":"HIGH","remediation":"Publish clear privacy notices explaining data collection and use."},
            {"id":"GDPR-A17","title":"Right to Erasure","keywords":["erasure","delete","right","forget","request","subject"],"severity":"HIGH","remediation":"Implement processes to handle data subject erasure requests within 30 days."},
            {"id":"GDPR-A25","title":"Data Protection by Design","keywords":["privacy by design","default","minimis","pseudonym","anonymis"],"severity":"HIGH","remediation":"Embed data protection principles into system design from the start."},
            {"id":"GDPR-A32","title":"Security of Processing","keywords":["encrypt","pseudonym","backup","test","assess","security measure"],"severity":"CRITICAL","remediation":"Implement appropriate technical measures including encryption and access control."},
            {"id":"GDPR-A33","title":"Breach Notification","keywords":["breach","notify","72 hour","dpa","supervisory","incident","report"],"severity":"CRITICAL","remediation":"Establish a breach notification process to notify DPA within 72 hours."},
            {"id":"GDPR-A35","title":"Data Protection Impact Assessment","keywords":["dpia","impact","assessment","high risk","processing","profiling"],"severity":"HIGH","remediation":"Conduct DPIAs for high-risk processing activities before commencing."},
            {"id":"GDPR-A37","title":"Data Protection Officer","keywords":["dpo","officer","data protection","appoint","contact"],"severity":"MEDIUM","remediation":"Appoint a DPO if required and publish their contact details."},
        ]
    },
    "PCI_DSS": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": [
            {"id":"PCI-1","title":"Network Security Controls","keywords":["firewall","network","segmentation","cardholder","dmz","acl"],"severity":"CRITICAL","remediation":"Install and maintain network security controls protecting cardholder data."},
            {"id":"PCI-2","title":"Secure Configuration","keywords":["default","password","config","harden","baseline","unnecessary service"],"severity":"HIGH","remediation":"Change all vendor defaults and apply security hardening baselines."},
            {"id":"PCI-3","title":"Protect Stored Account Data","keywords":["encrypt","pan","card","stored","token","mask","key management"],"severity":"CRITICAL","remediation":"Encrypt all stored cardholder data using AES-256."},
            {"id":"PCI-4","title":"Encrypt Data in Transit","keywords":["tls","encrypt","transit","transmission","https","ssl"],"severity":"CRITICAL","remediation":"Use TLS 1.2+ for all cardholder data transmissions."},
            {"id":"PCI-6","title":"Secure Systems & Software","keywords":["patch","vulnerability","scan","sast","pentest","code review","sdlc"],"severity":"HIGH","remediation":"Patch systems within defined timelines and perform regular security testing."},
            {"id":"PCI-7","title":"Restrict Access to System Components","keywords":["access","need to know","least privilege","rbac","iam","mfa"],"severity":"CRITICAL","remediation":"Restrict access to cardholder data on a need-to-know basis."},
            {"id":"PCI-8","title":"Identify & Authenticate Users","keywords":["mfa","password","authentication","identity","account","privilege"],"severity":"CRITICAL","remediation":"Enforce MFA for all access to cardholder data environments."},
            {"id":"PCI-10","title":"Log & Monitor Access","keywords":["log","monitor","audit","trail","siem","alert","tamper"],"severity":"HIGH","remediation":"Implement audit logging for all access to cardholder data."},
            {"id":"PCI-11","title":"Test Security Regularly","keywords":["pentest","scan","vulnerability","waf","ids","ips","test"],"severity":"HIGH","remediation":"Perform penetration testing and vulnerability scanning at least annually."},
            {"id":"PCI-12","title":"Security Policy & Programme","keywords":["policy","programme","risk","awareness","training","governance"],"severity":"HIGH","remediation":"Maintain a comprehensive information security policy and awareness programme."},
        ]
    }
}

# ============================================================
# CONTROL CHECKER ENGINE
# ============================================================

def check_control(control, text):
    text_lower = text.lower()
    matched = sum(1 for kw in control["keywords"] if kw in text_lower)
    total   = len(control["keywords"])
    ratio   = matched / total if total > 0 else 0
    if ratio >= 0.6:
        return "PASS"
    elif ratio >= 0.3:
        return "PARTIAL"
    else:
        return "FAIL"

def run_assessment(framework_key, text):
    framework = FRAMEWORKS.get(framework_key)
    if not framework:
        return None, []
    results = []
    for control in framework["controls"]:
        status = check_control(control, text)
        results.append({
            "control_id":  control["id"],
            "title":       control["title"],
            "status":      status,
            "severity":    control["severity"],
            "description": f"Control evaluated against submitted system description. Keywords matched: {sum(1 for kw in control['keywords'] if kw in text.lower())}/{len(control['keywords'])}.",
            "remediation": control["remediation"] if status != "PASS" else "Control satisfied."
        })
    return framework, results

def calculate_score(results):
    if not results:
        return 0.0
    weights = {"PASS": 1.0, "PARTIAL": 0.5, "FAIL": 0.0}
    score = sum(weights.get(r["status"], 0) for r in results) / len(results) * 100
    return round(score, 1)

# ============================================================
# API ROUTES
# ============================================================

@compliance_fabric_bp.route("/api/compliance-fabric/frameworks", methods=["GET"])
@jwt_required()
def list_frameworks():
    return jsonify({"frameworks": [{"id": k, "name": v["name"], "description": v["description"], "control_count": len(v["controls"])} for k, v in FRAMEWORKS.items()]}), 200

@compliance_fabric_bp.route("/api/compliance-fabric/assess", methods=["POST"])
@jwt_required()
def assess():
    data          = request.get_json(silent=True) or {}
    framework_key = data.get("framework", "NIS2")
    description   = data.get("description", "")

    if not description.strip():
        return jsonify({"error": "No system description provided"}), 400
    if framework_key not in FRAMEWORKS:
        return jsonify({"error": f"Unknown framework. Choose from: {list(FRAMEWORKS.keys())}"}), 400

    framework, results = run_assessment(framework_key, description)
    score   = calculate_score(results)
    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = sum(1 for r in results if r["status"] == "FAIL")
    partial = sum(1 for r in results if r["status"] == "PARTIAL")

    grade = "Excellent" if score >= 85 else "Good" if score >= 70 else "Needs Improvement" if score >= 50 else "Critical Gaps"
    summary = f"{framework['name']} assessment complete. Score: {score}/100 ({grade}). {passed} controls passed, {partial} partial, {failed} failed."

    report = ComplianceFabricReport(
        user_id       = get_jwt_identity(),
        framework     = framework_key,
        score         = score,
        status        = "complete",
        total_controls= len(results),
        passed        = passed,
        failed        = failed,
        partial       = partial,
        summary       = summary,
        node_meta     = "{}"
    )
    db.session.add(report)
    db.session.flush()

    for r in results:
        db.session.add(ComplianceFabricControl(
            report_id   = report.id,
            control_id  = r["control_id"],
            title       = r["title"],
            status      = r["status"],
            severity    = r["severity"],
            description = r["description"],
            remediation = r["remediation"],
            node_meta   = "{}"
        ))

    db.session.commit()

    return jsonify({"report_id": report.id, "framework": framework_key, "score": score, "grade": grade, "passed": passed, "failed": failed, "partial": partial, "summary": summary}), 200

@compliance_fabric_bp.route("/api/compliance-fabric/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    report = ComplianceFabricReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not report:
        return jsonify({"error": "Report not found"}), 404
    controls = ComplianceFabricControl.query.filter_by(report_id=report_id).all()
    return jsonify({
        "report_id":     report.id,
        "framework":     report.framework,
        "score":         report.score,
        "status":        report.status,
        "total_controls":report.total_controls,
        "passed":        report.passed,
        "failed":        report.failed,
        "partial":       report.partial,
        "summary":       report.summary,
        "created_at":    report.created_at.isoformat(),
        "controls": [{"control_id": c.control_id, "title": c.title, "status": c.status, "severity": c.severity, "description": c.description, "remediation": c.remediation} for c in controls]
    }), 200

@compliance_fabric_bp.route("/api/compliance-fabric/history", methods=["GET"])
@jwt_required()
def history():
    reports = ComplianceFabricReport.query.filter_by(user_id=get_jwt_identity()).order_by(ComplianceFabricReport.created_at.desc()).limit(50).all()
    return jsonify({"reports": [{"report_id": r.id, "framework": r.framework, "score": r.score, "passed": r.passed, "failed": r.failed, "partial": r.partial, "created_at": r.created_at.isoformat()} for r in reports]}), 200

@compliance_fabric_bp.route("/api/compliance-fabric/health", methods=["GET"])
def health():
    return jsonify({"module": "Autonomous Compliance Fabric", "version": "1.0.0", "frameworks": list(FRAMEWORKS.keys()), "status": "operational"}), 200
