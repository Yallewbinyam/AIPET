# ============================================================
# AIPET X — Compliance Automation Engine
# NIS2 | ISO 27001 | NIST CSF | SOC2 | GDPR | PCI-DSS
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float
from sqlalchemy.orm import relationship

compliance_automation_bp = Blueprint("compliance_automation", __name__)

class ComplianceAssessment(db.Model):
    __tablename__ = "compliance_assessments"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    framework       = Column(String(64))
    organisation    = Column(String(256))
    overall_score   = Column(Float, default=0.0)
    passed          = Column(Integer, default=0)
    failed          = Column(Integer, default=0)
    partial         = Column(Integer, default=0)
    critical_gaps   = Column(Integer, default=0)
    status          = Column(String(32), default="NON_COMPLIANT")
    summary         = Column(Text, nullable=True)
    controls        = Column(Text, default="[]")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

FRAMEWORKS = {
    "nis2": {
        "name": "NIS2 Directive",
        "description": "EU Network and Information Security Directive 2",
        "controls": [
            {"id":"NIS2-1","domain":"Risk Management","title":"Cybersecurity Risk Management Policy","keywords":["risk policy","risk management","risk assessment","cyber risk"],"weight":10},
            {"id":"NIS2-2","domain":"Incident Handling","title":"Incident Detection & Response","keywords":["incident response","ir plan","incident handling","siem","detection"],"weight":10},
            {"id":"NIS2-3","domain":"Business Continuity","title":"Business Continuity & Disaster Recovery","keywords":["bcp","dr plan","business continuity","disaster recovery","backup"],"weight":9},
            {"id":"NIS2-4","domain":"Supply Chain","title":"Supply Chain Security","keywords":["supply chain","vendor risk","third party","supplier security","sbom"],"weight":8},
            {"id":"NIS2-5","domain":"Access Control","title":"Access Control & Identity Management","keywords":["access control","iam","mfa","least privilege","identity"],"weight":9},
            {"id":"NIS2-6","domain":"Cryptography","title":"Encryption & Cryptography","keywords":["encryption","tls","cryptography","encrypted","aes","certificate"],"weight":8},
            {"id":"NIS2-7","domain":"Vulnerability","title":"Vulnerability Management","keywords":["vulnerability","patch","cve","scanning","pentest"],"weight":9},
            {"id":"NIS2-8","domain":"Training","title":"Cybersecurity Awareness Training","keywords":["training","awareness","phishing","education","security culture"],"weight":7},
            {"id":"NIS2-9","domain":"Asset Management","title":"Asset Inventory & Management","keywords":["asset inventory","asset management","cmdb","device management"],"weight":7},
            {"id":"NIS2-10","domain":"Reporting","title":"Incident Reporting to Authorities","keywords":["incident reporting","regulatory report","72 hour","notif","authority report"],"weight":8},
        ]
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "description": "International Standard for Information Security Management",
        "controls": [
            {"id":"ISO-A5","domain":"Organisational Controls","title":"Information Security Policies","keywords":["security policy","information security policy","isms","documented policy"],"weight":9},
            {"id":"ISO-A6","domain":"People Controls","title":"Screening & Security Awareness","keywords":["background check","screening","awareness training","hr security"],"weight":8},
            {"id":"ISO-A7","domain":"Physical Controls","title":"Physical & Environmental Security","keywords":["physical security","access card","cctv","clean desk","server room"],"weight":7},
            {"id":"ISO-A8","domain":"Technology Controls","title":"Asset & Endpoint Management","keywords":["asset management","endpoint","antivirus","edr","device control"],"weight":9},
            {"id":"ISO-A9","domain":"Access Control","title":"Access Control Management","keywords":["access control","role based","rbac","least privilege","mfa","privileged"],"weight":10},
            {"id":"ISO-A10","domain":"Cryptography","title":"Cryptographic Controls","keywords":["encryption","key management","certificate","tls","crypto policy"],"weight":8},
            {"id":"ISO-A12","domain":"Operations","title":"Operational Security","keywords":["change management","capacity","backup","monitoring","logging","patch"],"weight":9},
            {"id":"ISO-A13","domain":"Communications","title":"Network Security","keywords":["network security","firewall","dmz","network segmentation","vpn","ids"],"weight":9},
            {"id":"ISO-A16","domain":"Incident Management","title":"Information Security Incidents","keywords":["incident management","ir procedure","incident log","lessons learned"],"weight":8},
            {"id":"ISO-A17","domain":"BCM","title":"Business Continuity","keywords":["business continuity","bcp","rto","rpo","disaster recovery","resilience"],"weight":8},
        ]
    },
    "nist_csf": {
        "name": "NIST CSF 2.0",
        "description": "NIST Cybersecurity Framework 2.0",
        "controls": [
            {"id":"CSF-GV","domain":"Govern","title":"Governance & Risk Management","keywords":["governance","risk management","policy","roles responsibilities","cybersecurity strategy"],"weight":9},
            {"id":"CSF-ID","domain":"Identify","title":"Asset & Risk Identification","keywords":["asset inventory","risk assessment","vulnerability","business environment","supply chain risk"],"weight":9},
            {"id":"CSF-PR-AC","domain":"Protect","title":"Access Control","keywords":["access control","authentication","mfa","identity","least privilege","zero trust"],"weight":10},
            {"id":"CSF-PR-DS","domain":"Protect","title":"Data Security","keywords":["data protection","encryption","dlp","data classification","data at rest"],"weight":9},
            {"id":"CSF-PR-IP","domain":"Protect","title":"Security Awareness & Training","keywords":["awareness","training","phishing","security culture","hr security"],"weight":7},
            {"id":"CSF-DE","domain":"Detect","title":"Anomaly & Event Detection","keywords":["detection","siem","monitoring","ids","ips","anomaly","alert"],"weight":10},
            {"id":"CSF-RS","domain":"Respond","title":"Incident Response","keywords":["incident response","ir plan","containment","eradication","recovery"],"weight":9},
            {"id":"CSF-RC","domain":"Recover","title":"Recovery Planning","keywords":["recovery","backup","bcp","rto","rpo","restore","resilience"],"weight":8},
        ]
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "AICPA Service Organisation Control Trust Services Criteria",
        "controls": [
            {"id":"SOC-CC1","domain":"Control Environment","title":"Organisational Oversight & Integrity","keywords":["governance","board oversight","code of conduct","integrity","control environment"],"weight":9},
            {"id":"SOC-CC2","domain":"Communication","title":"Communication & Information","keywords":["security communication","policy communication","reporting structure","information security"],"weight":7},
            {"id":"SOC-CC3","domain":"Risk Assessment","title":"Risk Assessment Process","keywords":["risk assessment","risk identification","fraud risk","risk tolerance"],"weight":9},
            {"id":"SOC-CC4","domain":"Monitoring","title":"Monitoring Activities","keywords":["monitoring","audit","control testing","continuous monitoring","siem"],"weight":8},
            {"id":"SOC-CC6","domain":"Logical Access","title":"Logical & Physical Access Controls","keywords":["access control","mfa","rbac","privileged access","logical access","physical access"],"weight":10},
            {"id":"SOC-CC7","domain":"System Operations","title":"System Operations & Change Management","keywords":["change management","incident detection","backup","recovery","operations"],"weight":9},
            {"id":"SOC-CC8","domain":"Change Management","title":"Change Management Controls","keywords":["change control","release management","testing","code review","deployment"],"weight":8},
            {"id":"SOC-A1","domain":"Availability","title":"Availability Commitments","keywords":["availability","uptime","sla","redundancy","failover","disaster recovery"],"weight":9},
        ]
    },
    "gdpr": {
        "name": "GDPR",
        "description": "EU General Data Protection Regulation",
        "controls": [
            {"id":"GDPR-6","domain":"Lawfulness","title":"Lawful Basis for Processing","keywords":["lawful basis","consent","legitimate interest","data processing","legal basis"],"weight":9},
            {"id":"GDPR-13","domain":"Transparency","title":"Privacy Notices & Transparency","keywords":["privacy notice","privacy policy","data subject","transparency","information rights"],"weight":8},
            {"id":"GDPR-17","domain":"Rights","title":"Data Subject Rights","keywords":["data subject rights","right to erasure","access request","subject access","dsar","portability"],"weight":9},
            {"id":"GDPR-25","domain":"Privacy by Design","title":"Privacy by Design & Default","keywords":["privacy by design","data minimisation","pseudonymisation","privacy impact","dpia"],"weight":9},
            {"id":"GDPR-32","domain":"Security","title":"Security of Processing","keywords":["encryption","access control","security measure","pseudonymisation","integrity"],"weight":10},
            {"id":"GDPR-33","domain":"Breach Notification","title":"Personal Data Breach Notification","keywords":["breach notification","72 hour","data breach","incident notification","supervisory authority"],"weight":10},
            {"id":"GDPR-35","domain":"DPIA","title":"Data Protection Impact Assessment","keywords":["dpia","impact assessment","high risk processing","data protection officer","dpo"],"weight":8},
            {"id":"GDPR-37","domain":"DPO","title":"Data Protection Officer","keywords":["dpo","data protection officer","gdpr officer","supervisory authority","record keeping"],"weight":7},
        ]
    },
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": [
            {"id":"PCI-1","domain":"Network Security","title":"Install & Maintain Network Security","keywords":["firewall","network security","cardholder data environment","cde","network segmentation"],"weight":10},
            {"id":"PCI-2","domain":"Secure Config","title":"Secure Configurations","keywords":["secure configuration","hardening","default password","security baseline","system config"],"weight":9},
            {"id":"PCI-3","domain":"Data Protection","title":"Protect Stored Account Data","keywords":["card data","pan","encryption","tokenisation","data retention","stored data"],"weight":10},
            {"id":"PCI-4","domain":"Encryption","title":"Protect Data in Transit","keywords":["tls","encryption transit","ssl","data in transit","cardholder data network"],"weight":9},
            {"id":"PCI-6","domain":"Vulnerability","title":"Develop & Maintain Secure Systems","keywords":["secure development","vulnerability management","patch","code review","sast","pentest"],"weight":9},
            {"id":"PCI-7","domain":"Access Control","title":"Restrict Access to System Components","keywords":["least privilege","need to know","access control","role based","system access"],"weight":9},
            {"id":"PCI-8","domain":"Identity","title":"Identify Users & Authenticate Access","keywords":["mfa","authentication","unique id","password","identity management","privileged access"],"weight":10},
            {"id":"PCI-10","domain":"Logging","title":"Log & Monitor All Access","keywords":["audit log","logging","monitoring","log review","siem","time synchronisation"],"weight":9},
            {"id":"PCI-11","domain":"Testing","title":"Test Security Regularly","keywords":["penetration test","vulnerability scan","asm","wireless scan","quarterly scan"],"weight":8},
            {"id":"PCI-12","domain":"Policy","title":"Support Information Security with Policies","keywords":["security policy","incident response","acceptable use","risk assessment","security program"],"weight":8},
        ]
    }
}

def assess_compliance(description, framework_key):
    fw = FRAMEWORKS.get(framework_key)
    if not fw: return [], 0, 0, 0, 0, "UNKNOWN", "Unknown framework"

    desc_lower = description.lower()
    controls_result = []
    passed = failed = partial = 0

    for ctrl in fw["controls"]:
        matched = sum(1 for kw in ctrl["keywords"] if kw.lower() in desc_lower)
        total_kw = len(ctrl["keywords"])
        ratio = matched / total_kw

        if ratio >= 0.5:
            status = "PASS"
            passed += 1
            score = ctrl["weight"]
        elif ratio >= 0.2:
            status = "PARTIAL"
            partial += 1
            score = ctrl["weight"] * 0.5
        else:
            status = "FAIL"
            failed += 1
            score = 0

        controls_result.append({
            "id":          ctrl["id"],
            "domain":      ctrl["domain"],
            "title":       ctrl["title"],
            "status":      status,
            "score":       score,
            "max_score":   ctrl["weight"],
            "gap":         ctrl["title"] if status == "FAIL" else None,
            "remediation": f"Implement {ctrl['title']} controls to meet {fw['name']} requirements." if status != "PASS" else None
        })

    total_weight = sum(c["weight"] for c in fw["controls"])
    earned = sum(c["score"] for c in controls_result)
    overall = round((earned / total_weight) * 100, 1)
    critical_gaps = failed
    compliance_status = "COMPLIANT" if overall >= 90 else "SUBSTANTIALLY_COMPLIANT" if overall >= 70 else "PARTIALLY_COMPLIANT" if overall >= 50 else "NON_COMPLIANT"

    summary = (f"{fw['name']} compliance assessment complete. "
               f"Overall score: {overall}%. Status: {compliance_status}. "
               f"{passed} control(s) passed, {partial} partial, {failed} failed. "
               f"{critical_gaps} critical gap(s) requiring immediate attention.")

    return controls_result, overall, passed, failed, partial, critical_gaps, compliance_status, summary

@compliance_automation_bp.route("/api/compliance-automation/assess", methods=["POST"])
@jwt_required()
def assess():
    data         = request.get_json(silent=True) or {}
    framework    = data.get("framework", "nis2")
    organisation = data.get("organisation", "My Organisation")
    description  = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    controls, overall, passed, failed, partial, gaps, status, summary = assess_compliance(description, framework)

    a = ComplianceAssessment(user_id=get_jwt_identity(), framework=framework, organisation=organisation, overall_score=overall, passed=passed, failed=failed, partial=partial, critical_gaps=gaps, status=status, summary=summary, controls=json.dumps(controls), node_meta="{}")
    db.session.add(a); db.session.commit()

    fw_info = FRAMEWORKS.get(framework, {})
    return jsonify({"assessment_id":a.id,"framework":framework,"framework_name":fw_info.get("name",""),"organisation":organisation,"overall_score":overall,"passed":passed,"failed":failed,"partial":partial,"critical_gaps":gaps,"status":status,"controls":controls,"summary":summary}), 200

@compliance_automation_bp.route("/api/compliance-automation/frameworks", methods=["GET"])
def frameworks():
    return jsonify({"frameworks":[{"key":k,"name":v["name"],"description":v["description"],"total_controls":len(v["controls"])} for k,v in FRAMEWORKS.items()]}), 200

@compliance_automation_bp.route("/api/compliance-automation/history", methods=["GET"])
@jwt_required()
def history():
    assessments = ComplianceAssessment.query.filter_by(user_id=get_jwt_identity()).order_by(ComplianceAssessment.created_at.desc()).limit(50).all()
    return jsonify({"assessments":[{"assessment_id":a.id,"framework":a.framework,"organisation":a.organisation,"overall_score":a.overall_score,"status":a.status,"passed":a.passed,"failed":a.failed,"critical_gaps":a.critical_gaps,"created_at":a.created_at.isoformat()} for a in assessments]}), 200

@compliance_automation_bp.route("/api/compliance-automation/health", methods=["GET"])
def health():
    return jsonify({"module":"Compliance Automation Engine","version":"1.0.0","frameworks":len(FRAMEWORKS),"status":"operational"}), 200
