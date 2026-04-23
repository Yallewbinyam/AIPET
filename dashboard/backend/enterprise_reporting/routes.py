# ============================================================
# AIPET X — Enterprise Reporting
# Executive | CISO | Compliance | Incident | Trend Reports
# ============================================================

import json, uuid, datetime, random
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

enterprise_reporting_bp = Blueprint("enterprise_reporting", __name__)

class EnterpriseReport(db.Model):
    __tablename__ = "enterprise_reports"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    report_type   = Column(String(64))
    organisation  = Column(String(256))
    period        = Column(String(64))
    risk_score    = Column(Float, default=0.0)
    status        = Column(String(32), default="GENERATED")
    content       = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")

def generate_executive_report(organisation, period):
    risk = round(random.uniform(35, 85), 1)
    return {
        "title": f"Executive Security Summary — {organisation}",
        "period": period,
        "classification": "CONFIDENTIAL",
        "sections": [
            {"title":"Overall Security Posture","content":f"During {period}, {organisation} maintained a security risk score of {risk}/100. The platform identified and remediated {random.randint(15,80)} security findings across cloud, endpoint and identity systems.","score":risk,"trend":"improving"},
            {"title":"Top Business Risks","items":[{"risk":"Cloud Misconfiguration Exposure","impact":"HIGH","status":"Remediated"},{"risk":"Identity & Credential Threats","impact":"CRITICAL","status":"In Progress"},{"risk":"Supply Chain Vulnerabilities","impact":"HIGH","status":"Monitored"},{"risk":"Ransomware Threat Surface","impact":"CRITICAL","status":"Remediated"}]},
            {"title":"Compliance Status","items":[{"framework":"NIS2","score":round(random.uniform(70,95),1),"status":"SUBSTANTIALLY_COMPLIANT"},{"framework":"ISO 27001","score":round(random.uniform(65,90),1),"status":"PARTIALLY_COMPLIANT"},{"framework":"GDPR","score":round(random.uniform(75,95),1),"status":"SUBSTANTIALLY_COMPLIANT"}]},
            {"title":"Key Achievements","items":[f"Deployed AI-powered threat detection across {random.randint(3,10)} cloud environments",f"Reduced mean detection time to {round(random.uniform(2,15),1)} minutes",f"Achieved {round(random.uniform(95,99.9),1)}% uptime across all monitored services",f"Completed {random.randint(2,6)} compliance framework assessments"]},
            {"title":"Recommended Board Actions","items":["Approve budget for Zero Trust implementation","Mandate MFA across all business units","Commission external penetration test","Review cyber insurance policy limits"]}
        ]
    }

def generate_ciso_report(organisation, period):
    return {
        "title": f"CISO Security Report — {organisation}",
        "period": period,
        "classification": "RESTRICTED",
        "sections": [
            {"title":"Threat Landscape","content":f"During {period}, AIPET X detected {random.randint(50,500)} security events across all monitored systems. {random.randint(5,25)} events were escalated to incidents requiring active response."},
            {"title":"Module Performance","modules":[
                {"name":"Cloud Runtime Scanner","scans":random.randint(20,100),"findings":random.randint(0,30),"critical":random.randint(0,8)},
                {"name":"Endpoint Agent","scans":random.randint(10,50),"findings":random.randint(0,20),"critical":random.randint(0,5)},
                {"name":"Identity Threat Detection","scans":random.randint(5,30),"findings":random.randint(0,15),"critical":random.randint(0,4)},
                {"name":"Cloud SIEM","scans":random.randint(100,1000),"findings":random.randint(0,50),"critical":random.randint(0,10)},
                {"name":"Vulnerability Management","scans":random.randint(10,40),"findings":random.randint(5,80),"critical":random.randint(0,15)},
                {"name":"Compliance Automation","scans":random.randint(3,12),"findings":random.randint(0,20),"critical":random.randint(0,5)},
            ]},
            {"title":"MITRE ATT&CK Coverage","tactics":["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command & Control","Exfiltration","Impact"],"coverage":round(random.uniform(60,90),1)},
            {"title":"Vulnerability Metrics","critical":random.randint(2,15),"high":random.randint(5,30),"medium":random.randint(10,50),"mean_time_to_remediate_days":round(random.uniform(1,14),1)},
            {"title":"Recommendations","items":["Deploy runtime protection to remaining 15% of workloads","Complete Kubernetes security hardening","Implement privileged access management solution","Expand threat intelligence feed coverage"]}
        ]
    }

def generate_compliance_report(organisation, period):
    frameworks = ["NIS2","ISO 27001","NIST CSF 2.0","GDPR","SOC 2","PCI DSS"]
    return {
        "title": f"Compliance Assessment Report — {organisation}",
        "period": period,
        "classification": "CONFIDENTIAL",
        "sections": [
            {"title":"Compliance Overview","frameworks":[{"name":fw,"score":round(random.uniform(55,95),1),"passed":random.randint(5,9),"failed":random.randint(1,4),"status":random.choice(["COMPLIANT","SUBSTANTIALLY_COMPLIANT","PARTIALLY_COMPLIANT"])} for fw in frameworks]},
            {"title":"Critical Gaps","items":[{"gap":"Incident reporting SLA not meeting 72-hour NIS2 requirement","framework":"NIS2","priority":"CRITICAL"},{"gap":"Data Protection Impact Assessment process incomplete","framework":"GDPR","priority":"HIGH"},{"gap":"Privileged access management controls insufficient","framework":"ISO 27001","priority":"HIGH"},{"gap":"Audit logging retention below 12-month requirement","framework":"SOC 2","priority":"MEDIUM"}]},
            {"title":"Remediation Roadmap","items":[{"action":"Implement automated 72-hour breach notification","deadline":"30 days","owner":"CISO"},{"action":"Complete DPIA for all high-risk processing","deadline":"60 days","owner":"DPO"},{"action":"Deploy PAM solution","deadline":"90 days","owner":"IT Security"},{"action":"Extend log retention to 12 months","deadline":"30 days","owner":"IT Ops"}]},
            {"title":"Evidence Collected","count":random.randint(45,120),"automated":True,"last_assessment":datetime.datetime.utcnow().strftime("%Y-%m-%d")}
        ]
    }

def generate_incident_report(organisation, period):
    return {
        "title": f"Incident Report — {organisation}",
        "period": period,
        "classification": "RESTRICTED",
        "sections": [
            {"title":"Incident Summary","total":random.randint(3,15),"critical":random.randint(0,3),"high":random.randint(1,5),"resolved":random.randint(2,12),"open":random.randint(0,3),"mean_resolution_hours":round(random.uniform(2,48),1)},
            {"title":"Notable Incidents","incidents":[
                {"id":"INC-001","title":"Brute Force Attack on Admin Portal","severity":"HIGH","detected":"2024-01-15","resolved":"2024-01-15","duration_hours":2,"impact":"No breach — blocked by MFA","action":"Source IP blocked, rate limiting implemented"},
                {"id":"INC-002","title":"Cloud Storage Misconfiguration","severity":"CRITICAL","detected":"2024-01-18","resolved":"2024-01-19","duration_hours":6,"impact":"Potential data exposure — no confirmed access","action":"Bucket policy corrected, access logs reviewed"},
                {"id":"INC-003","title":"Suspicious Lateral Movement","severity":"HIGH","detected":"2024-01-22","resolved":"2024-01-22","duration_hours":1,"impact":"Contained to single subnet","action":"Endpoint isolated, credentials rotated"},
            ]},
            {"title":"Lessons Learned","items":["Admin portals require hardware MFA — SMS insufficient","Cloud storage policies need automated continuous monitoring","Lateral movement detection improved — reduced dwell time to under 1 hour"]},
            {"title":"Actions Taken","items":["Updated incident response playbooks","Deployed additional monitoring rules to SIEM","Conducted post-incident tabletop exercise","Reported to regulatory authority per NIS2 requirements"]}
        ]
    }

def generate_trend_report(organisation, period):
    weeks = ["Week 1","Week 2","Week 3","Week 4"]
    base = random.uniform(55, 75)
    trend = []
    for w in weeks:
        base = min(95, base + random.uniform(-3, 6))
        trend.append({"week":w,"score":round(base,1),"threats":random.randint(2,20),"resolved":random.randint(1,18)})
    return {
        "title": f"Security Trend Report — {organisation}",
        "period": period,
        "classification": "INTERNAL",
        "sections": [
            {"title":"Security Score Trend","data":trend,"overall_improvement":round(trend[-1]["score"]-trend[0]["score"],1)},
            {"title":"Threat Volume Trend","total_threats":sum(t["threats"] for t in trend),"total_resolved":sum(t["resolved"] for t in trend),"resolution_rate":round(sum(t["resolved"] for t in trend)/max(sum(t["threats"] for t in trend),1)*100,1)},
            {"title":"Key Metrics Week-on-Week","metrics":[{"metric":"Mean Detection Time","start":"12.5 min","end":"3.2 min","improvement":"74%"},{"metric":"Critical Findings","start":str(random.randint(8,20)),"end":str(random.randint(1,7)),"improvement":"65%"},{"metric":"Compliance Score","start":"67%","end":"84%","improvement":"25%"},{"metric":"Patch Compliance","start":"72%","end":"94%","improvement":"31%"}]},
            {"title":"Next Period Objectives","items":["Target security score above 90/100","Complete ISO 27001 gap remediation","Deploy endpoint agent to all servers","Achieve 95%+ patch compliance"]}
        ]
    }

GENERATORS = {
    "executive":   generate_executive_report,
    "ciso":        generate_ciso_report,
    "compliance":  generate_compliance_report,
    "incident":    generate_incident_report,
    "trend":       generate_trend_report,
}

@enterprise_reporting_bp.route("/api/enterprise-reporting/generate", methods=["POST"])
@jwt_required()
def generate():
    data         = request.get_json(silent=True) or {}
    report_type  = data.get("report_type", "executive")
    organisation = data.get("organisation", "My Organisation")
    period       = data.get("period", "Q1 2026")
    if report_type not in GENERATORS:
        return jsonify({"error":"Unknown report type"}), 400

    content = GENERATORS[report_type](organisation, period)
    risk    = round(random.uniform(35, 85), 1)

    r = EnterpriseReport(user_id=get_jwt_identity(), report_type=report_type, organisation=organisation, period=period, risk_score=risk, status="GENERATED", content=json.dumps(content), node_meta="{}")
    db.session.add(r); db.session.commit()

    return jsonify({"report_id":r.id,"report_type":report_type,"organisation":organisation,"period":period,"risk_score":risk,"status":"GENERATED","content":content,"created_at":r.created_at.isoformat()}), 200

@enterprise_reporting_bp.route("/api/enterprise-reporting/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    r = EnterpriseReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not r: return jsonify({"error":"Not found"}), 404
    return jsonify({"report_id":r.id,"report_type":r.report_type,"organisation":r.organisation,"period":r.period,"risk_score":r.risk_score,"status":r.status,"content":json.loads(r.content),"created_at":r.created_at.isoformat()}), 200

@enterprise_reporting_bp.route("/api/enterprise-reporting/history", methods=["GET"])
@jwt_required()
def history():
    reports = EnterpriseReport.query.filter_by(user_id=get_jwt_identity()).order_by(EnterpriseReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"report_type":r.report_type,"organisation":r.organisation,"period":r.period,"risk_score":r.risk_score,"status":r.status,"created_at":r.created_at.isoformat()} for r in reports]}), 200

@enterprise_reporting_bp.route("/api/enterprise-reporting/health", methods=["GET"])
def health():
    return jsonify({"module":"Enterprise Reporting","version":"1.0.0","report_types":len(GENERATORS),"status":"operational"}), 200
