# ============================================================
# AIPET X — Cloud SIEM Correlation Engine
# Event Correlation | Alert Triage | Incident Detection
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

cloud_siem_bp = Blueprint("cloud_siem", __name__)

class SIEMReport(db.Model):
    __tablename__ = "siem_reports"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    event_source    = Column(String(128))
    total_events    = Column(Integer, default=0)
    correlated      = Column(Integer, default=0)
    critical_alerts = Column(Integer, default=0)
    incidents       = Column(Integer, default=0)
    risk_score      = Column(Float, default=0.0)
    summary         = Column(Text, nullable=True)
    alerts          = Column(Text, default="[]")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

CORRELATION_RULES = [
    {"id":"SIEM-001","title":"Brute Force Attack Campaign","keywords":["multiple failed login","authentication failure","failed login","brute force","password spray","lockout","login attempt"],"severity":"CRITICAL","category":"Credential Attack","mitre":"T1110","confidence":"HIGH","description":"Multiple authentication failures from same source — active brute force campaign detected.","response":"Block source IP. Force password reset. Enable MFA. Review account lockout policy."},
    {"id":"SIEM-002","title":"Lateral Movement via Remote Services","keywords":["psexec","wmi execution","lateral movement","smb connection","remote service","net use","admin share"],"severity":"CRITICAL","category":"Lateral Movement","mitre":"T1021","confidence":"HIGH","description":"Attacker moving laterally across internal network using remote execution tools.","response":"Isolate affected systems. Block lateral movement paths. Reset compromised credentials."},
    {"id":"SIEM-003","title":"Data Exfiltration to External Host","keywords":["large upload","data exfil","ftp upload","unusual egress","bulk transfer","data leaving","outbound large"],"severity":"CRITICAL","category":"Exfiltration","mitre":"T1041","confidence":"HIGH","description":"Abnormal volume of data being transferred to external destination.","response":"Block egress traffic. Identify exfiltrated data. Notify DPO. Initiate incident response."},
    {"id":"SIEM-004","title":"Privilege Escalation Detected","keywords":["privilege escalation","sudo","admin access","root gained","elevated privilege","uac bypass","token manipulation"],"severity":"CRITICAL","category":"Privilege Escalation","mitre":"T1548","confidence":"HIGH","description":"User or process gained elevated privileges outside normal workflow.","response":"Revoke elevated access. Investigate how escalation occurred. Patch vulnerability."},
    {"id":"SIEM-005","title":"Impossible Travel Alert","keywords":["impossible travel","geo anomaly","location anomaly","multiple countries","travel alert","simultaneous login","different location"],"severity":"HIGH","category":"Account Compromise","mitre":"T1078","confidence":"HIGH","description":"User authenticated from two geographically distant locations in impossible timeframe.","response":"Suspend account. Force MFA. Contact user to verify. Reset credentials if confirmed."},
    {"id":"SIEM-006","title":"Ransomware Kill Chain Detected","keywords":["ransomware","file encryption","shadow delete","vssadmin","ransom note","mass rename","encrypt extension"],"severity":"CRITICAL","category":"Ransomware","mitre":"T1486","confidence":"HIGH","description":"Multiple ransomware indicators detected — active ransomware attack in progress.","response":"ISOLATE ALL AFFECTED SYSTEMS IMMEDIATELY. Disconnect from network. Preserve memory. Contact IR team."},
    {"id":"SIEM-007","title":"Insider Threat — Unusual Data Access","keywords":["unusual access","off hours","bulk download","sensitive file","after hours","data hoarding","mass copy"],"severity":"HIGH","category":"Insider Threat","mitre":"T1005","confidence":"MEDIUM","description":"Employee accessing unusually large volumes of sensitive data outside normal patterns.","response":"Alert DLP team. Review user activity. Preserve evidence. Consider HR involvement."},
    {"id":"SIEM-008","title":"Cloud Infrastructure Compromise","keywords":["cloud api abuse","iam abuse","aws compromise","azure compromise","cloud console","root account login","cloud admin"],"severity":"CRITICAL","category":"Cloud Attack","mitre":"T1078.004","confidence":"HIGH","description":"Unauthorised access to cloud management plane detected.","response":"Rotate all cloud credentials. Revoke compromised access. Review all recent API calls. Enable CloudTrail."},
    {"id":"SIEM-009","title":"Zero-Day Exploit Attempt","keywords":["zero day","0day","unknown exploit","cve new","unpatched exploit","exploit attempt","vulnerability exploit"],"severity":"CRITICAL","category":"Exploitation","mitre":"T1190","confidence":"MEDIUM","description":"Exploitation attempt targeting potentially unpatched vulnerability.","response":"Apply emergency patch. Implement virtual patching via WAF. Isolate vulnerable systems."},
    {"id":"SIEM-010","title":"C2 Beacon Pattern Detected","keywords":["c2 beacon","command control","beacon interval","periodic callback","cobalt strike","metasploit","c2 communication"],"severity":"CRITICAL","category":"Command & Control","mitre":"T1071","confidence":"HIGH","description":"Regular beaconing pattern to external C2 infrastructure — active malware infection.","response":"Identify infected host. Isolate from network. Block C2 domain/IP. Perform forensic investigation."},
    {"id":"SIEM-011","title":"Supply Chain Attack Indicators","keywords":["supply chain","software update","trusted software","build pipeline","ci cd compromise","code signing","update mechanism"],"severity":"CRITICAL","category":"Supply Chain","mitre":"T1195","confidence":"MEDIUM","description":"Indicators of supply chain compromise in software update or build pipeline.","response":"Halt software updates. Audit build pipeline. Verify code signing. Notify affected customers."},
    {"id":"SIEM-012","title":"DDoS Attack Detected","keywords":["ddos","denial of service","traffic spike","syn flood","udp flood","amplification","bandwidth exhaustion"],"severity":"HIGH","category":"Availability","mitre":"T1498","confidence":"HIGH","description":"Distributed denial of service attack impacting service availability.","response":"Enable DDoS protection. Rate limit traffic. Contact upstream provider. Activate CDN scrubbing."},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}
CONF_W = {"HIGH":1.5,"MEDIUM":1.0,"LOW":0.5}

def correlate_events(description, event_source):
    desc_lower = description.lower()
    alerts = []
    for rule in CORRELATION_RULES:
        matched = sum(1 for kw in rule["keywords"] if kw.lower() in desc_lower)
        if matched > 0:
            alerts.append({
                "rule_id":    rule["id"],
                "title":      rule["title"],
                "severity":   rule["severity"],
                "category":   rule["category"],
                "mitre":      rule["mitre"],
                "confidence": rule["confidence"],
                "description":rule["description"],
                "response":   rule["response"],
                "matched":    matched,
            })
    alerts.sort(key=lambda x: (-SEV_W.get(x["severity"],0), -x["matched"]))
    return alerts

def calc_risk(alerts):
    if not alerts: return 0.0
    raw = sum(SEV_W.get(a["severity"],0) * CONF_W.get(a["confidence"],1.0) for a in alerts)
    return round(min(raw * 1.3, 100.0), 1)

@cloud_siem_bp.route("/api/cloud-siem/correlate", methods=["POST"])
@jwt_required()
def correlate():
    data         = request.get_json(silent=True) or {}
    event_source = data.get("event_source", "multi-source")
    description  = data.get("description", "")
    total_events = data.get("total_events", 1000)
    if not description.strip(): return jsonify({"error":"No events provided"}), 400

    alerts   = correlate_events(description, event_source)
    risk     = calc_risk(alerts)
    critical = sum(1 for a in alerts if a["severity"]=="CRITICAL")
    incidents= sum(1 for a in alerts if a["severity"]=="CRITICAL" and a["confidence"]=="HIGH")

    summary = (f"SIEM correlation complete for {event_source}. "
               f"{total_events} event(s) processed. {len(alerts)} alert(s) correlated — "
               f"{critical} critical, {incidents} confirmed incident(s). Risk: {risk}/100.")

    r = SIEMReport(user_id=get_jwt_identity(), event_source=event_source, total_events=total_events, correlated=len(alerts), critical_alerts=critical, incidents=incidents, risk_score=risk, summary=summary, alerts=json.dumps(alerts), node_meta="{}")
    db.session.add(r); db.session.commit()

    return jsonify({"report_id":r.id,"event_source":event_source,"total_events":total_events,"correlated":len(alerts),"critical_alerts":critical,"incidents":incidents,"risk_score":risk,"alerts":alerts,"summary":summary}), 200

@cloud_siem_bp.route("/api/cloud-siem/history", methods=["GET"])
@jwt_required()
def history():
    reports = SIEMReport.query.filter_by(user_id=get_jwt_identity()).order_by(SIEMReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"event_source":r.event_source,"total_events":r.total_events,"correlated":r.correlated,"critical_alerts":r.critical_alerts,"incidents":r.incidents,"risk_score":r.risk_score,"created_at":r.created_at.isoformat()} for r in reports]}), 200

@cloud_siem_bp.route("/api/cloud-siem/health", methods=["GET"])
def health():
    return jsonify({"module":"Cloud SIEM Correlation Engine","version":"1.0.0","rules":len(CORRELATION_RULES),"status":"operational"}), 200
