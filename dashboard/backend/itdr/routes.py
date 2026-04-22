# ============================================================
# AIPET X — Identity Threat Detection (ITDR)
# Golden Ticket | Pass-the-Hash | Kerberoasting | MFA Attacks
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

itdr_bp = Blueprint("itdr", __name__)

class ITDRScan(db.Model):
    __tablename__ = "itdr_scans"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(Integer, nullable=False)
    environment    = Column(String(64), default="production")
    identity_store = Column(String(64), default="active_directory")
    risk_score     = Column(Float, default=0.0)
    severity       = Column(String(16), default="LOW")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    identities_compromised = Column(Integer, default=0)
    summary        = Column(Text, nullable=True)
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta      = Column(Text, default="{}")
    findings       = relationship("ITDRFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class ITDRFinding(db.Model):
    __tablename__ = "itdr_findings"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(64), ForeignKey("itdr_scans.id"), nullable=False)
    attack_type    = Column(String(64))
    title          = Column(String(256))
    severity       = Column(String(16))
    affected_identity = Column(String(256), nullable=True)
    mitre_tactic   = Column(String(128), nullable=True)
    mitre_technique= Column(String(128), nullable=True)
    description    = Column(Text)
    remediation    = Column(Text)
    urgency        = Column(String(32), default="HIGH")
    node_meta      = Column(Text, default="{}")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

ITDR_RULES = [
    # Kerberos Attacks
    {"type":"Kerberos Attack","title":"Golden Ticket Attack Detected","keywords":["golden ticket","krbtgt","forged ticket","kerberos forgery","ticket forgery","golden ticket attack"],"severity":"CRITICAL","tactic":"Lateral Movement","technique":"T1550.003 — Use Alternate Authentication Material","urgency":"IMMEDIATE","remediation":"Reset krbtgt password TWICE with 10-hour gap. Invalidate all Kerberos tickets. Audit all domain admin activity immediately."},
    {"type":"Kerberos Attack","title":"Silver Ticket Attack Detected","keywords":["silver ticket","service ticket forged","forged service ticket","silver ticket attack","kerberos service"],"severity":"CRITICAL","tactic":"Lateral Movement","technique":"T1550.003 — Use Alternate Authentication Material","urgency":"IMMEDIATE","remediation":"Reset service account password. Enable Kerberos armoring (FAST). Monitor service ticket anomalies."},
    {"type":"Kerberos Attack","title":"Kerberoasting Attack Detected","keywords":["kerberoasting","spn","service principal name","kerberos hash","tgs request","roast"],"severity":"HIGH","tactic":"Credential Access","technique":"T1558.003 — Kerberoasting","urgency":"HIGH","remediation":"Use strong 25+ char passwords for service accounts. Enable AES encryption. Audit SPN accounts. Use gMSA where possible."},
    {"type":"Kerberos Attack","title":"AS-REP Roasting Detected","keywords":["asrep roasting","as-rep","kerberos pre-auth disabled","no pre-authentication","asrep attack"],"severity":"HIGH","tactic":"Credential Access","technique":"T1558.004 — AS-REP Roasting","urgency":"HIGH","remediation":"Enable Kerberos pre-authentication on all accounts. Use strong passwords on affected accounts."},
    {"type":"Kerberos Attack","title":"Pass-the-Ticket Attack","keywords":["pass the ticket","ptt","stolen ticket","ticket injection","ticket reuse","kerberos ticket stolen"],"severity":"CRITICAL","tactic":"Lateral Movement","technique":"T1550.003","urgency":"IMMEDIATE","remediation":"Purge all Kerberos tickets on affected systems. Force re-authentication. Enable Protected Users group."},
    # NTLM Attacks
    {"type":"NTLM Attack","title":"Pass-the-Hash Attack Detected","keywords":["pass the hash","pth","ntlm hash","hash relay","ntlm relay","credential relay","hash reuse"],"severity":"CRITICAL","tactic":"Lateral Movement","technique":"T1550.002 — Pass the Hash","urgency":"IMMEDIATE","remediation":"Enable Protected Users group. Disable NTLM where possible. Deploy PAM. Enable Windows Defender Credential Guard."},
    {"type":"NTLM Attack","title":"NTLM Relay Attack","keywords":["ntlm relay","responder","llmnr","nbns","ntlm capture","relay attack","smb relay"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1557.001 — LLMNR/NBT-NS Poisoning","urgency":"IMMEDIATE","remediation":"Disable LLMNR and NBT-NS. Enable SMB signing. Deploy EPA (Extended Protection for Authentication)."},
    {"type":"NTLM Attack","title":"Brute Force on NTLM Authentication","keywords":["brute force ntlm","ntlm brute","password spray ntlm","ntlm lockout","multiple ntlm fail"],"severity":"HIGH","tactic":"Credential Access","technique":"T1110 — Brute Force","urgency":"HIGH","remediation":"Enable account lockout policy. Deploy Azure AD Password Protection. Monitor failed NTLM authentications."},
    # MFA Attacks
    {"type":"MFA Attack","title":"MFA Fatigue Attack Detected","keywords":["mfa fatigue","mfa bombing","push bombing","mfa spam","authenticator spam","approve approve approve","mfa flood"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1621 — Multi-Factor Authentication Request Generation","urgency":"IMMEDIATE","remediation":"Enable number matching in MFA. Limit MFA push notifications. Block after 3 failed MFA attempts. Switch to FIDO2."},
    {"type":"MFA Attack","title":"SIM Swapping Attack","keywords":["sim swap","sim swapping","sim hijack","phone number takeover","carrier fraud","mobile account takeover"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1621","urgency":"IMMEDIATE","remediation":"Remove SMS-based MFA. Migrate to authenticator app or hardware key. Contact carrier for port freeze."},
    {"type":"MFA Attack","title":"Adversary-in-the-Middle MFA Bypass","keywords":["aitm","adversary in the middle","evilginx","mfa bypass","session token stolen","reverse proxy phish","token theft"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1557 — Adversary-in-the-Middle","urgency":"IMMEDIATE","remediation":"Enable Conditional Access with compliant device requirement. Use FIDO2 phishing-resistant MFA. Enable token binding."},
    # Privilege Escalation
    {"type":"Privilege Escalation","title":"DCSync Attack Detected","keywords":["dcsync","dc sync","directory replication","drsuapi","domain replication","replicating directory"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1003.006 — DCSync","urgency":"IMMEDIATE","remediation":"Remove unauthorised replication rights. Audit DCSync permissions. Monitor for DS-Replication-Get-Changes events."},
    {"type":"Privilege Escalation","title":"AdminSDHolder Abuse","keywords":["adminsdholder","sdprop","acl abuse","security descriptor","admincount","protected groups"],"severity":"HIGH","tactic":"Persistence","technique":"T1484 — Domain Policy Modification","urgency":"HIGH","remediation":"Audit AdminSDHolder ACL. Remove unauthorised ACEs. Monitor SDProp changes. Implement tiered admin model."},
    {"type":"Privilege Escalation","title":"Domain Admin Account Compromise","keywords":["domain admin compromise","da compromise","domain admin stolen","enterprise admin","schema admin compromise"],"severity":"CRITICAL","tactic":"Privilege Escalation","technique":"T1078.002 — Domain Accounts","urgency":"IMMEDIATE","remediation":"Reset domain admin credentials. Rotate krbtgt. Audit all actions by compromised account. Implement PAW model."},
    # Reconnaissance
    {"type":"Identity Reconnaissance","title":"LDAP Enumeration Detected","keywords":["ldap enum","ldap recon","ad enumeration","bloodhound","sharphound","powerview","ldap query recon"],"severity":"HIGH","tactic":"Discovery","technique":"T1087.002 — Domain Account Discovery","urgency":"HIGH","remediation":"Enable LDAP signing and channel binding. Monitor for bulk LDAP queries. Restrict AD enumeration permissions."},
    {"type":"Identity Reconnaissance","title":"BloodHound AD Reconnaissance","keywords":["bloodhound","sharphound","neo4j","attack path","ad attack path","graph recon","ad graph"],"severity":"HIGH","tactic":"Discovery","technique":"T1087 — Account Discovery","urgency":"HIGH","remediation":"Monitor for BloodHound collection patterns. Enable advanced audit policies. Restrict AD read permissions."},
    # Account Manipulation
    {"type":"Account Manipulation","title":"Unauthorized Group Membership Change","keywords":["group membership","added to admin","domain admins added","group change unauthorized","privilege group add"],"severity":"CRITICAL","tactic":"Persistence","technique":"T1098 — Account Manipulation","urgency":"IMMEDIATE","remediation":"Revert group membership. Investigate who made the change. Enable alerting on privileged group modifications."},
    {"type":"Account Manipulation","title":"Service Account Password Reset","keywords":["service account reset","sa password reset","service account modified","sa modified","krbtgt reset"],"severity":"HIGH","tactic":"Persistence","technique":"T1098","urgency":"HIGH","remediation":"Verify the reset was authorised. If not — treat as active compromise. Rotate affected credentials immediately."},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}
URGENCY_W = {"IMMEDIATE":2.0,"HIGH":1.5,"MEDIUM":1.0,"LOW":0.5}

def run_itdr(description, identity_store):
    desc_lower = description.lower()
    findings = []
    for rule in ITDR_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({
                "attack_type":       rule["type"],
                "title":             rule["title"],
                "severity":          rule["severity"],
                "affected_identity": f"{identity_store.replace('_',' ').title()} Identity",
                "mitre_tactic":      rule["tactic"],
                "mitre_technique":   rule["technique"],
                "description":       f"Identity threat detected: {rule['title']}. This is an active {rule['urgency']} priority threat requiring immediate investigation.",
                "remediation":       rule["remediation"],
                "urgency":           rule["urgency"],
            })
    return findings

def calc_risk(findings):
    if not findings: return 0.0
    raw = sum(SEV_W.get(f["severity"],0) * URGENCY_W.get(f["urgency"],1.0) for f in findings)
    return round(min(raw * 1.2, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@itdr_bp.route("/api/itdr/scan", methods=["POST"])
@jwt_required()
def scan():
    data           = request.get_json(silent=True) or {}
    environment    = data.get("environment", "production")
    identity_store = data.get("identity_store", "active_directory")
    description    = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400
    findings   = run_itdr(description, identity_store)
    score      = calc_risk(findings)
    sev        = overall_sev(score)
    critical   = sum(1 for f in findings if f["severity"] == "CRITICAL")
    immediate  = sum(1 for f in findings if f["urgency"] == "IMMEDIATE")
    compromised= len(set(f["attack_type"] for f in findings))
    summary    = (f"ITDR scan complete for {environment} {identity_store.replace('_',' ').title()}. "
                  f"Risk: {score}/100. {len(findings)} identity threat(s) — {critical} critical, {immediate} immediate. "
                  f"{compromised} attack type(s) detected.")
    s = ITDRScan(user_id=get_jwt_identity(), environment=environment, identity_store=identity_store, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, identities_compromised=compromised, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(ITDRFinding(scan_id=s.id, attack_type=f["attack_type"], title=f["title"], severity=f["severity"], affected_identity=f["affected_identity"], mitre_tactic=f["mitre_tactic"], mitre_technique=f["mitre_technique"], description=f["description"], remediation=f["remediation"], urgency=f["urgency"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"risk_score":score,"severity":sev,"total_findings":len(findings),"critical_count":critical,"immediate_count":immediate,"identities_compromised":compromised,"summary":summary}), 200

@itdr_bp.route("/api/itdr/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = ITDRScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = ITDRFinding.query.filter_by(scan_id=scan_id).all()
    types = list(dict.fromkeys(f.attack_type for f in findings))
    return jsonify({"scan_id":s.id,"environment":s.environment,"identity_store":s.identity_store,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"identities_compromised":s.identities_compromised,"summary":s.summary,"created_at":s.created_at.isoformat(),"attack_types":types,"findings":[{"attack_type":f.attack_type,"title":f.title,"severity":f.severity,"affected_identity":f.affected_identity,"mitre_tactic":f.mitre_tactic,"mitre_technique":f.mitre_technique,"description":f.description,"remediation":f.remediation,"urgency":f.urgency} for f in findings]}), 200

@itdr_bp.route("/api/itdr/history", methods=["GET"])
@jwt_required()
def history():
    scans = ITDRScan.query.filter_by(user_id=get_jwt_identity()).order_by(ITDRScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"environment":s.environment,"identity_store":s.identity_store,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@itdr_bp.route("/api/itdr/health", methods=["GET"])
def health():
    return jsonify({"module":"Identity Threat Detection","version":"1.0.0","rules":len(ITDR_RULES),"status":"operational"}), 200
