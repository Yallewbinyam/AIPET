# ============================================================
# AIPET X — Module #39: Cognitive SOC Twin
# Scenario Classification | SOC Playbooks | Threat Actor Profiling
# Phase 5C | v6.2.0
# ============================================================

import re, json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

soc_twin_bp = Blueprint("soc_twin", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class SocTwinSession(db.Model):
    __tablename__ = "soc_twin_sessions"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    scenario_name = Column(String(256))
    scenario_type = Column(String(64))
    threat_actor  = Column(String(128), nullable=True)
    severity      = Column(String(16), default="MEDIUM")
    risk_score    = Column(Float, default=0.0)
    impact_score  = Column(Float, default=0.0)
    status        = Column(String(32), default="complete")
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    actions       = relationship("SocTwinAction", backref="session", lazy=True, cascade="all, delete-orphan")

class SocTwinAction(db.Model):
    __tablename__ = "soc_twin_actions"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id    = Column(String(64), ForeignKey("soc_twin_sessions.id"), nullable=False)
    priority      = Column(Integer)
    phase         = Column(String(64))
    action        = Column(Text)
    owner         = Column(String(128))
    timeframe     = Column(String(64))
    mitre_ref     = Column(String(128), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# SCENARIO CLASSIFIER
# ============================================================

SCENARIOS = [
    {"type":"RANSOMWARE","keywords":["ransomware","ransom","encrypt file","bitcoin","decrypt","ransom note","lockbit","ryuk","conti","blackcat"],"severity":"CRITICAL","risk":95,"impact":90,"threat_actor":"Financially Motivated Ransomware Group"},
    {"type":"DATA_BREACH","keywords":["data breach","exfiltrat","stolen data","data leak","database dump","pii","sensitive data","customer data exposed"],"severity":"CRITICAL","risk":90,"impact":95,"threat_actor":"Unknown Threat Actor / Insider"},
    {"type":"APT","keywords":["apt","advanced persistent","nation state","targeted attack","long term","supply chain attack","zero day","state sponsored"],"severity":"CRITICAL","risk":95,"impact":85,"threat_actor":"Nation-State APT Group"},
    {"type":"INSIDER_THREAT","keywords":["insider","disgruntled","employee","rogue","internal","sabotage","data theft","privileged user","malicious insider"],"severity":"HIGH","risk":80,"impact":85,"threat_actor":"Malicious Insider"},
    {"type":"DDOS","keywords":["ddos","denial of service","flood","volumetric","amplification","botnet","traffic spike","service unavailable","bandwidth"],"severity":"HIGH","risk":70,"impact":80,"threat_actor":"Hacktivist / Botnet Operator"},
    {"type":"PHISHING","keywords":["phishing","spearphish","credential harvest","malicious email","business email compromise","bec","email fraud","fake login"],"severity":"HIGH","risk":75,"impact":70,"threat_actor":"Cybercriminal Group"},
    {"type":"MALWARE","keywords":["malware","trojan","backdoor","rat","rootkit","spyware","keylogger","worm","virus","dropper","loader"],"severity":"HIGH","risk":80,"impact":75,"threat_actor":"Cybercriminal / APT Group"},
    {"type":"CLOUD_BREACH","keywords":["cloud breach","s3 bucket","misconfigured","cloud storage","exposed bucket","cloud access","aws breach","azure breach","gcp breach"],"severity":"HIGH","risk":75,"impact":80,"threat_actor":"Opportunistic Threat Actor"},
    {"type":"SUPPLY_CHAIN","keywords":["supply chain","third party","vendor","software update","dependency","npm package","pypi","solarwinds","3cx"],"severity":"CRITICAL","risk":90,"impact":90,"threat_actor":"Nation-State / Sophisticated APT"},
    {"type":"CREDENTIAL_ATTACK","keywords":["credential","brute force","password spray","stuffing","account takeover","ato","stolen credential","dark web"],"severity":"HIGH","risk":70,"impact":65,"threat_actor":"Cybercriminal Group"},
]

DEFAULT_SCENARIO = {"type":"UNKNOWN","severity":"MEDIUM","risk":50,"impact":50,"threat_actor":"Unknown Threat Actor"}

def classify_scenario(text):
    text_lower = text.lower()
    for scenario in SCENARIOS:
        if any(kw in text_lower for kw in scenario["keywords"]):
            return scenario
    return DEFAULT_SCENARIO

# ============================================================
# SOC PLAYBOOK ENGINE
# ============================================================

PLAYBOOKS = {
    "RANSOMWARE": [
        {"priority":1,"phase":"Immediate","action":"Isolate all affected systems from the network immediately. Disconnect from LAN and Wi-Fi.","owner":"SOC Tier 1","timeframe":"0-15 mins","mitre_ref":"RS.MI-1"},
        {"priority":2,"phase":"Immediate","action":"Alert CISO, IT leadership and legal team. Activate incident response plan.","owner":"Incident Commander","timeframe":"0-15 mins","mitre_ref":None},
        {"priority":3,"phase":"Containment","action":"Identify patient zero and ransomware variant. Preserve memory and disk images for forensics.","owner":"SOC Tier 2 / Forensics","timeframe":"15-60 mins","mitre_ref":"T1486"},
        {"priority":4,"phase":"Containment","action":"Block C2 IP addresses and domains at firewall and DNS level.","owner":"Network Security","timeframe":"15-60 mins","mitre_ref":"T1071"},
        {"priority":5,"phase":"Eradication","action":"Restore systems from clean backups. Verify backup integrity before restoration.","owner":"IT Operations","timeframe":"1-24 hrs","mitre_ref":None},
        {"priority":6,"phase":"Recovery","action":"Re-image compromised endpoints. Apply all patches before reconnecting to network.","owner":"IT Operations","timeframe":"1-48 hrs","mitre_ref":None},
        {"priority":7,"phase":"Post-Incident","action":"Notify regulators and affected parties per legal obligations. Conduct post-mortem.","owner":"Legal / Compliance","timeframe":"24-72 hrs","mitre_ref":None},
    ],
    "DATA_BREACH": [
        {"priority":1,"phase":"Immediate","action":"Identify scope of breach — what data, how many records, which systems affected.","owner":"SOC Tier 2","timeframe":"0-30 mins","mitre_ref":"T1041"},
        {"priority":2,"phase":"Immediate","action":"Revoke compromised credentials and API keys. Force password resets for affected accounts.","owner":"IAM Team","timeframe":"0-30 mins","mitre_ref":None},
        {"priority":3,"phase":"Containment","action":"Block exfiltration channels — suspicious IPs, domains, cloud storage endpoints.","owner":"Network Security","timeframe":"15-60 mins","mitre_ref":"T1567"},
        {"priority":4,"phase":"Containment","action":"Preserve logs and evidence for forensic investigation and legal proceedings.","owner":"Forensics Team","timeframe":"1-2 hrs","mitre_ref":None},
        {"priority":5,"phase":"Notification","action":"Notify DPA within 72 hours if personal data is involved (GDPR Article 33).","owner":"DPO / Legal","timeframe":"Within 72 hrs","mitre_ref":None},
        {"priority":6,"phase":"Eradication","action":"Patch the vulnerability exploited. Conduct full security review of affected systems.","owner":"Security Engineering","timeframe":"24-48 hrs","mitre_ref":None},
        {"priority":7,"phase":"Post-Incident","action":"Notify affected individuals if high risk to their rights. Implement DLP controls.","owner":"Legal / DPO","timeframe":"72 hrs+","mitre_ref":None},
    ],
    "APT": [
        {"priority":1,"phase":"Detection","action":"Activate threat hunting team. Search for IOCs across all endpoints and network logs.","owner":"Threat Hunting / SOC Tier 3","timeframe":"0-1 hr","mitre_ref":"T1595"},
        {"priority":2,"phase":"Containment","action":"Isolate suspected compromised systems. Do not alert attacker — maintain stealth observation.","owner":"SOC Tier 2","timeframe":"1-4 hrs","mitre_ref":None},
        {"priority":3,"phase":"Investigation","action":"Map full attack timeline using MITRE ATT&CK framework. Identify all persistence mechanisms.","owner":"Forensics / Threat Intel","timeframe":"4-24 hrs","mitre_ref":None},
        {"priority":4,"phase":"Eradication","action":"Remove all backdoors, implants and persistence mechanisms simultaneously to prevent re-entry.","owner":"Security Engineering","timeframe":"24-72 hrs","mitre_ref":"T1053"},
        {"priority":5,"phase":"Hardening","action":"Reset all credentials, rotate all secrets, review and tighten all IAM policies.","owner":"IAM / Security Engineering","timeframe":"24-48 hrs","mitre_ref":None},
        {"priority":6,"phase":"Post-Incident","action":"Brief senior leadership and board. Consider government notification for nation-state attacks.","owner":"CISO / Legal","timeframe":"48-72 hrs","mitre_ref":None},
    ],
    "INSIDER_THREAT": [
        {"priority":1,"phase":"Immediate","action":"Revoke all access for suspected insider immediately. Preserve audit logs before deletion.","owner":"IAM / HR","timeframe":"0-15 mins","mitre_ref":None},
        {"priority":2,"phase":"Investigation","action":"Collect and preserve all digital evidence — emails, file access logs, USB activity, SIEM data.","owner":"Forensics / Legal","timeframe":"0-2 hrs","mitre_ref":None},
        {"priority":3,"phase":"Containment","action":"Identify all data accessed, copied or transmitted by the insider. Quantify the damage.","owner":"SOC Tier 2","timeframe":"1-4 hrs","mitre_ref":"T1052"},
        {"priority":4,"phase":"Legal","action":"Engage legal counsel. Determine if law enforcement notification is required.","owner":"Legal / HR","timeframe":"2-24 hrs","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Review and tighten insider threat monitoring controls. Implement UEBA if not present.","owner":"Security Engineering","timeframe":"1-2 weeks","mitre_ref":None},
    ],
    "DDOS": [
        {"priority":1,"phase":"Immediate","action":"Activate DDoS mitigation service (Cloudflare, Akamai, AWS Shield). Enable rate limiting.","owner":"Network / Cloud Team","timeframe":"0-15 mins","mitre_ref":None},
        {"priority":2,"phase":"Containment","action":"Block attacking IP ranges at upstream provider and WAF. Enable geo-blocking if applicable.","owner":"Network Security","timeframe":"15-30 mins","mitre_ref":None},
        {"priority":3,"phase":"Communication","action":"Notify affected customers and stakeholders. Publish status page update.","owner":"Comms / Customer Success","timeframe":"15-30 mins","mitre_ref":None},
        {"priority":4,"phase":"Analysis","action":"Capture traffic samples for forensic analysis. Identify attack vector and botnet source.","owner":"SOC Tier 2","timeframe":"30-60 mins","mitre_ref":"T1498"},
        {"priority":5,"phase":"Post-Incident","action":"Increase capacity and implement permanent DDoS protection. Review SLA obligations.","owner":"Architecture / Legal","timeframe":"24-48 hrs","mitre_ref":None},
    ],
    "PHISHING": [
        {"priority":1,"phase":"Immediate","action":"Pull the phishing email from all mailboxes using email security gateway. Block sender domain.","owner":"Email Security / SOC","timeframe":"0-15 mins","mitre_ref":"T1566"},
        {"priority":2,"phase":"Containment","action":"Identify all users who clicked the link or opened the attachment. Reset their credentials.","owner":"SOC Tier 1 / IAM","timeframe":"15-30 mins","mitre_ref":None},
        {"priority":3,"phase":"Investigation","action":"Analyse the phishing payload. Check for malware installation or credential harvesting.","owner":"SOC Tier 2 / Malware Analysis","timeframe":"30-60 mins","mitre_ref":None},
        {"priority":4,"phase":"Communication","action":"Warn all staff about the phishing campaign. Issue targeted security awareness reminder.","owner":"Security Awareness Team","timeframe":"30-60 mins","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Update email filtering rules. Consider DMARC enforcement and phishing simulation training.","owner":"Security Engineering","timeframe":"24-48 hrs","mitre_ref":None},
    ],
    "MALWARE": [
        {"priority":1,"phase":"Immediate","action":"Isolate infected endpoint(s). Prevent lateral spread via network segmentation.","owner":"SOC Tier 1","timeframe":"0-15 mins","mitre_ref":None},
        {"priority":2,"phase":"Investigation","action":"Extract malware sample for analysis. Submit to sandbox (e.g. Any.run, Joe Sandbox).","owner":"Malware Analyst","timeframe":"15-60 mins","mitre_ref":"T1204"},
        {"priority":3,"phase":"Containment","action":"Block malware C2 infrastructure at firewall and DNS. Update EDR signatures.","owner":"Network Security / EDR Team","timeframe":"15-60 mins","mitre_ref":"T1071"},
        {"priority":4,"phase":"Eradication","action":"Re-image infected endpoints. Restore from clean backup. Verify no persistence remains.","owner":"IT Operations","timeframe":"1-24 hrs","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Update threat intel feeds with new IOCs. Share with ISAC if applicable.","owner":"Threat Intel Team","timeframe":"24-48 hrs","mitre_ref":None},
    ],
    "CLOUD_BREACH": [
        {"priority":1,"phase":"Immediate","action":"Revoke exposed cloud credentials. Rotate all access keys and service account tokens.","owner":"Cloud Security / IAM","timeframe":"0-15 mins","mitre_ref":None},
        {"priority":2,"phase":"Containment","action":"Enable S3 Block Public Access. Restrict misconfigured storage buckets and APIs immediately.","owner":"Cloud Security","timeframe":"15-30 mins","mitre_ref":"T1530"},
        {"priority":3,"phase":"Investigation","action":"Review CloudTrail / Azure Monitor / GCP Audit logs for unauthorised access and data access.","owner":"SOC Tier 2","timeframe":"15-60 mins","mitre_ref":None},
        {"priority":4,"phase":"Eradication","action":"Run cloud security posture scan. Fix all misconfigurations identified.","owner":"Cloud Security Engineering","timeframe":"1-24 hrs","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Implement CSPM tool. Enable alerts for public storage and privilege escalation.","owner":"Cloud Architecture","timeframe":"24-48 hrs","mitre_ref":None},
    ],
    "SUPPLY_CHAIN": [
        {"priority":1,"phase":"Immediate","action":"Identify all systems using the compromised vendor/package. Quarantine immediately.","owner":"SOC / IT Operations","timeframe":"0-30 mins","mitre_ref":"T1195"},
        {"priority":2,"phase":"Containment","action":"Block updates from the compromised source. Pin to last known good version.","owner":"DevOps / Security Engineering","timeframe":"15-60 mins","mitre_ref":None},
        {"priority":3,"phase":"Investigation","action":"Analyse the compromised package/update for malicious code and persistence mechanisms.","owner":"Malware Analyst / AppSec","timeframe":"1-4 hrs","mitre_ref":None},
        {"priority":4,"phase":"Eradication","action":"Remove compromised software. Re-image affected systems. Rotate all credentials.","owner":"IT Operations / IAM","timeframe":"4-24 hrs","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Implement SBOM tracking. Enforce code signing. Add supplier security assessment requirements.","owner":"Security Architecture","timeframe":"1-2 weeks","mitre_ref":None},
    ],
    "CREDENTIAL_ATTACK": [
        {"priority":1,"phase":"Immediate","action":"Lock targeted accounts. Enable CAPTCHA and IP rate limiting on login endpoints.","owner":"IAM / SOC Tier 1","timeframe":"0-15 mins","mitre_ref":"T1110"},
        {"priority":2,"phase":"Containment","action":"Block attacking IP ranges. Enable geo-blocking if attack originates from specific regions.","owner":"Network Security","timeframe":"15-30 mins","mitre_ref":None},
        {"priority":3,"phase":"Investigation","action":"Identify compromised accounts. Check for successful logins from attacker IPs.","owner":"SOC Tier 2","timeframe":"15-60 mins","mitre_ref":None},
        {"priority":4,"phase":"Eradication","action":"Force password reset for all affected accounts. Enforce MFA immediately.","owner":"IAM Team","timeframe":"1-2 hrs","mitre_ref":None},
        {"priority":5,"phase":"Post-Incident","action":"Deploy identity threat detection. Monitor dark web for exposed credentials.","owner":"Threat Intel / IAM","timeframe":"24-48 hrs","mitre_ref":None},
    ],
    "UNKNOWN": [
        {"priority":1,"phase":"Immediate","action":"Gather more information about the incident. Classify the threat type before proceeding.","owner":"SOC Tier 1","timeframe":"0-30 mins","mitre_ref":None},
        {"priority":2,"phase":"Containment","action":"Apply general containment — isolate affected systems, preserve logs, alert security team.","owner":"SOC Team","timeframe":"0-1 hr","mitre_ref":None},
        {"priority":3,"phase":"Investigation","action":"Engage SOC Tier 2 and threat intelligence team for deeper analysis.","owner":"SOC Tier 2 / Threat Intel","timeframe":"1-4 hrs","mitre_ref":None},
    ]
}

def get_playbook(scenario_type):
    return PLAYBOOKS.get(scenario_type, PLAYBOOKS["UNKNOWN"])

def overall_severity(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 60: return "HIGH"
    if risk >= 35: return "MEDIUM"
    return "LOW"

# ============================================================
# API ROUTES
# ============================================================

@soc_twin_bp.route("/api/soc-twin/simulate", methods=["POST"])
@jwt_required()
def simulate():
    data     = request.get_json(silent=True) or {}
    scenario_name = data.get("scenario_name", "Unnamed Incident")
    description   = data.get("description", "")

    if not description.strip():
        return jsonify({"error": "No incident description provided"}), 400

    scenario = classify_scenario(description)
    playbook = get_playbook(scenario["type"])
    sev      = overall_severity(scenario["risk"])

    summary = (f"SOC Twin simulation complete. Scenario classified as: {scenario['type'].replace('_',' ')}. "
               f"Threat actor profile: {scenario['threat_actor']}. "
               f"Risk: {scenario['risk']}/100. {len(playbook)} response action(s) generated.")

    session = SocTwinSession(
        user_id       = get_jwt_identity(),
        scenario_name = scenario_name,
        scenario_type = scenario["type"],
        threat_actor  = scenario["threat_actor"],
        severity      = sev,
        risk_score    = scenario["risk"],
        impact_score  = scenario["impact"],
        status        = "complete",
        summary       = summary,
        node_meta     = "{}"
    )
    db.session.add(session)
    db.session.flush()

    for a in playbook:
        db.session.add(SocTwinAction(
            session_id = session.id,
            priority   = a["priority"],
            phase      = a["phase"],
            action     = a["action"],
            owner      = a["owner"],
            timeframe  = a["timeframe"],
            mitre_ref  = a.get("mitre_ref"),
            node_meta  = "{}"
        ))

    db.session.commit()

    return jsonify({
        "session_id":    session.id,
        "scenario_type": scenario["type"],
        "threat_actor":  scenario["threat_actor"],
        "severity":      sev,
        "risk_score":    scenario["risk"],
        "impact_score":  scenario["impact"],
        "action_count":  len(playbook),
        "summary":       summary
    }), 200

@soc_twin_bp.route("/api/soc-twin/sessions/<session_id>", methods=["GET"])
@jwt_required()
def get_session(session_id):
    session = SocTwinSession.query.filter_by(id=session_id, user_id=get_jwt_identity()).first()
    if not session:
        return jsonify({"error": "Session not found"}), 404
    actions = SocTwinAction.query.filter_by(session_id=session_id).order_by(SocTwinAction.priority).all()
    return jsonify({
        "session_id":    session.id,
        "scenario_name": session.scenario_name,
        "scenario_type": session.scenario_type,
        "threat_actor":  session.threat_actor,
        "severity":      session.severity,
        "risk_score":    session.risk_score,
        "impact_score":  session.impact_score,
        "summary":       session.summary,
        "created_at":    session.created_at.isoformat(),
        "actions": [{"priority": a.priority, "phase": a.phase, "action": a.action, "owner": a.owner, "timeframe": a.timeframe, "mitre_ref": a.mitre_ref} for a in actions],
        "phases": list(dict.fromkeys(a.phase for a in actions))
    }), 200

@soc_twin_bp.route("/api/soc-twin/history", methods=["GET"])
@jwt_required()
def history():
    sessions = SocTwinSession.query.filter_by(user_id=get_jwt_identity()).order_by(SocTwinSession.created_at.desc()).limit(50).all()
    return jsonify({"sessions": [{"session_id": s.id, "scenario_name": s.scenario_name, "scenario_type": s.scenario_type, "severity": s.severity, "risk_score": s.risk_score, "created_at": s.created_at.isoformat()} for s in sessions]}), 200

@soc_twin_bp.route("/api/soc-twin/health", methods=["GET"])
def health():
    return jsonify({"module": "Cognitive SOC Twin", "version": "1.0.0", "scenarios": [s["type"] for s in SCENARIOS], "status": "operational"}), 200
