# ============================================================
# AIPET X — Module #41: Global Threat Radar
# Threat Actor Intel | Sector Risk | Geopolitical Mapping
# Phase 5C | v6.2.0
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

threat_radar_bp = Blueprint("threat_radar", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class ThreatRadarReport(db.Model):
    __tablename__ = "threat_radar_reports"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    organisation  = Column(String(256))
    region        = Column(String(64))
    sector        = Column(String(64))
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="MEDIUM")
    threat_count  = Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    threats       = relationship("ThreatRadarThreat", backref="report", lazy=True, cascade="all, delete-orphan")

class ThreatRadarThreat(db.Model):
    __tablename__ = "threat_radar_threats"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id     = Column(String(64), ForeignKey("threat_radar_reports.id"), nullable=False)
    threat_type   = Column(String(64))
    actor         = Column(String(128))
    severity      = Column(String(16))
    confidence    = Column(String(16))
    description   = Column(Text)
    mitigation    = Column(Text, nullable=True)
    mitre_tactic  = Column(String(128), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# THREAT ACTOR INTELLIGENCE DATABASE
# ============================================================

THREAT_ACTORS = {
    "RANSOMWARE": [
        {"actor":"LockBit 3.0","severity":"CRITICAL","confidence":"HIGH","description":"Most prolific ransomware group globally. Targets all sectors with double-extortion tactics. Uses affiliate model.","mitigation":"Implement offline backups, network segmentation, EDR, and patch management. Block known LockBit IOCs.","mitre_tactic":"Impact — T1486 Data Encrypted for Impact"},
        {"actor":"BlackCat (ALPHV)","severity":"CRITICAL","confidence":"HIGH","description":"Sophisticated ransomware-as-a-service group. Uses Rust-based malware. Targets critical infrastructure.","mitigation":"Deploy EDR with behavioural detection. Enforce MFA. Monitor for lateral movement and credential dumping.","mitre_tactic":"Impact — T1486 Data Encrypted for Impact"},
        {"actor":"Cl0p","severity":"HIGH","confidence":"HIGH","description":"Known for mass exploitation of zero-days in file transfer software (MOVEit, GoAnywhere). Data extortion focus.","mitigation":"Patch file transfer systems immediately. Monitor for unauthorised data access and exfiltration attempts.","mitre_tactic":"Exfiltration — T1041"},
        {"actor":"Play Ransomware","severity":"HIGH","confidence":"MEDIUM","description":"Targets MSPs and critical infrastructure. Uses intermittent encryption to evade detection.","mitigation":"Harden RDP access. Implement network monitoring and anomaly detection. Maintain tested backups.","mitre_tactic":"Impact — T1486"},
    ],
    "APT": [
        {"actor":"APT29 (Cozy Bear)","severity":"CRITICAL","confidence":"HIGH","description":"Russian SVR intelligence group. Targets government, defence, healthcare. Known for supply chain attacks (SolarWinds).","mitigation":"Implement Zero Trust architecture. Monitor privileged access. Deploy UEBA and threat hunting capability.","mitre_tactic":"Collection — T1213 Data from Information Repositories"},
        {"actor":"APT41 (Winnti)","severity":"CRITICAL","confidence":"HIGH","description":"Chinese state-sponsored group conducting espionage and financially motivated attacks simultaneously.","mitigation":"Patch internet-facing applications urgently. Monitor for web shells and living-off-the-land techniques.","mitre_tactic":"Initial Access — T1190 Exploit Public-Facing Application"},
        {"actor":"Lazarus Group","severity":"CRITICAL","confidence":"HIGH","description":"North Korean state-sponsored group targeting financial institutions, cryptocurrency and defence contractors.","mitigation":"Implement strict email filtering. Monitor cryptocurrency transactions. Apply SWIFT security controls.","mitre_tactic":"Collection — T1005 Data from Local System"},
        {"actor":"APT28 (Fancy Bear)","severity":"HIGH","confidence":"HIGH","description":"Russian GRU military intelligence. Targets government, military, energy sector with spearphishing and credential theft.","mitigation":"Enforce MFA. Deploy email security gateway. Monitor for credential harvesting and lateral movement.","mitre_tactic":"Credential Access — T1003 OS Credential Dumping"},
        {"actor":"Volt Typhoon","severity":"CRITICAL","confidence":"HIGH","description":"Chinese APT pre-positioning in US critical infrastructure. Uses living-off-the-land techniques to evade detection.","mitigation":"Audit all administrative tools usage. Monitor network traffic for unusual patterns. Harden OT/ICS systems.","mitre_tactic":"Defense Evasion — T1036 Masquerading"},
    ],
    "HACKTIVIST": [
        {"actor":"Anonymous Sudan","severity":"HIGH","confidence":"MEDIUM","description":"DDoS-focused hacktivist group targeting Western organisations. Geopolitically motivated attacks on critical services.","mitigation":"Deploy DDoS mitigation service. Implement rate limiting and WAF. Prepare DDoS response playbook.","mitre_tactic":"Impact — T1498 Network Denial of Service"},
        {"actor":"KillNet","severity":"HIGH","confidence":"MEDIUM","description":"Pro-Russian hacktivist collective conducting DDoS attacks against NATO countries and Western infrastructure.","mitigation":"Enable upstream DDoS protection. Implement CDN with DDoS mitigation. Prepare incident response plan.","mitre_tactic":"Impact — T1498 Network Denial of Service"},
    ],
    "CYBERCRIMINAL": [
        {"actor":"FIN7","severity":"HIGH","confidence":"HIGH","description":"Financially motivated group targeting retail, hospitality and finance. Uses sophisticated phishing and POS malware.","mitigation":"Deploy email security with sandboxing. Implement POS security controls and network segmentation.","mitre_tactic":"Initial Access — T1566 Phishing"},
        {"actor":"TA505","severity":"HIGH","confidence":"MEDIUM","description":"Prolific cybercriminal group distributing banking trojans and ransomware via mass phishing campaigns.","mitigation":"Implement email filtering, employee phishing training, and endpoint protection with behaviour monitoring.","mitre_tactic":"Initial Access — T1566.001 Spearphishing Attachment"},
    ]
}

# ============================================================
# SECTOR RISK DATABASE
# ============================================================

SECTOR_RISKS = {
    "finance": {"risk_modifier":20,"top_threats":["RANSOMWARE","APT","CYBERCRIMINAL"],"sector_note":"Financial sector faces elevated threat from ransomware, BEC fraud, and nation-state espionage targeting SWIFT systems and trading platforms."},
    "healthcare": {"risk_modifier":20,"top_threats":["RANSOMWARE","APT"],"sector_note":"Healthcare is the most targeted sector for ransomware due to critical nature of operations and historically weak security posture."},
    "energy": {"risk_modifier":20,"top_threats":["APT","HACKTIVIST"],"sector_note":"Energy and utilities face nation-state threats targeting OT/ICS infrastructure. Volt Typhoon and Sandworm are active against this sector."},
    "government": {"risk_modifier":20,"top_threats":["APT","HACKTIVIST"],"sector_note":"Government entities face persistent nation-state espionage campaigns and hacktivist DDoS attacks. Data theft is the primary objective."},
    "technology": {"risk_modifier":15,"top_threats":["APT","RANSOMWARE","CYBERCRIMINAL"],"sector_note":"Technology companies face supply chain attacks, IP theft, and ransomware. MSPs are high-value targets as gateways to customer networks."},
    "education": {"risk_modifier":10,"top_threats":["RANSOMWARE","CYBERCRIMINAL"],"sector_note":"Education sector faces ransomware due to large attack surface, limited security budgets, and valuable research data."},
    "retail": {"risk_modifier":10,"top_threats":["CYBERCRIMINAL","RANSOMWARE"],"sector_note":"Retail faces POS malware, e-commerce skimming, and ransomware targeting peak shopping periods."},
    "manufacturing": {"risk_modifier":15,"top_threats":["RANSOMWARE","APT"],"sector_note":"Manufacturing faces ransomware targeting OT environments and APT groups seeking IP theft and supply chain disruption."},
    "legal": {"risk_modifier":15,"top_threats":["RANSOMWARE","APT","CYBERCRIMINAL"],"sector_note":"Legal sector holds highly sensitive client data. Ransomware and data theft pose significant regulatory and reputational risk."},
    "other": {"risk_modifier":5,"top_threats":["RANSOMWARE","CYBERCRIMINAL"],"sector_note":"General threat landscape applies. Ransomware and cybercrime remain the most likely threats for most organisations."},
}

# ============================================================
# REGIONAL THREAT MAPPER
# ============================================================

REGIONAL_THREATS = {
    "uk": {"modifier":10,"note":"UK organisations face elevated threats from Russian APT groups, ransomware affiliates and state-sponsored espionage. NCSC advisories should be monitored regularly."},
    "eu": {"modifier":10,"note":"EU organisations must comply with NIS2. Russian and Chinese APT activity is elevated across EU member states. Critical infrastructure is a primary target."},
    "us": {"modifier":15,"note":"US faces the highest volume of ransomware attacks globally. Chinese APT Volt Typhoon is pre-positioning in critical infrastructure. FBI and CISA advisories are essential."},
    "asia": {"modifier":10,"note":"Asian organisations face North Korean Lazarus Group financial attacks and Chinese APT espionage. Ransomware activity is growing rapidly in the region."},
    "middle_east": {"modifier":10,"note":"Middle East faces hacktivist activity, Iranian APT groups, and ransomware targeting energy and government sectors."},
    "global": {"modifier":5,"note":"Global threat landscape is dominated by ransomware-as-a-service, BEC fraud, and nation-state espionage targeting critical infrastructure."},
}

# ============================================================
# THREAT RADAR ENGINE
# ============================================================

def run_threat_radar(region, sector, org_description):
    region_data = REGIONAL_THREATS.get(region.lower(), REGIONAL_THREATS["global"])
    sector_data = SECTOR_RISKS.get(sector.lower(), SECTOR_RISKS["other"])
    top_threat_types = sector_data["top_threats"]

    threats = []
    for threat_type in top_threat_types:
        actors = THREAT_ACTORS.get(threat_type, [])
        for actor in actors[:2]:
            threats.append({
                "threat_type": threat_type,
                "actor":       actor["actor"],
                "severity":    actor["severity"],
                "confidence":  actor["confidence"],
                "description": actor["description"],
                "mitigation":  actor["mitigation"],
                "mitre_tactic":actor["mitre_tactic"],
            })

    base_score = 40
    sector_bonus  = sector_data["risk_modifier"]
    region_bonus  = region_data["modifier"]
    critical_count = sum(1 for t in threats if t["severity"] == "CRITICAL")
    threat_bonus  = critical_count * 5
    risk_score = min(base_score + sector_bonus + region_bonus + threat_bonus, 100)

    return threats, risk_score, sector_data["sector_note"], region_data["note"]

def overall_severity(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

# ============================================================
# API ROUTES
# ============================================================

@threat_radar_bp.route("/api/threat-radar/scan", methods=["POST"])
@jwt_required()
def scan():
    data         = request.get_json(silent=True) or {}
    organisation = data.get("organisation", "Your Organisation")
    region       = data.get("region", "global")
    sector       = data.get("sector", "other")
    description  = data.get("description", "")

    threats, risk_score, sector_note, region_note = run_threat_radar(region, sector, description)
    sev = overall_severity(risk_score)

    summary = (f"Global Threat Radar scan complete for {organisation} ({sector.title()} sector, {region.upper()} region). "
               f"Risk score: {risk_score}/100. Severity: {sev}. "
               f"{len(threats)} active threat actor(s) identified.")

    report = ThreatRadarReport(
        user_id      = get_jwt_identity(),
        organisation = organisation,
        region       = region,
        sector       = sector,
        risk_score   = risk_score,
        severity     = sev,
        threat_count = len(threats),
        summary      = summary,
        node_meta    = json.dumps({"sector_note": sector_note, "region_note": region_note})
    )
    db.session.add(report)
    db.session.flush()

    for t in threats:
        db.session.add(ThreatRadarThreat(
            report_id   = report.id,
            threat_type = t["threat_type"],
            actor       = t["actor"],
            severity    = t["severity"],
            confidence  = t["confidence"],
            description = t["description"],
            mitigation  = t["mitigation"],
            mitre_tactic= t["mitre_tactic"],
            node_meta   = "{}"
        ))

    db.session.commit()

    return jsonify({
        "report_id":    report.id,
        "organisation": organisation,
        "region":       region,
        "sector":       sector,
        "risk_score":   risk_score,
        "severity":     sev,
        "threat_count": len(threats),
        "summary":      summary
    }), 200

@threat_radar_bp.route("/api/threat-radar/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    report = ThreatRadarReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not report:
        return jsonify({"error": "Report not found"}), 404
    threats = ThreatRadarThreat.query.filter_by(report_id=report_id).all()
    meta = json.loads(report.node_meta)
    return jsonify({
        "report_id":    report.id,
        "organisation": report.organisation,
        "region":       report.region,
        "sector":       report.sector,
        "risk_score":   report.risk_score,
        "severity":     report.severity,
        "threat_count": report.threat_count,
        "summary":      report.summary,
        "sector_note":  meta.get("sector_note",""),
        "region_note":  meta.get("region_note",""),
        "created_at":   report.created_at.isoformat(),
        "threats": [{"threat_type": t.threat_type, "actor": t.actor, "severity": t.severity, "confidence": t.confidence, "description": t.description, "mitigation": t.mitigation, "mitre_tactic": t.mitre_tactic} for t in threats],
        "by_type": {
            "RANSOMWARE":   sum(1 for t in threats if t.threat_type == "RANSOMWARE"),
            "APT":          sum(1 for t in threats if t.threat_type == "APT"),
            "HACKTIVIST":   sum(1 for t in threats if t.threat_type == "HACKTIVIST"),
            "CYBERCRIMINAL":sum(1 for t in threats if t.threat_type == "CYBERCRIMINAL"),
        }
    }), 200

@threat_radar_bp.route("/api/threat-radar/history", methods=["GET"])
@jwt_required()
def history():
    reports = ThreatRadarReport.query.filter_by(user_id=get_jwt_identity()).order_by(ThreatRadarReport.created_at.desc()).limit(50).all()
    return jsonify({"reports": [{"report_id": r.id, "organisation": r.organisation, "region": r.region, "sector": r.sector, "risk_score": r.risk_score, "severity": r.severity, "threat_count": r.threat_count, "created_at": r.created_at.isoformat()} for r in reports]}), 200

@threat_radar_bp.route("/api/threat-radar/health", methods=["GET"])
def health():
    return jsonify({"module": "Global Threat Radar", "version": "1.0.0", "threat_actors": sum(len(v) for v in THREAT_ACTORS.values()), "status": "operational"}), 200
