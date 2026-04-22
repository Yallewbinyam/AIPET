# ============================================================
# AIPET X — Adversary Profiling Engine
# Threat Actor Attribution | TTP Analysis | Campaign Tracking
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

adversary_profiling_bp = Blueprint("adversary_profiling", __name__)

class AdversaryProfile(db.Model):
    __tablename__ = "adversary_profiles"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    actor_name      = Column(String(256))
    actor_type      = Column(String(64))
    origin          = Column(String(128))
    motivation      = Column(String(128))
    sophistication  = Column(String(32))
    confidence      = Column(Float, default=0.0)
    threat_level    = Column(String(16))
    active_since    = Column(String(32))
    targets         = Column(Text, default="[]")
    ttps            = Column(Text, default="[]")
    summary         = Column(Text)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

ADVERSARY_DB = {
    "apt29": {
        "name":"APT29 (Cozy Bear / Midnight Blizzard)",
        "type":"Nation-State APT",
        "origin":"Russia — SVR (Foreign Intelligence Service)",
        "motivation":"Espionage — Government, Defence, Think Tanks",
        "sophistication":"Very High",
        "active_since":"2008",
        "threat_level":"CRITICAL",
        "keywords":["apt29","cozy bear","nobelium","midnight blizzard","solarwinds","solorigate","wellmess","hammertoss"],
        "targets":["Government","Defence","Healthcare","Think Tanks","Energy","Technology"],
        "ttps":["T1566 Phishing","T1195 Supply Chain","T1078 Valid Accounts","T1027 Obfuscated Files","T1071 C2","T1003 Credential Dump"],
        "known_tools":["SUNBURST","TEARDROP","WellMess","GoldFinder","Cobalt Strike"],
        "recent_campaigns":["SolarWinds 2020","Microsoft Exchange 2021","TeamViewer 2024"],
        "mitigations":["Zero Trust Architecture","MFA Everywhere","Supply Chain Security","Privileged Access Management","Threat Hunting"],
        "description":"APT29 is one of the most sophisticated nation-state threat actors globally. Operating on behalf of Russian SVR, they conduct long-term espionage campaigns with exceptional stealth and patience. Known for the SolarWinds supply chain attack affecting 18,000+ organisations."
    },
    "apt28": {
        "name":"APT28 (Fancy Bear / Forest Blizzard)",
        "type":"Nation-State APT",
        "origin":"Russia — GRU (Military Intelligence)",
        "motivation":"Espionage, Disruption — Government, Military, Elections",
        "sophistication":"Very High",
        "active_since":"2004",
        "threat_level":"CRITICAL",
        "keywords":["apt28","fancy bear","sofacy","forest blizzard","pawn storm","strontium","sednit"],
        "targets":["Government","Military","Elections","NATO","Defence","Media"],
        "ttps":["T1566 Phishing","T1190 Exploit Public App","T1078 Valid Accounts","T1003 Credential Dump","T1041 Exfiltration"],
        "known_tools":["X-Agent","Sofacy","LoJax","CHOPSTICK","GAMEFISH"],
        "recent_campaigns":["DNC Hack 2016","French Election 2017","Bundestag Hack 2021"],
        "mitigations":["Email Security Gateway","MFA","Network Segmentation","Endpoint Detection","Threat Intelligence"],
        "description":"APT28 operates on behalf of Russian GRU military intelligence. Known for election interference operations, targeting NATO members and government entities with sophisticated spearphishing and exploitation campaigns."
    },
    "lazarus": {
        "name":"Lazarus Group (Hidden Cobra / Zinc)",
        "type":"Nation-State APT",
        "origin":"North Korea — RGB (Reconnaissance General Bureau)",
        "motivation":"Financial Gain, Espionage — Crypto, Banking, Defence",
        "sophistication":"High",
        "active_since":"2009",
        "threat_level":"CRITICAL",
        "keywords":["lazarus","hidden cobra","zinc","apt38","north korea","dprk","guardians of peace"],
        "targets":["Financial Institutions","Cryptocurrency","Defence","Healthcare","Government"],
        "ttps":["T1566 Phishing","T1486 Ransomware","T1005 Data Collection","T1041 Exfiltration","T1059 Scripting"],
        "known_tools":["WannaCry","HOPLIGHT","HARDRAIN","AppleJeus","BLINDINGCAN"],
        "recent_campaigns":["WannaCry 2017","Bangladesh Bank Heist","Bybit Crypto Theft 2025"],
        "mitigations":["Crypto Asset Protection","SWIFT Security Controls","Employee Awareness","Network Monitoring","Zero Trust"],
        "description":"Lazarus Group is North Korea primary cyber threat actor focused on financial theft to fund state activities. Responsible for over $3 billion in cryptocurrency theft and the WannaCry ransomware pandemic."
    },
    "apt41": {
        "name":"APT41 (Winnti / Double Dragon)",
        "type":"Nation-State APT + Cybercrime",
        "origin":"China — MSS (Ministry of State Security)",
        "motivation":"Espionage + Financial — Technology, Healthcare, Telecom",
        "sophistication":"Very High",
        "active_since":"2012",
        "threat_level":"CRITICAL",
        "keywords":["apt41","winnti","barium","double dragon","earth baku","bronze atlas"],
        "targets":["Technology","Healthcare","Telecommunications","Video Games","Finance","Government"],
        "ttps":["T1190 Exploit Public App","T1195 Supply Chain","T1078 Valid Accounts","T1027 Obfuscation","T1486 Ransomware"],
        "known_tools":["DUSTPAN","KEYPLUG","LOWKEY","Cobalt Strike","ShadowPad"],
        "recent_campaigns":["SolarWinds adjacent 2021","Healthcare targeting 2023","Gaming industry 2024"],
        "mitigations":["Patch Management","Supply Chain Security","Network Segmentation","DLP Controls","Threat Hunting"],
        "description":"APT41 uniquely conducts both state-sponsored espionage and financially motivated cybercrime. They target intellectual property, personal health information, and conduct supply chain attacks."
    },
    "lockbit": {
        "name":"LockBit Ransomware Group",
        "type":"Ransomware-as-a-Service",
        "origin":"Eastern Europe / Russia-Affiliated",
        "motivation":"Financial — Ransomware Extortion",
        "sophistication":"High",
        "active_since":"2019",
        "threat_level":"CRITICAL",
        "keywords":["lockbit","lockbit 3","lockbit black","lockbit green","lb3"],
        "targets":["All Sectors","Critical Infrastructure","Healthcare","Manufacturing","Finance"],
        "ttps":["T1486 Ransomware","T1078 Valid Accounts","T1190 Exploit","T1021 Remote Services","T1070 Log Clearing"],
        "known_tools":["LockBit 3.0","StealBit","Cobalt Strike","Mimikatz"],
        "recent_campaigns":["ICBC Attack 2023","Boeing 2023","Royal Mail 2023","Fulton County 2024"],
        "mitigations":["Offline Backups","EDR","Network Segmentation","MFA","Patch Management","IR Planning"],
        "description":"LockBit is the most prolific ransomware group globally, operating an affiliate model. Responsible for more attacks than any other ransomware group. Took down briefly in 2024 but quickly resumed operations."
    },
    "blackcat": {
        "name":"BlackCat (ALPHV) Ransomware",
        "type":"Ransomware-as-a-Service",
        "origin":"Eastern Europe",
        "motivation":"Financial — Double Extortion Ransomware",
        "sophistication":"High",
        "active_since":"2021",
        "threat_level":"CRITICAL",
        "keywords":["blackcat","alphv","noberus","ransomware alphv","blackcat ransomware"],
        "targets":["Healthcare","Finance","Critical Infrastructure","Technology","Legal"],
        "ttps":["T1486 Ransomware","T1567 Exfiltration to Cloud","T1190 Exploit","T1078 Valid Accounts"],
        "known_tools":["BlackCat/ALPHV","ExMatter","Cobalt Strike"],
        "recent_campaigns":["MGM Resorts 2023","Change Healthcare 2024","Caesars Entertainment 2023"],
        "mitigations":["Backup Strategy","EDR","Zero Trust","Incident Response Plan","MFA"],
        "description":"BlackCat uses Rust-based malware making it harder to detect. Known for the Change Healthcare attack affecting US healthcare billing for months. Shut down by FBI in 2024 but operators regrouped."
    },
    "volt_typhoon": {
        "name":"Volt Typhoon (Bronze Silhouette)",
        "type":"Nation-State APT",
        "origin":"China — PLA (People Liberation Army)",
        "motivation":"Pre-positioning — Critical Infrastructure Disruption",
        "sophistication":"Very High",
        "active_since":"2021",
        "threat_level":"CRITICAL",
        "keywords":["volt typhoon","bronze silhouette","vanguard panda","living off land critical","ot infrastructure china"],
        "targets":["Critical Infrastructure","Energy","Water","Transport","Communications","Military"],
        "ttps":["T1036 Masquerading","T1078 Valid Accounts","T1133 External Remote Services","T1571 Non-Standard Port"],
        "known_tools":["LOLBins","Custom Web Shells","SOHO Router Malware"],
        "recent_campaigns":["US Critical Infrastructure 2023-2024","Guam Military 2023","Pacific Infrastructure"],
        "mitigations":["OT/IT Segmentation","Privileged Access Management","Network Monitoring","Zero Trust OT","Threat Hunting"],
        "description":"Volt Typhoon is pre-positioning inside US critical infrastructure for potential future disruptive attacks. Uses living-off-the-land techniques to avoid detection. CISA has issued multiple advisories."
    },
    "clop": {
        "name":"Cl0p Ransomware Group (TA505)",
        "type":"Ransomware / Data Extortion",
        "origin":"Eastern Europe — Ukraine-Linked",
        "motivation":"Financial — Mass Exploitation Campaigns",
        "sophistication":"High",
        "active_since":"2019",
        "threat_level":"HIGH",
        "keywords":["cl0p","clop","ta505","fin11","moveit","goanywhere","clop ransomware"],
        "targets":["All Sectors","File Transfer Software Users","Healthcare","Finance","Legal"],
        "ttps":["T1190 Exploit Public App","T1567 Exfiltration","T1486 Ransomware","T1005 Data Collection"],
        "known_tools":["Cl0p","DEWMODE","LEMURLOOT"],
        "recent_campaigns":["MOVEit 2023 (2000+ orgs)","GoAnywhere 2023","Accellion 2021"],
        "mitigations":["Patch File Transfer Software Urgently","Network Monitoring","DLP","Incident Response"],
        "description":"Cl0p specialises in mass exploitation of zero-days in file transfer software. The MOVEit campaign in 2023 affected over 2000 organisations including governments, universities and major corporations."
    },
}

def identify_actor(description):
    desc_lower = description.lower()
    matches = []
    for key, actor in ADVERSARY_DB.items():
        matched = sum(1 for kw in actor["keywords"] if kw in desc_lower)
        if matched > 0:
            confidence = min(matched / len(actor["keywords"]) * 100 * 3, 99.0)
            matches.append((key, actor, round(confidence, 1)))
    matches.sort(key=lambda x: -x[2])
    return matches[:3]

@adversary_profiling_bp.route("/api/adversary-profiling/profile", methods=["POST"])
@jwt_required()
def profile():
    data        = request.get_json(silent=True) or {}
    description = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    matches = identify_actor(description)
    if not matches:
        return jsonify({"actor_found":False,"message":"No known threat actor matched. May be unknown actor or insufficient indicators.","profiles":[]}), 200

    profiles = []
    for key, actor, confidence in matches:
        p = AdversaryProfile(
            user_id=get_jwt_identity(), actor_name=actor["name"], actor_type=actor["type"],
            origin=actor["origin"], motivation=actor["motivation"], sophistication=actor["sophistication"],
            confidence=confidence, threat_level=actor["threat_level"], active_since=actor["active_since"],
            targets=json.dumps(actor["targets"]), ttps=json.dumps(actor["ttps"]),
            summary=actor["description"], node_meta=json.dumps({"tools":actor["known_tools"],"campaigns":actor["recent_campaigns"],"mitigations":actor["mitigations"]})
        )
        db.session.add(p)
        profiles.append({"actor_name":actor["name"],"actor_type":actor["type"],"origin":actor["origin"],"motivation":actor["motivation"],"sophistication":actor["sophistication"],"confidence":confidence,"threat_level":actor["threat_level"],"active_since":actor["active_since"],"targets":actor["targets"],"ttps":actor["ttps"],"known_tools":actor["known_tools"],"recent_campaigns":actor["recent_campaigns"],"mitigations":actor["mitigations"],"description":actor["description"]})

    db.session.commit()
    return jsonify({"actor_found":True,"profiles":profiles,"primary_actor":profiles[0]["actor_name"],"confidence":profiles[0]["confidence"]}), 200

@adversary_profiling_bp.route("/api/adversary-profiling/actors", methods=["GET"])
@jwt_required()
def list_actors():
    return jsonify({"actors":[{"key":k,"name":v["name"],"type":v["type"],"origin":v["origin"],"threat_level":v["threat_level"],"active_since":v["active_since"]} for k,v in ADVERSARY_DB.items()]}), 200

@adversary_profiling_bp.route("/api/adversary-profiling/history", methods=["GET"])
@jwt_required()
def history():
    profiles = AdversaryProfile.query.filter_by(user_id=get_jwt_identity()).order_by(AdversaryProfile.created_at.desc()).limit(50).all()
    return jsonify({"profiles":[{"id":p.id,"actor_name":p.actor_name,"actor_type":p.actor_type,"confidence":p.confidence,"threat_level":p.threat_level,"created_at":p.created_at.isoformat()} for p in profiles]}), 200

@adversary_profiling_bp.route("/api/adversary-profiling/health", methods=["GET"])
def health():
    return jsonify({"module":"Adversary Profiling Engine","version":"1.0.0","actors_in_db":len(ADVERSARY_DB),"status":"operational"}), 200
