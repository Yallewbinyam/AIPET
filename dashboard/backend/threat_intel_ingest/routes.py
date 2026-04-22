# ============================================================
# AIPET X — Threat Intelligence Ingestion
# IOC Processing | TTP Mapping | Feed Management
# ============================================================

import json, uuid, datetime, re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

threat_intel_ingest_bp = Blueprint("threat_intel_ingest", __name__)

class ThreatIntelFeed(db.Model):
    __tablename__ = "threat_intel_feeds"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    feed_name     = Column(String(256))
    feed_type     = Column(String(64))
    total_iocs    = Column(Integer, default=0)
    critical_iocs = Column(Integer, default=0)
    threat_actors = Column(Integer, default=0)
    ttps_mapped   = Column(Integer, default=0)
    risk_score    = Column(Float, default=0.0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    iocs          = relationship("ThreatIntelIOC", backref="feed", lazy=True, cascade="all, delete-orphan")

class ThreatIntelIOC(db.Model):
    __tablename__ = "threat_intel_iocs"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    feed_id       = Column(String(64), ForeignKey("threat_intel_feeds.id"), nullable=False)
    ioc_type      = Column(String(32))
    ioc_value     = Column(String(512))
    severity      = Column(String(16))
    confidence    = Column(String(16))
    threat_actor  = Column(String(128), nullable=True)
    ttp           = Column(String(128), nullable=True)
    description   = Column(Text)
    first_seen    = Column(String(32), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

IOC_PATTERNS = [
    {"type":"IP Address","pattern":r"\b(?:\d{1,3}\.){3}\d{1,3}\b","severity":"HIGH","confidence":"HIGH"},
    {"type":"Domain","pattern":r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|onion|ru|cn|tk)\b","severity":"MEDIUM","confidence":"MEDIUM"},
    {"type":"URL","pattern":r"https?://[^\s<>]{8,}","severity":"HIGH","confidence":"HIGH"},
    {"type":"MD5 Hash","pattern":r"\b[a-fA-F0-9]{32}\b","severity":"HIGH","confidence":"HIGH"},
    {"type":"SHA256 Hash","pattern":r"\b[a-fA-F0-9]{64}\b","severity":"CRITICAL","confidence":"HIGH"},
    {"type":"CVE","pattern":r"CVE-\d{4}-\d{4,7}","severity":"HIGH","confidence":"HIGH"},
    {"type":"Email","pattern":r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b","severity":"MEDIUM","confidence":"MEDIUM"},
    {"type":"Registry Key","pattern":r"HKEY_[A-Z_]+\\[\w\\]+","severity":"HIGH","confidence":"HIGH"},
    {"type":"File Path","pattern":r"(?:[A-Za-z]:\\|/(?:tmp|var|etc|usr)/)[\w/\\.\-]+","severity":"MEDIUM","confidence":"MEDIUM"},
]

THREAT_ACTOR_KEYWORDS = {
    "APT29": ["cozy bear","apt29","nobelium","midnight blizzard","solarwinds","solorigate"],
    "APT28": ["fancy bear","apt28","sofacy","forest blizzard","pawn storm"],
    "Lazarus Group": ["lazarus","hidden cobra","zinc","apt38","north korea"],
    "APT41": ["winnti","apt41","barium","double dragon","china nexus"],
    "LockBit": ["lockbit","lockbit 3","lockbit 2","lockbit black"],
    "BlackCat": ["blackcat","alphv","noberus"],
    "Cl0p": ["cl0p","clop","ta505","fin11"],
    "Volt Typhoon": ["volt typhoon","bronze silhouette","vanguard panda"],
    "Anonymous Sudan": ["anonymous sudan","killnet","pro-russian hacktivist"],
    "FIN7": ["fin7","carbanak","navigator group","sangria tempest"],
}

TTP_KEYWORDS = {
    "T1566 Phishing": ["phishing","spearphish","malicious email","credential harvest"],
    "T1486 Ransomware": ["ransomware","encrypt","ransom","lockbit","blackcat"],
    "T1003 Credential Dump": ["credential dump","mimikatz","lsass","dcsync","ntds"],
    "T1190 Exploit Public App": ["exploit","cve","rce","remote code execution","vulnerability exploit"],
    "T1071 C2 Communication": ["c2","command and control","beacon","cobalt strike","metasploit"],
    "T1055 Process Injection": ["injection","dll inject","process hollow","shellcode"],
    "T1041 Exfiltration": ["exfiltrate","data theft","exfiltration","data leak"],
    "T1078 Valid Accounts": ["credential stuffing","account takeover","stolen credential","valid account"],
}

def extract_iocs(text):
    iocs = []
    seen = set()
    for pattern_info in IOC_PATTERNS:
        matches = re.findall(pattern_info["pattern"], text)
        for match in matches:
            if match not in seen and len(match) > 4:
                seen.add(match)
                iocs.append({
                    "ioc_type":    pattern_info["type"],
                    "ioc_value":   match,
                    "severity":    pattern_info["severity"],
                    "confidence":  pattern_info["confidence"],
                    "threat_actor": None,
                    "ttp":         None,
                    "description": f"{pattern_info['type']} indicator of compromise extracted from threat intelligence feed.",
                    "first_seen":  datetime.datetime.utcnow().strftime("%Y-%m-%d"),
                })
    return iocs

def detect_threat_actors(text):
    text_lower = text.lower()
    detected = []
    for actor, keywords in THREAT_ACTOR_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            detected.append(actor)
    return detected

def map_ttps(text):
    text_lower = text.lower()
    mapped = []
    for ttp, keywords in TTP_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            mapped.append(ttp)
    return mapped

def calc_risk(iocs, actors, ttps):
    sev_w = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}
    ioc_score = min(sum(sev_w.get(i["severity"],0) for i in iocs[:10])*1.5, 60)
    actor_score = min(len(actors) * 15, 25)
    ttp_score = min(len(ttps) * 5, 15)
    return round(min(ioc_score + actor_score + ttp_score, 100.0), 1)

@threat_intel_ingest_bp.route("/api/threat-intel-ingest/process", methods=["POST"])
@jwt_required()
def process():
    data      = request.get_json(silent=True) or {}
    feed_name = data.get("feed_name", "Manual Intel Feed")
    feed_type = data.get("feed_type", "manual")
    raw_intel = data.get("raw_intel", "")
    if not raw_intel.strip(): return jsonify({"error":"No intelligence data provided"}), 400

    iocs   = extract_iocs(raw_intel)
    actors = detect_threat_actors(raw_intel)
    ttps   = map_ttps(raw_intel)
    score  = calc_risk(iocs, actors, ttps)
    critical = sum(1 for i in iocs if i["severity"]=="CRITICAL")

    # Tag IOCs with actors and TTPs
    for ioc in iocs:
        if actors: ioc["threat_actor"] = actors[0]
        if ttps:   ioc["ttp"] = ttps[0]

    summary = (f"Threat Intel ingestion complete for {feed_name}. "
               f"{len(iocs)} IOC(s) extracted — {critical} critical. "
               f"{len(actors)} threat actor(s) identified: {', '.join(actors[:3]) if actors else 'Unknown'}. "
               f"{len(ttps)} TTP(s) mapped to MITRE ATT&CK.")

    f = ThreatIntelFeed(user_id=get_jwt_identity(), feed_name=feed_name, feed_type=feed_type, total_iocs=len(iocs), critical_iocs=critical, threat_actors=len(actors), ttps_mapped=len(ttps), risk_score=score, summary=summary, node_meta=json.dumps({"actors":actors,"ttps":ttps}))
    db.session.add(f); db.session.flush()

    for ioc in iocs[:50]:
        db.session.add(ThreatIntelIOC(feed_id=f.id, ioc_type=ioc["ioc_type"], ioc_value=ioc["ioc_value"], severity=ioc["severity"], confidence=ioc["confidence"], threat_actor=ioc["threat_actor"], ttp=ioc["ttp"], description=ioc["description"], first_seen=ioc["first_seen"], node_meta="{}"))

    db.session.commit()
    return jsonify({"feed_id":f.id,"feed_name":feed_name,"total_iocs":len(iocs),"critical_iocs":critical,"threat_actors":actors,"ttps_mapped":ttps,"risk_score":score,"summary":summary}), 200

@threat_intel_ingest_bp.route("/api/threat-intel-ingest/feeds/<feed_id>", methods=["GET"])
@jwt_required()
def get_feed(feed_id):
    f = ThreatIntelFeed.query.filter_by(id=feed_id, user_id=get_jwt_identity()).first()
    if not f: return jsonify({"error":"Not found"}), 404
    iocs = ThreatIntelIOC.query.filter_by(feed_id=feed_id).all()
    meta = json.loads(f.node_meta)
    return jsonify({"feed_id":f.id,"feed_name":f.feed_name,"feed_type":f.feed_type,"total_iocs":f.total_iocs,"critical_iocs":f.critical_iocs,"threat_actors":meta.get("actors",[]),"ttps_mapped":meta.get("ttps",[]),"risk_score":f.risk_score,"summary":f.summary,"created_at":f.created_at.isoformat(),"iocs":[{"ioc_type":i.ioc_type,"ioc_value":i.ioc_value,"severity":i.severity,"confidence":i.confidence,"threat_actor":i.threat_actor,"ttp":i.ttp,"description":i.description,"first_seen":i.first_seen} for i in iocs]}), 200

@threat_intel_ingest_bp.route("/api/threat-intel-ingest/history", methods=["GET"])
@jwt_required()
def history():
    feeds = ThreatIntelFeed.query.filter_by(user_id=get_jwt_identity()).order_by(ThreatIntelFeed.created_at.desc()).limit(50).all()
    return jsonify({"feeds":[{"feed_id":f.id,"feed_name":f.feed_name,"feed_type":f.feed_type,"total_iocs":f.total_iocs,"critical_iocs":f.critical_iocs,"threat_actors":f.threat_actors,"risk_score":f.risk_score,"created_at":f.created_at.isoformat()} for f in feeds]}), 200

@threat_intel_ingest_bp.route("/api/threat-intel-ingest/health", methods=["GET"])
def health():
    return jsonify({"module":"Threat Intelligence Ingestion","version":"1.0.0","ioc_patterns":len(IOC_PATTERNS),"threat_actors":len(THREAT_ACTOR_KEYWORDS),"ttps":len(TTP_KEYWORDS),"status":"operational"}), 200
