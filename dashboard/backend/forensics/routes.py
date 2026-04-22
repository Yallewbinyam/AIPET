# ============================================================
# AIPET X — Module #36: AI Forensics Engine
# IOC Extraction | MITRE ATT&CK Mapping | Timeline Reconstruction
# Phase 5C | v6.2.0
# ============================================================

import re, json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

forensics_bp = Blueprint("forensics", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class ForensicCase(db.Model):
    __tablename__ = "forensic_cases"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    title         = Column(String(256))
    severity      = Column(String(16), default="MEDIUM")
    status        = Column(String(32), default="open")
    risk_score    = Column(Float, default=0.0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at  = Column(DateTime, nullable=True)
    node_meta     = Column(Text, default="{}")
    artifacts     = relationship("ForensicArtifact", backref="case", lazy=True, cascade="all, delete-orphan")
    timeline      = relationship("ForensicTimeline", backref="case", lazy=True, cascade="all, delete-orphan")

class ForensicArtifact(db.Model):
    __tablename__ = "forensic_artifacts"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id       = Column(String(64), ForeignKey("forensic_cases.id"), nullable=False)
    artifact_type = Column(String(32))   # IP | DOMAIN | HASH | CVE | EMAIL | URL
    value         = Column(String(512))
    source        = Column(String(256), nullable=True)
    confidence    = Column(String(16), default="MEDIUM")
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

class ForensicTimeline(db.Model):
    __tablename__ = "forensic_timeline"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id       = Column(String(64), ForeignKey("forensic_cases.id"), nullable=False)
    step          = Column(Integer)
    stage         = Column(String(64))
    description   = Column(Text)
    mitre_tactic  = Column(String(128), nullable=True)
    mitre_technique = Column(String(128), nullable=True)
    severity      = Column(String(16), default="MEDIUM")
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# IOC EXTRACTION ENGINE
# ============================================================

IOC_PATTERNS = [
    {"type": "IP",     "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",                                     "confidence": "HIGH"},
    {"type": "DOMAIN", "pattern": r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|gov|edu|xyz|onion)\b",   "confidence": "MEDIUM"},
    {"type": "HASH_MD5","pattern": r"\b[a-fA-F0-9]{32}\b",                                                "confidence": "HIGH"},
    {"type": "HASH_SHA256","pattern": r"\b[a-fA-F0-9]{64}\b",                                             "confidence": "HIGH"},
    {"type": "CVE",    "pattern": r"CVE-\d{4}-\d{4,7}",                                                   "confidence": "HIGH"},
    {"type": "EMAIL",  "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",           "confidence": "MEDIUM"},
    {"type": "URL",    "pattern": r"https?://[^\s<>]+",                                                    "confidence": "HIGH"},
]

def extract_iocs(text):
    iocs = []
    seen = set()
    for rule in IOC_PATTERNS:
        matches = re.findall(rule["pattern"], text)
        for match in matches:
            if match not in seen:
                seen.add(match)
                iocs.append({"type": rule["type"], "value": match, "confidence": rule["confidence"]})
    return iocs

# ============================================================
# MITRE ATT&CK STAGE CLASSIFIER
# ============================================================

MITRE_RULES = [
    {"keywords": ["nmap","scan","recon","enumerat","fingerprint","ping sweep","port scan"],
     "tactic": "Reconnaissance", "technique": "T1595 — Active Scanning", "stage": "Reconnaissance", "severity": "LOW"},
    {"keywords": ["exploit","payload","shellcode","buffer overflow","metasploit","msfvenom","vulnerability"],
     "tactic": "Initial Access", "technique": "T1190 — Exploit Public-Facing Application", "stage": "Initial Access", "severity": "CRITICAL"},
    {"keywords": ["phishing","spearphish","malicious email","attachment","lure","credential harvest"],
     "tactic": "Initial Access", "technique": "T1566 — Phishing", "stage": "Initial Access", "severity": "HIGH"},
    {"keywords": ["reverse shell","bind shell","nc -e","bash -i","python -c","powershell","cmd.exe"],
     "tactic": "Execution", "technique": "T1059 — Command and Scripting Interpreter", "stage": "Execution", "severity": "CRITICAL"},
    {"keywords": ["cron","startup","registry","service install","persistence","autorun","scheduled task"],
     "tactic": "Persistence", "technique": "T1053 — Scheduled Task/Job", "stage": "Persistence", "severity": "HIGH"},
    {"keywords": ["privilege escalat","sudo","suid","root","administrator","token impersonat","bypass uac"],
     "tactic": "Privilege Escalation", "technique": "T1068 — Exploitation for Privilege Escalation", "stage": "Privilege Escalation", "severity": "CRITICAL"},
    {"keywords": ["mimikatz","credential dump","lsass","hash dump","pass the hash","password spray","brute force"],
     "tactic": "Credential Access", "technique": "T1003 — OS Credential Dumping", "stage": "Credential Access", "severity": "CRITICAL"},
    {"keywords": ["lateral movement","psexec","wmi","rdp","smb","ssh tunnel","pivot"],
     "tactic": "Lateral Movement", "technique": "T1021 — Remote Services", "stage": "Lateral Movement", "severity": "HIGH"},
    {"keywords": ["exfiltrat","data transfer","upload","ftp","dns tunnel","base64 encode","compress archive"],
     "tactic": "Exfiltration", "technique": "T1041 — Exfiltration Over C2 Channel", "stage": "Exfiltration", "severity": "CRITICAL"},
    {"keywords": ["ransomware","encrypt","ransom","bitcoin","tor","c2","command and control","beacon"],
     "tactic": "Command and Control", "technique": "T1071 — Application Layer Protocol", "stage": "Command & Control", "severity": "CRITICAL"},
    {"keywords": ["delete log","clear event","timestomp","obfuscat","anti-forensic","cover track"],
     "tactic": "Defense Evasion", "technique": "T1070 — Indicator Removal", "stage": "Defense Evasion", "severity": "HIGH"},
]

def classify_stages(text):
    text_lower = text.lower()
    matched = []
    seen_stages = set()
    for rule in MITRE_RULES:
        if any(kw in text_lower for kw in rule["keywords"]):
            if rule["stage"] not in seen_stages:
                seen_stages.add(rule["stage"])
                matched.append(rule)
    return matched

# ============================================================
# TIMELINE RECONSTRUCTOR
# ============================================================

STAGE_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Lateral Movement", "Command & Control", "Exfiltration"
]

def reconstruct_timeline(stages, text):
    ordered = sorted(stages, key=lambda s: STAGE_ORDER.index(s["stage"]) if s["stage"] in STAGE_ORDER else 99)
    timeline = []
    base_time = datetime.datetime.utcnow() - datetime.timedelta(hours=len(ordered))
    for i, stage in enumerate(ordered):
        timeline.append({
            "step": i + 1,
            "stage": stage["stage"],
            "mitre_tactic": stage["tactic"],
            "mitre_technique": stage["technique"],
            "severity": stage["severity"],
            "description": f"Attack stage detected: {stage['tactic']} — {stage['technique']}. Keywords matched in submitted evidence.",
            "estimated_time": (base_time + datetime.timedelta(hours=i)).isoformat()
        })
    return timeline

# ============================================================
# RISK SCORER
# ============================================================

SEV_WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}

def calculate_risk(stages, iocs):
    stage_score = sum(SEV_WEIGHTS.get(s["severity"], 0) for s in stages)
    ioc_score   = min(len(iocs) * 2, 30)
    return round(min((stage_score * 2) + ioc_score, 100.0), 1)

def overall_severity(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

# ============================================================
# API ROUTES
# ============================================================

@forensics_bp.route("/api/forensics/investigate", methods=["POST"])
@jwt_required()
def investigate():
    data     = request.get_json(silent=True) or {}
    title    = data.get("title", "Untitled Investigation")
    evidence = data.get("evidence", "")
    source   = data.get("source", "manual")

    if not evidence.strip():
        return jsonify({"error": "No evidence provided"}), 400

    # Run engines
    iocs     = extract_iocs(evidence)
    stages   = classify_stages(evidence)
    timeline = reconstruct_timeline(stages, evidence)
    score    = calculate_risk(stages, iocs)
    sev      = overall_severity(score)

    summary = f"Forensic analysis identified {len(iocs)} IOC(s) and {len(stages)} MITRE ATT&CK stage(s). "               f"Risk score: {score}/100. Severity: {sev}."

    # Persist case
    case = ForensicCase(
        user_id      = get_jwt_identity(),
        title        = title,
        severity     = sev,
        status       = "complete",
        risk_score   = score,
        summary      = summary,
        completed_at = datetime.datetime.utcnow(),
        node_meta    = json.dumps({"source": source})
    )
    db.session.add(case)
    db.session.flush()

    # Persist IOCs as artifacts
    for ioc in iocs:
        db.session.add(ForensicArtifact(
            case_id       = case.id,
            artifact_type = ioc["type"],
            value         = ioc["value"],
            source        = source,
            confidence    = ioc["confidence"],
            node_meta     = "{}"
        ))

    # Persist timeline
    for t in timeline:
        db.session.add(ForensicTimeline(
            case_id         = case.id,
            step            = t["step"],
            stage           = t["stage"],
            description     = t["description"],
            mitre_tactic    = t["mitre_tactic"],
            mitre_technique = t["mitre_technique"],
            severity        = t["severity"],
            node_meta       = "{}"
        ))

    db.session.commit()

    return jsonify({
        "case_id":    case.id,
        "title":      title,
        "severity":   sev,
        "risk_score": score,
        "ioc_count":  len(iocs),
        "stage_count":len(stages),
        "summary":    summary
    }), 200


@forensics_bp.route("/api/forensics/cases/<case_id>", methods=["GET"])
@jwt_required()
def get_case(case_id):
    case = ForensicCase.query.filter_by(id=case_id, user_id=get_jwt_identity()).first()
    if not case:
        return jsonify({"error": "Case not found"}), 404

    artifacts = ForensicArtifact.query.filter_by(case_id=case_id).all()
    timeline  = ForensicTimeline.query.filter_by(case_id=case_id).order_by(ForensicTimeline.step).all()

    return jsonify({
        "case_id":    case.id,
        "title":      case.title,
        "severity":   case.severity,
        "status":     case.status,
        "risk_score": case.risk_score,
        "summary":    case.summary,
        "created_at": case.created_at.isoformat(),
        "artifacts": [{"type": a.artifact_type, "value": a.value, "confidence": a.confidence} for a in artifacts],
        "timeline":  [{"step": t.step, "stage": t.stage, "mitre_tactic": t.mitre_tactic, "mitre_technique": t.mitre_technique, "severity": t.severity, "description": t.description} for t in timeline],
        "ioc_summary": {
            "IP":     sum(1 for a in artifacts if a.artifact_type == "IP"),
            "DOMAIN": sum(1 for a in artifacts if a.artifact_type == "DOMAIN"),
            "HASH":   sum(1 for a in artifacts if "HASH" in a.artifact_type),
            "CVE":    sum(1 for a in artifacts if a.artifact_type == "CVE"),
            "URL":    sum(1 for a in artifacts if a.artifact_type == "URL"),
        }
    }), 200


@forensics_bp.route("/api/forensics/timeline/<case_id>", methods=["GET"])
@jwt_required()
def get_timeline(case_id):
    case = ForensicCase.query.filter_by(id=case_id, user_id=get_jwt_identity()).first()
    if not case:
        return jsonify({"error": "Case not found"}), 404
    timeline = ForensicTimeline.query.filter_by(case_id=case_id).order_by(ForensicTimeline.step).all()
    return jsonify({
        "case_id":  case_id,
        "title":    case.title,
        "timeline": [{"step": t.step, "stage": t.stage, "mitre_tactic": t.mitre_tactic, "mitre_technique": t.mitre_technique, "severity": t.severity, "description": t.description} for t in timeline]
    }), 200


@forensics_bp.route("/api/forensics/history", methods=["GET"])
@jwt_required()
def history():
    cases = ForensicCase.query.filter_by(user_id=get_jwt_identity()).order_by(ForensicCase.created_at.desc()).limit(50).all()
    return jsonify({"cases": [{"case_id": c.id, "title": c.title, "severity": c.severity, "risk_score": c.risk_score, "status": c.status, "created_at": c.created_at.isoformat()} for c in cases]}), 200


@forensics_bp.route("/api/forensics/health", methods=["GET"])
def health():
    return jsonify({"module": "AI Forensics Engine", "version": "1.0.0", "status": "operational"}), 200
