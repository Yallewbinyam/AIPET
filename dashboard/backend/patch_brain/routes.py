# ============================================================
# AIPET X — Module #43: Autonomous Patch Brain
# CVE Prioritisation | Patch Scheduling | Risk Scoring
# Phase 5C | v6.2.0
# ============================================================

import re, json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

patch_brain_bp = Blueprint("patch_brain", __name__)

class PatchBrainSession(db.Model):
    __tablename__ = "patch_brain_sessions"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    environment   = Column(String(64))
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="LOW")
    total_patches = Column(Integer, default=0)
    critical_count= Column(Integer, default=0)
    high_count    = Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    patches       = relationship("PatchBrainItem", backref="session", lazy=True, cascade="all, delete-orphan")

class PatchBrainItem(db.Model):
    __tablename__ = "patch_brain_items"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id    = Column(String(64), ForeignKey("patch_brain_sessions.id"), nullable=False)
    cve_id        = Column(String(32), nullable=True)
    component     = Column(String(256))
    current_version=Column(String(64))
    fixed_version = Column(String(64))
    severity      = Column(String(16))
    cvss_score    = Column(Float, default=0.0)
    priority      = Column(Integer)
    patch_action  = Column(Text)
    deadline      = Column(String(64))
    exploited     = Column(Integer, default=0)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

VULN_DB = {
    "pip": [
        {"kw":["django"],"cve":"CVE-2023-36053","component":"Django","current":"3.2.0","fixed":"4.2.1","severity":"HIGH","cvss":7.5,"exploited":0,"action":"pip install --upgrade django>=4.2.1","deadline":"7 days"},
        {"kw":["flask"],"cve":"CVE-2023-30861","component":"Flask","current":"2.0.0","fixed":"2.3.2","severity":"MEDIUM","cvss":5.9,"exploited":0,"action":"pip install --upgrade flask>=2.3.2","deadline":"30 days"},
        {"kw":["requests"],"cve":"CVE-2023-32681","component":"Requests","current":"2.28.0","fixed":"2.31.0","severity":"MEDIUM","cvss":6.1,"exploited":0,"action":"pip install --upgrade requests>=2.31.0","deadline":"30 days"},
        {"kw":["pyyaml","yaml"],"cve":"CVE-2020-14343","component":"PyYAML","current":"5.3.0","fixed":"6.0.0","severity":"CRITICAL","cvss":9.8,"exploited":1,"action":"pip install --upgrade pyyaml>=6.0.0","deadline":"Immediate"},
        {"kw":["cryptography"],"cve":"CVE-2023-49083","component":"cryptography","current":"40.0.0","fixed":"41.0.6","severity":"HIGH","cvss":7.4,"exploited":0,"action":"pip install --upgrade cryptography>=41.0.6","deadline":"7 days"},
        {"kw":["pillow"],"cve":"CVE-2023-44271","component":"Pillow","current":"9.0.0","fixed":"10.0.1","severity":"HIGH","cvss":7.5,"exploited":0,"action":"pip install --upgrade pillow>=10.0.1","deadline":"7 days"},
        {"kw":["sqlalchemy"],"cve":"CVE-2019-7164","component":"SQLAlchemy","current":"1.3.0","fixed":"2.0.0","severity":"MEDIUM","cvss":5.3,"exploited":0,"action":"pip install --upgrade sqlalchemy>=2.0.0","deadline":"30 days"},
        {"kw":["paramiko"],"cve":"CVE-2023-48795","component":"Paramiko","current":"2.11.0","fixed":"3.4.0","severity":"MEDIUM","cvss":5.9,"exploited":0,"action":"pip install --upgrade paramiko>=3.4.0","deadline":"30 days"},
    ],
    "npm": [
        {"kw":["lodash"],"cve":"CVE-2021-23337","component":"lodash","current":"4.17.20","fixed":"4.17.21","severity":"HIGH","cvss":7.2,"exploited":1,"action":"npm update lodash","deadline":"Immediate"},
        {"kw":["axios"],"cve":"CVE-2023-45857","component":"axios","current":"1.5.0","fixed":"1.6.0","severity":"MEDIUM","cvss":6.5,"exploited":0,"action":"npm update axios","deadline":"30 days"},
        {"kw":["jsonwebtoken","jwt"],"cve":"CVE-2022-23539","component":"jsonwebtoken","current":"8.5.1","fixed":"9.0.0","severity":"CRITICAL","cvss":9.4,"exploited":1,"action":"npm install jsonwebtoken@9.0.0","deadline":"Immediate"},
        {"kw":["express"],"cve":"CVE-2024-29041","component":"express","current":"4.18.0","fixed":"4.19.2","severity":"HIGH","cvss":7.5,"exploited":0,"action":"npm update express","deadline":"7 days"},
        {"kw":["node-fetch","fetch"],"cve":"CVE-2022-0235","component":"node-fetch","current":"2.6.0","fixed":"2.6.7","severity":"HIGH","cvss":8.8,"exploited":0,"action":"npm install node-fetch@2.6.7","deadline":"7 days"},
        {"kw":["minimist"],"cve":"CVE-2021-44906","component":"minimist","current":"1.2.5","fixed":"1.2.6","severity":"CRITICAL","cvss":9.8,"exploited":0,"action":"npm install minimist@1.2.6","deadline":"7 days"},
    ],
    "os": [
        {"kw":["openssl"],"cve":"CVE-2023-0286","component":"OpenSSL","current":"1.1.1","fixed":"1.1.1t","severity":"HIGH","cvss":7.4,"exploited":0,"action":"apt-get install --only-upgrade openssl","deadline":"7 days"},
        {"kw":["openssh","ssh"],"cve":"CVE-2023-38408","component":"OpenSSH","current":"8.9","fixed":"9.3p2","severity":"CRITICAL","cvss":9.8,"exploited":1,"action":"apt-get install --only-upgrade openssh-server","deadline":"Immediate"},
        {"kw":["linux kernel","kernel"],"cve":"CVE-2023-32629","component":"Linux Kernel","current":"5.15","fixed":"5.15.0-78","severity":"HIGH","cvss":7.8,"exploited":1,"action":"apt-get dist-upgrade","deadline":"Immediate"},
        {"kw":["apache","httpd"],"cve":"CVE-2023-25690","component":"Apache HTTP Server","current":"2.4.54","fixed":"2.4.56","severity":"CRITICAL","cvss":9.8,"exploited":1,"action":"apt-get install --only-upgrade apache2","deadline":"Immediate"},
        {"kw":["nginx"],"cve":"CVE-2022-41741","component":"nginx","current":"1.22.0","fixed":"1.22.1","severity":"HIGH","cvss":7.8,"exploited":0,"action":"apt-get install --only-upgrade nginx","deadline":"7 days"},
        {"kw":["sudo"],"cve":"CVE-2023-22809","component":"sudo","current":"1.9.12","fixed":"1.9.12p2","severity":"HIGH","cvss":7.8,"exploited":1,"action":"apt-get install --only-upgrade sudo","deadline":"Immediate"},
        {"kw":["curl","libcurl"],"cve":"CVE-2023-38545","component":"curl","current":"7.88.0","fixed":"8.4.0","severity":"CRITICAL","cvss":9.8,"exploited":1,"action":"apt-get install --only-upgrade curl","deadline":"Immediate"},
    ]
}

SEV_WEIGHTS = {"CRITICAL":10,"HIGH":6,"MEDIUM":3,"LOW":1}
DEADLINE_PRIORITY = {"Immediate":1,"7 days":2,"30 days":3,"90 days":4}

def detect_ecosystem(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["pip","requirements.txt","python","django","flask","pyyaml"]):
        return "pip"
    elif any(kw in text_lower for kw in ["npm","package.json","node","lodash","express","react"]):
        return "npm"
    else:
        return "os"

def run_patch_brain(description, ecosystem):
    text_lower = description.lower()
    db2 = VULN_DB.get(ecosystem, VULN_DB["os"])
    patches = []
    priority = 1
    for item in db2:
        if any(kw in text_lower for kw in item["kw"]):
            patches.append({
                "cve_id":          item["cve"],
                "component":       item["component"],
                "current_version": item["current"],
                "fixed_version":   item["fixed"],
                "severity":        item["severity"],
                "cvss_score":      item["cvss"],
                "priority":        DEADLINE_PRIORITY.get(item["deadline"],4),
                "patch_action":    item["action"],
                "deadline":        item["deadline"],
                "exploited":       item["exploited"],
            })
    patches.sort(key=lambda x: (x["priority"], -x["cvss_score"]))
    for i, p in enumerate(patches):
        p["priority"] = i + 1
    return patches

def calc_risk(patches):
    if not patches: return 0.0
    raw = sum(SEV_WEIGHTS.get(p["severity"],0) * (1.5 if p["exploited"] else 1.0) for p in patches)
    return round(min(raw * 1.8, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@patch_brain_bp.route("/api/patch-brain/analyse", methods=["POST"])
@jwt_required()
def analyse():
    data  = request.get_json(silent=True) or {}
    env   = data.get("environment","production")
    desc  = data.get("description","")
    eco   = data.get("ecosystem","") or detect_ecosystem(desc)
    if not desc.strip(): return jsonify({"error":"No description provided"}),400
    patches  = run_patch_brain(desc, eco)
    score    = calc_risk(patches)
    sev      = overall_sev(score)
    critical = sum(1 for p in patches if p["severity"]=="CRITICAL")
    high     = sum(1 for p in patches if p["severity"]=="HIGH")
    exploited= sum(1 for p in patches if p["exploited"])
    summary  = (f"Patch Brain analysis complete. {len(patches)} patch(es) required. "
                f"{critical} critical, {high} high. {exploited} actively exploited in the wild. "
                f"Risk score: {score}/100.")
    s = PatchBrainSession(user_id=get_jwt_identity(),environment=env,risk_score=score,severity=sev,total_patches=len(patches),critical_count=critical,high_count=high,summary=summary,node_meta=json.dumps({"ecosystem":eco}))
    db.session.add(s); db.session.flush()
    for p in patches:
        db.session.add(PatchBrainItem(session_id=s.id,cve_id=p["cve_id"],component=p["component"],current_version=p["current_version"],fixed_version=p["fixed_version"],severity=p["severity"],cvss_score=p["cvss_score"],priority=p["priority"],patch_action=p["patch_action"],deadline=p["deadline"],exploited=p["exploited"],node_meta="{}"))
    db.session.commit()
    return jsonify({"session_id":s.id,"environment":env,"ecosystem":eco,"risk_score":score,"severity":sev,"total_patches":len(patches),"critical":critical,"exploited":exploited,"summary":summary}),200

@patch_brain_bp.route("/api/patch-brain/sessions/<session_id>", methods=["GET"])
@jwt_required()
def get_session(session_id):
    s = PatchBrainSession.query.filter_by(id=session_id,user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}),404
    patches = PatchBrainItem.query.filter_by(session_id=session_id).order_by(PatchBrainItem.priority).all()
    return jsonify({"session_id":s.id,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"total_patches":s.total_patches,"critical_count":s.critical_count,"high_count":s.high_count,"summary":s.summary,"created_at":s.created_at.isoformat(),"ecosystem":json.loads(s.node_meta).get("ecosystem",""),"patches":[{"priority":p.priority,"cve_id":p.cve_id,"component":p.component,"current_version":p.current_version,"fixed_version":p.fixed_version,"severity":p.severity,"cvss_score":p.cvss_score,"patch_action":p.patch_action,"deadline":p.deadline,"exploited":bool(p.exploited)} for p in patches]}),200

@patch_brain_bp.route("/api/patch-brain/history", methods=["GET"])
@jwt_required()
def history():
    sessions = PatchBrainSession.query.filter_by(user_id=get_jwt_identity()).order_by(PatchBrainSession.created_at.desc()).limit(50).all()
    return jsonify({"sessions":[{"session_id":s.id,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"total_patches":s.total_patches,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in sessions]}),200

@patch_brain_bp.route("/api/patch-brain/health", methods=["GET"])
def health():
    return jsonify({"module":"Autonomous Patch Brain","version":"1.0.0","ecosystems":["pip","npm","os"],"status":"operational"}),200
