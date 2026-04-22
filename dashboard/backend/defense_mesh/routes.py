# ============================================================
# AIPET X — Module #46: Global Defense Mesh
# Unified Defense Score | Cross-Module Aggregation | Roadmap
# Phase 5C | v6.2.0 — FINAL MODULE
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

defense_mesh_bp = Blueprint("defense_mesh", __name__)

class DefenseMeshReport(db.Model):
    __tablename__ = "defense_mesh_reports"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    organisation    = Column(String(256))
    defense_score   = Column(Float, default=0.0)
    maturity_level  = Column(String(64))
    total_gaps      = Column(Integer, default=0)
    critical_gaps   = Column(Integer, default=0)
    summary         = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")
    pillars         = relationship("DefenseMeshPillar", backref="report", lazy=True, cascade="all, delete-orphan")
    recommendations = relationship("DefenseMeshRecommendation", backref="report", lazy=True, cascade="all, delete-orphan")

class DefenseMeshPillar(db.Model):
    __tablename__ = "defense_mesh_pillars"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id     = Column(String(64), ForeignKey("defense_mesh_reports.id"), nullable=False)
    pillar_name   = Column(String(128))
    score         = Column(Float, default=0.0)
    status        = Column(String(32))
    gap_count     = Column(Integer, default=0)
    description   = Column(Text)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

class DefenseMeshRecommendation(db.Model):
    __tablename__ = "defense_mesh_recommendations"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id     = Column(String(64), ForeignKey("defense_mesh_reports.id"), nullable=False)
    priority      = Column(Integer)
    pillar        = Column(String(128))
    title         = Column(String(256))
    description   = Column(Text)
    effort        = Column(String(32))
    impact        = Column(String(32))
    timeframe     = Column(String(64))
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

DEFENSE_PILLARS = [
    {
        "name": "Identity & Access Management",
        "keywords": ["mfa","identity","rbac","iam","privileged","zero trust","sso","okta","active directory","least privilege"],
        "weight": 15,
        "description": "Strength of identity verification, access controls, MFA enforcement and privileged access management.",
        "recommendations": [
            {"title":"Enforce MFA across all accounts","effort":"Low","impact":"Critical","timeframe":"1 week"},
            {"title":"Implement Privileged Access Management (PAM)","effort":"Medium","impact":"High","timeframe":"1 month"},
            {"title":"Deploy Identity Threat Detection (ITDR)","effort":"High","impact":"High","timeframe":"3 months"},
        ]
    },
    {
        "name": "Endpoint & Device Security",
        "keywords": ["edr","endpoint","antivirus","device","patch","mdm","xdr","crowdstrike","defender","sentinelone"],
        "weight": 12,
        "description": "Coverage and effectiveness of endpoint detection, device management and patch compliance.",
        "recommendations": [
            {"title":"Deploy EDR on all endpoints","effort":"Medium","impact":"Critical","timeframe":"2 weeks"},
            {"title":"Implement automated patch management","effort":"Medium","impact":"High","timeframe":"1 month"},
            {"title":"Enforce device compliance via MDM","effort":"Medium","impact":"High","timeframe":"1 month"},
        ]
    },
    {
        "name": "Network Security",
        "keywords": ["firewall","segmentation","vlan","ids","ips","vpn","ndr","network","flow log","zero trust network"],
        "weight": 12,
        "description": "Network segmentation, traffic inspection, intrusion detection and secure remote access controls.",
        "recommendations": [
            {"title":"Implement network micro-segmentation","effort":"High","impact":"High","timeframe":"3 months"},
            {"title":"Deploy Network Detection & Response (NDR)","effort":"High","impact":"High","timeframe":"2 months"},
            {"title":"Enable VPC Flow Logs and traffic analysis","effort":"Low","impact":"Medium","timeframe":"1 week"},
        ]
    },
    {
        "name": "Cloud Security Posture",
        "keywords": ["cloud","aws","azure","gcp","cspm","misconfiguration","s3","iam policy","cloudtrail","cloud hardener"],
        "weight": 12,
        "description": "Cloud configuration hygiene, CSPM coverage, and compliance with CIS cloud benchmarks.",
        "recommendations": [
            {"title":"Deploy Cloud Security Posture Management (CSPM)","effort":"Medium","impact":"High","timeframe":"2 weeks"},
            {"title":"Enable cloud-native threat detection (GuardDuty/Defender)","effort":"Low","impact":"High","timeframe":"1 week"},
            {"title":"Remediate all critical cloud misconfigurations","effort":"Medium","impact":"Critical","timeframe":"2 weeks"},
        ]
    },
    {
        "name": "Application Security",
        "keywords": ["sast","sca","secret","vulnerability","code","appsec","devsecops","owasp","pentest","waf","api security"],
        "weight": 10,
        "description": "Secure development practices, SAST/DAST coverage, dependency management and API security.",
        "recommendations": [
            {"title":"Integrate SAST into CI/CD pipeline","effort":"Medium","impact":"High","timeframe":"1 month"},
            {"title":"Implement SCA for dependency vulnerability management","effort":"Low","impact":"High","timeframe":"2 weeks"},
            {"title":"Deploy Web Application Firewall (WAF)","effort":"Low","impact":"High","timeframe":"1 week"},
        ]
    },
    {
        "name": "Threat Detection & SIEM",
        "keywords": ["siem","detection","alert","log","monitor","splunk","sentinel","qradar","threat hunting","ueba","soar"],
        "weight": 12,
        "description": "Visibility, detection capability, log coverage and mean time to detect (MTTD) across the environment.",
        "recommendations": [
            {"title":"Centralise logging in a SIEM platform","effort":"High","impact":"Critical","timeframe":"2 months"},
            {"title":"Implement UEBA for insider threat detection","effort":"High","impact":"High","timeframe":"3 months"},
            {"title":"Build and test detection rules for top ATT&CK techniques","effort":"Medium","impact":"High","timeframe":"1 month"},
        ]
    },
    {
        "name": "Incident Response",
        "keywords": ["incident","response","playbook","forensic","soar","ir plan","tabletop","containment","breach response"],
        "weight": 10,
        "description": "Maturity of incident response plans, playbooks, team readiness and mean time to respond (MTTR).",
        "recommendations": [
            {"title":"Develop and test IR playbooks for top 5 scenarios","effort":"Medium","impact":"High","timeframe":"1 month"},
            {"title":"Conduct quarterly tabletop exercises","effort":"Low","impact":"High","timeframe":"Ongoing"},
            {"title":"Deploy SOAR for automated incident response","effort":"High","impact":"High","timeframe":"3 months"},
        ]
    },
    {
        "name": "Data Protection",
        "keywords": ["encrypt","data protection","gdpr","dlp","classification","privacy","backup","data loss","pii","sensitive data"],
        "weight": 10,
        "description": "Data classification, encryption coverage, DLP controls and regulatory compliance posture.",
        "recommendations": [
            {"title":"Implement data classification across all data stores","effort":"High","impact":"High","timeframe":"3 months"},
            {"title":"Deploy Data Loss Prevention (DLP) controls","effort":"High","impact":"High","timeframe":"2 months"},
            {"title":"Enable encryption at rest and in transit everywhere","effort":"Medium","impact":"Critical","timeframe":"1 month"},
        ]
    },
    {
        "name": "OT/ICS & Physical Security",
        "keywords": ["ot","ics","scada","plc","industrial","physical","cctv","badge","operational technology","modbus","dnp3"],
        "weight": 7,
        "description": "Operational technology security, OT/IT segmentation and physical security controls.",
        "recommendations": [
            {"title":"Segment OT/IT networks with data diode or unidirectional gateway","effort":"High","impact":"Critical","timeframe":"3 months"},
            {"title":"Deploy OT-aware IDS (Claroty/Dragos/Nozomi)","effort":"High","impact":"High","timeframe":"3 months"},
            {"title":"Conduct OT asset inventory and vulnerability assessment","effort":"Medium","impact":"High","timeframe":"1 month"},
        ]
    },
    {
        "name": "Compliance & Governance",
        "keywords": ["compliance","governance","policy","nis2","iso27001","gdpr","pci","audit","risk management","board"],
        "weight": 10,
        "description": "Regulatory compliance posture, security governance maturity and risk management programme.",
        "recommendations": [
            {"title":"Map controls to NIS2/ISO27001 and close gaps","effort":"High","impact":"High","timeframe":"3 months"},
            {"title":"Establish a security risk register and review quarterly","effort":"Medium","impact":"High","timeframe":"1 month"},
            {"title":"Implement continuous compliance monitoring","effort":"High","impact":"High","timeframe":"3 months"},
        ]
    },
]

def evaluate_pillars(description):
    desc_lower = description.lower()
    results = []
    for pillar in DEFENSE_PILLARS:
        matched = sum(1 for kw in pillar["keywords"] if kw in desc_lower)
        total   = len(pillar["keywords"])
        coverage= matched / total
        if coverage >= 0.5:
            score, status, gaps = round(75 + coverage*25, 1), "Strong", 0
        elif coverage >= 0.25:
            score, status, gaps = round(40 + coverage*60, 1), "Developing", 1
        elif coverage > 0:
            score, status, gaps = round(20 + coverage*40, 1), "Weak", 2
        else:
            score, status, gaps = 10.0, "Critical Gap", 3
        results.append({
            "pillar_name": pillar["name"],
            "score":       score,
            "status":      status,
            "gap_count":   gaps,
            "description": pillar["description"],
            "weight":      pillar["weight"],
            "recommendations": pillar["recommendations"] if status in ("Weak","Critical Gap") else []
        })
    return results

def calc_defense_score(pillars):
    total_weight = sum(p["weight"] for p in DEFENSE_PILLARS)
    weighted = sum(p["score"] * (p["weight"]/total_weight) for p in pillars)
    return round(weighted, 1)

def maturity_level(score):
    if score >= 85: return "Optimised"
    if score >= 70: return "Managed"
    if score >= 50: return "Defined"
    if score >= 30: return "Developing"
    return "Initial"

def build_roadmap(pillars):
    recs = []
    priority = 1
    # Critical gaps first
    for pillar in sorted(pillars, key=lambda x: x["score"]):
        for rec in pillar["recommendations"]:
            recs.append({
                "priority":    priority,
                "pillar":      pillar["pillar_name"],
                "title":       rec["title"],
                "description": f"Strengthen {pillar['pillar_name']} pillar. Current score: {pillar['score']}/100.",
                "effort":      rec["effort"],
                "impact":      rec["impact"],
                "timeframe":   rec["timeframe"],
            })
            priority += 1
    return recs[:15]  # Top 15 recommendations

@defense_mesh_bp.route("/api/defense-mesh/assess", methods=["POST"])
@jwt_required()
def assess():
    data         = request.get_json(silent=True) or {}
    organisation = data.get("organisation","Your Organisation")
    description  = data.get("description","")
    if not description.strip(): return jsonify({"error":"No description provided"}),400
    pillars  = evaluate_pillars(description)
    score    = calc_defense_score(pillars)
    maturity = maturity_level(score)
    roadmap  = build_roadmap(pillars)
    total_gaps    = sum(p["gap_count"] for p in pillars)
    critical_gaps = sum(1 for p in pillars if p["status"]=="Critical Gap")
    summary = (f"Global Defense Mesh assessment complete for {organisation}. "
               f"Overall Defense Score: {score}/100. Maturity: {maturity}. "
               f"{critical_gaps} critical gap(s) across {len(pillars)} defense pillars. "
               f"{len(roadmap)} prioritised remediation action(s) generated.")
    r = DefenseMeshReport(user_id=get_jwt_identity(),organisation=organisation,defense_score=score,maturity_level=maturity,total_gaps=total_gaps,critical_gaps=critical_gaps,summary=summary,node_meta="{}")
    db.session.add(r); db.session.flush()
    for p in pillars:
        db.session.add(DefenseMeshPillar(report_id=r.id,pillar_name=p["pillar_name"],score=p["score"],status=p["status"],gap_count=p["gap_count"],description=p["description"],node_meta="{}"))
    for rec in roadmap:
        db.session.add(DefenseMeshRecommendation(report_id=r.id,priority=rec["priority"],pillar=rec["pillar"],title=rec["title"],description=rec["description"],effort=rec["effort"],impact=rec["impact"],timeframe=rec["timeframe"],node_meta="{}"))
    db.session.commit()
    return jsonify({"report_id":r.id,"organisation":organisation,"defense_score":score,"maturity_level":maturity,"total_gaps":total_gaps,"critical_gaps":critical_gaps,"roadmap_count":len(roadmap),"summary":summary}),200

@defense_mesh_bp.route("/api/defense-mesh/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    r = DefenseMeshReport.query.filter_by(id=report_id,user_id=get_jwt_identity()).first()
    if not r: return jsonify({"error":"Not found"}),404
    pillars = DefenseMeshPillar.query.filter_by(report_id=report_id).all()
    recs    = DefenseMeshRecommendation.query.filter_by(report_id=report_id).order_by(DefenseMeshRecommendation.priority).all()
    return jsonify({"report_id":r.id,"organisation":r.organisation,"defense_score":r.defense_score,"maturity_level":r.maturity_level,"total_gaps":r.total_gaps,"critical_gaps":r.critical_gaps,"summary":r.summary,"created_at":r.created_at.isoformat(),"pillars":[{"pillar_name":p.pillar_name,"score":p.score,"status":p.status,"gap_count":p.gap_count,"description":p.description} for p in pillars],"roadmap":[{"priority":rec.priority,"pillar":rec.pillar,"title":rec.title,"description":rec.description,"effort":rec.effort,"impact":rec.impact,"timeframe":rec.timeframe} for rec in recs]}),200

@defense_mesh_bp.route("/api/defense-mesh/history", methods=["GET"])
@jwt_required()
def history():
    reports = DefenseMeshReport.query.filter_by(user_id=get_jwt_identity()).order_by(DefenseMeshReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"organisation":r.organisation,"defense_score":r.defense_score,"maturity_level":r.maturity_level,"critical_gaps":r.critical_gaps,"created_at":r.created_at.isoformat()} for r in reports]}),200

@defense_mesh_bp.route("/api/defense-mesh/health", methods=["GET"])
def health():
    return jsonify({"module":"Global Defense Mesh","version":"1.0.0","pillars":len(DEFENSE_PILLARS),"status":"operational"}),200
