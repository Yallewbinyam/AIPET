# ============================================================
# AIPET X — Multi-Cloud Scale Engine (Wiz Gap — Phase 1)
# Cross-Cloud Orchestration | Scale Analysis | Cost Security
# ============================================================

import json, uuid, datetime, random
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float
from sqlalchemy.orm import relationship

multicloud_scale_bp = Blueprint("multicloud_scale", __name__)

class MultiCloudScaleReport(db.Model):
    __tablename__ = "multicloud_scale_reports"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    total_providers = Column(Integer, default=0)
    total_regions   = Column(Integer, default=0)
    total_workloads = Column(Integer, default=0)
    security_score  = Column(Float, default=0.0)
    cost_risk_score = Column(Float, default=0.0)
    scale_issues    = Column(Integer, default=0)
    summary         = Column(Text, nullable=True)
    recommendations = Column(Text, default="[]")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

SCALE_RULES = [
    {"title":"No Centralised Identity Provider","keywords":["no sso","no central identity","multiple identity","no centralised iam","separate identity per cloud"],"severity":"CRITICAL","category":"Identity","impact":"Each cloud has separate IAM — no unified identity. Creates security gaps and audit blind spots.","recommendation":"Implement centralised IdP (Okta/Azure AD) with federation to all cloud providers via SAML/OIDC."},
    {"title":"No Unified Logging Across Clouds","keywords":["no central log","separate logs","no unified siem","log per cloud","no cross cloud log"],"severity":"HIGH","category":"Observability","impact":"Security events siloed per cloud — attacker can pivot between clouds undetected.","recommendation":"Deploy centralised SIEM. Route all cloud audit logs (CloudTrail, Azure Monitor, GCP Audit) to one platform."},
    {"title":"Inconsistent Security Policies Across Clouds","keywords":["inconsistent policy","different policy","policy per cloud","no standard policy","policy gap"],"severity":"HIGH","category":"Governance","impact":"Security controls vary by cloud provider — attackers exploit the weakest cloud.","recommendation":"Implement cloud-agnostic policy framework. Use OPA or HashiCorp Sentinel for unified policy enforcement."},
    {"title":"No Multi-Cloud Cost Security Governance","keywords":["no cost control","budget alert","cost overrun","no spend limit","uncontrolled spend"],"severity":"MEDIUM","category":"Cost Security","impact":"Uncontrolled cloud spend can indicate cryptomining, data exfiltration or compromised resources.","recommendation":"Set budget alerts and anomaly detection across all providers. Monitor for unexpected spend spikes."},
    {"title":"Data Residency Not Enforced","keywords":["data residency","data sovereignty","gdpr region","data location","cross region data","region restriction"],"severity":"HIGH","category":"Compliance","impact":"Data may flow across regions violating GDPR, NIS2 and data sovereignty requirements.","recommendation":"Enforce region-locked storage policies. Use cloud-native controls to restrict data to approved regions."},
    {"title":"No Multi-Cloud Disaster Recovery","keywords":["no dr","no disaster recovery","single cloud dr","no failover","no cross cloud backup"],"severity":"HIGH","category":"Resilience","impact":"Single cloud failure takes down entire platform. No cross-cloud failover capability.","recommendation":"Implement active-active or active-passive DR across at least 2 cloud providers. Test failover quarterly."},
    {"title":"Unmanaged Shadow Cloud Usage","keywords":["shadow cloud","unmanaged cloud","rogue cloud","unauthorised cloud","unknown cloud account"],"severity":"HIGH","category":"Governance","impact":"Developers using unapproved cloud services creates security and compliance blind spots.","recommendation":"Implement cloud access security broker (CASB). Enforce approved cloud services list via policy."},
    {"title":"No Multi-Cloud Network Segmentation","keywords":["flat multi cloud","no network segmentation multi","open cloud connectivity","unrestricted cloud to cloud","no inter cloud firewall"],"severity":"HIGH","category":"Network","impact":"Compromise in one cloud can pivot to all connected clouds via flat network.","recommendation":"Implement Transit Gateway / Virtual WAN with strict inter-cloud routing policies and inspection."},
    {"title":"Secrets Not Centralised","keywords":["secret per cloud","no vault","secrets manager per cloud","no central secret","separate secrets"],"severity":"HIGH","category":"Credential Security","impact":"Secrets spread across cloud-native managers — no unified rotation or audit trail.","recommendation":"Deploy HashiCorp Vault or centralised secrets manager. Federate all cloud secrets through single control plane."},
    {"title":"No Multi-Cloud Threat Detection","keywords":["no cross cloud detection","threat detection per cloud","no unified threat","siem per cloud","no multi cloud soc"],"severity":"CRITICAL","category":"Detection","impact":"Coordinated cross-cloud attacks go undetected when threat detection is siloed per provider.","recommendation":"Deploy unified SIEM with cross-cloud correlation rules. Enable threat intelligence sharing across all providers."},
]

def run_scale_analysis(description, providers, regions, workloads):
    desc_lower = description.lower()
    issues = []
    for rule in SCALE_RULES:
        if any(kw in desc_lower for kw in rule["keywords"]):
            issues.append(rule)

    security_score = max(10, 100 - (len([i for i in issues if i["severity"]=="CRITICAL"])*20 + len([i for i in issues if i["severity"]=="HIGH"])*10 + len([i for i in issues if i["severity"]=="MEDIUM"])*5))
    cost_risk = min(100, len(issues) * 8 + random.randint(5,20))

    recommendations = [{"priority":i+1,"title":issue["title"],"category":issue["category"],"severity":issue["severity"],"impact":issue["impact"],"recommendation":issue["recommendation"]} for i,issue in enumerate(issues)]

    summary = (f"Multi-Cloud Scale Analysis complete. {len(providers)} provider(s), {regions} region(s), {workloads} workload(s). "
               f"Security score: {security_score}/100. {len(issues)} scale issue(s) detected. "
               f"Cost risk score: {cost_risk}/100.")

    return issues, security_score, cost_risk, recommendations, summary

@multicloud_scale_bp.route("/api/multicloud-scale/analyse", methods=["POST"])
@jwt_required()
def analyse():
    data        = request.get_json(silent=True) or {}
    description = data.get("description", "")
    providers   = data.get("providers", ["aws"])
    regions     = data.get("regions", 3)
    workloads   = data.get("workloads", 50)
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    issues, sec_score, cost_risk, recs, summary = run_scale_analysis(description, providers, regions, workloads)

    r = MultiCloudScaleReport(
        user_id=get_jwt_identity(), total_providers=len(providers),
        total_regions=regions, total_workloads=workloads,
        security_score=sec_score, cost_risk_score=cost_risk,
        scale_issues=len(issues), summary=summary,
        recommendations=json.dumps(recs), node_meta="{}")
    db.session.add(r); db.session.commit()

    return jsonify({"report_id":r.id,"providers":providers,"regions":regions,"workloads":workloads,"security_score":sec_score,"cost_risk_score":cost_risk,"scale_issues":len(issues),"summary":summary,"recommendations":recs}), 200

@multicloud_scale_bp.route("/api/multicloud-scale/history", methods=["GET"])
@jwt_required()
def history():
    reports = MultiCloudScaleReport.query.filter_by(user_id=get_jwt_identity()).order_by(MultiCloudScaleReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"total_providers":r.total_providers,"total_regions":r.total_regions,"security_score":r.security_score,"cost_risk_score":r.cost_risk_score,"scale_issues":r.scale_issues,"created_at":r.created_at.isoformat()} for r in reports]}), 200

@multicloud_scale_bp.route("/api/multicloud-scale/health", methods=["GET"])
def health():
    return jsonify({"module":"Multi-Cloud Scale Engine","phase":"Wiz Gap — Phase 1","version":"1.0.0","rules":len(SCALE_RULES),"status":"operational"}), 200
