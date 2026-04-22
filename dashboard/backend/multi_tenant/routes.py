# ============================================================
# AIPET X — Multi-Tenant Architecture
# Tenant Management | Isolation | Resource Quotas
# ============================================================

import json, uuid, datetime, random
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

multi_tenant_bp = Blueprint("multi_tenant", __name__)

class TenantAssessment(db.Model):
    __tablename__ = "tenant_assessments"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    tenant_name     = Column(String(256))
    tenant_type     = Column(String(64))
    isolation_score = Column(Float, default=0.0)
    risk_score      = Column(Float, default=0.0)
    total_tenants   = Column(Integer, default=0)
    issues          = Column(Integer, default=0)
    summary         = Column(Text, nullable=True)
    findings        = Column(Text, default="[]")
    tenants_data    = Column(Text, default="[]")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

TENANT_RULES = [
    {"title":"No Tenant Data Isolation","keywords":["no isolation","shared database","tenant data mixed","no data separation","shared schema","cross tenant data"],"severity":"CRITICAL","category":"Data Isolation","fix":"Implement per-tenant schemas or databases. Use row-level security. Never share data across tenants."},
    {"title":"Missing Tenant Resource Quotas","keywords":["no quota","unlimited resources","no rate limit","resource abuse","noisy neighbour","no throttle"],"severity":"HIGH","category":"Resource Management","fix":"Implement per-tenant quotas. Add rate limiting. Monitor resource usage. Alert on quota breach."},
    {"title":"No Tenant Authentication Separation","keywords":["shared auth","no tenant auth","single auth","tenant auth missing","no namespace","shared login"],"severity":"CRITICAL","category":"Authentication","fix":"Implement tenant-scoped authentication. Use tenant ID in JWT claims. Validate tenant context on every request."},
    {"title":"Cross-Tenant Privilege Escalation Risk","keywords":["cross tenant","tenant escape","privilege escalation tenant","tenant boundary","tenant hop","cross tenant access"],"severity":"CRITICAL","category":"Security","fix":"Enforce tenant boundaries at application and database layer. Audit cross-tenant operations. Add tenant validation middleware."},
    {"title":"No Tenant Audit Logging","keywords":["no audit","no tenant log","audit missing","no activity log","tenant activity","no compliance log"],"severity":"HIGH","category":"Compliance","fix":"Implement per-tenant audit logs. Log all data access. Provide tenant admins with their own audit trail."},
    {"title":"Shared Encryption Keys","keywords":["shared key","same key","no per tenant key","shared encryption","one key all tenants","key isolation"],"severity":"CRITICAL","category":"Encryption","fix":"Use per-tenant encryption keys. Rotate keys independently. Use envelope encryption with tenant-specific DEKs."},
    {"title":"No Tenant Onboarding Automation","keywords":["manual onboarding","no automation","manual setup","slow onboarding","manual tenant","no provisioning"],"severity":"MEDIUM","category":"Operations","fix":"Automate tenant provisioning. Use IaC for tenant setup. Target sub-minute onboarding."},
    {"title":"No Tenant Offboarding Process","keywords":["no offboarding","data retention","tenant deletion","no cleanup","data after cancel","ghost tenant"],"severity":"HIGH","category":"Compliance","fix":"Implement automated offboarding. Define data retention policy. Purge data per GDPR. Document offboarding SLA."},
]

def assess_tenancy(description, tenant_type):
    desc_lower = description.lower()
    findings = []
    for rule in TENANT_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({"title":rule["title"],"severity":rule["severity"],"category":rule["category"],"fix":rule["fix"]})

    isolation = round(max(10, 100 - len(findings)*12), 1)
    risk      = round(min(len(findings)*13, 100.0), 1)

    tenants = []
    tenant_names = ["NHS Trust London","UK Manufacturing Co","Smart Building Corp","University Research Lab","MSP Partner UK"]
    for name in tenant_names:
        h = round(random.uniform(max(20,isolation-20), min(100,isolation+20)), 1)
        tenants.append({"name":name,"plan":random.choice(["Professional","Enterprise","AIPET X"]),"health":h,"scans":random.randint(5,200),"status":"HEALTHY" if h>70 else "WARNING" if h>50 else "AT_RISK","data_region":random.choice(["EU","UK","US"])})

    summary = (f"Multi-tenant assessment complete for {tenant_type} architecture. "
               f"Isolation score: {isolation}/100. Risk: {risk}/100. "
               f"{len(findings)} issue(s) detected. {len(tenants)} active tenant(s) modelled.")

    return findings, isolation, risk, tenants, summary

@multi_tenant_bp.route("/api/multi-tenant/assess", methods=["POST"])
@jwt_required()
def assess():
    data        = request.get_json(silent=True) or {}
    tenant_name = data.get("tenant_name", "My Platform")
    tenant_type = data.get("tenant_type", "saas")
    description = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    findings, isolation, risk, tenants, summary = assess_tenancy(description, tenant_type)

    a = TenantAssessment(user_id=get_jwt_identity(), tenant_name=tenant_name, tenant_type=tenant_type, isolation_score=isolation, risk_score=risk, total_tenants=len(tenants), issues=len(findings), summary=summary, findings=json.dumps(findings), tenants_data=json.dumps(tenants), node_meta="{}")
    db.session.add(a); db.session.commit()

    return jsonify({"assessment_id":a.id,"tenant_name":tenant_name,"tenant_type":tenant_type,"isolation_score":isolation,"risk_score":risk,"total_tenants":len(tenants),"issues":len(findings),"findings":findings,"tenants":tenants,"summary":summary}), 200

@multi_tenant_bp.route("/api/multi-tenant/history", methods=["GET"])
@jwt_required()
def history():
    assessments = TenantAssessment.query.filter_by(user_id=get_jwt_identity()).order_by(TenantAssessment.created_at.desc()).limit(50).all()
    return jsonify({"assessments":[{"assessment_id":a.id,"tenant_name":a.tenant_name,"tenant_type":a.tenant_type,"isolation_score":a.isolation_score,"risk_score":a.risk_score,"total_tenants":a.total_tenants,"issues":a.issues,"created_at":a.created_at.isoformat()} for a in assessments]}), 200

@multi_tenant_bp.route("/api/multi-tenant/health", methods=["GET"])
def health():
    return jsonify({"module":"Multi-Tenant Architecture","version":"1.0.0","rules":len(TENANT_RULES),"status":"operational"}), 200
