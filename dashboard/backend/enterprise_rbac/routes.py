# ============================================================
# AIPET X — Enterprise RBAC + SSO
# Role Management | Permission Control | SSO Integration
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

enterprise_rbac_bp = Blueprint("enterprise_rbac", __name__)

class RBACRole(db.Model):
    __tablename__ = "rbac_roles"
    id          = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = Column(Integer, nullable=False)
    role_name   = Column(String(128))
    role_type   = Column(String(64))
    permissions = Column(Text, default="[]")
    description = Column(Text, nullable=True)
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta   = Column(Text, default="{}")

class RBACAssessment(db.Model):
    __tablename__ = "rbac_assessments"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    organisation    = Column(String(256))
    total_roles     = Column(Integer, default=0)
    over_privileged = Column(Integer, default=0)
    sso_configured  = Column(Integer, default=0)
    mfa_enforced    = Column(Integer, default=0)
    risk_score      = Column(Float, default=0.0)
    issues          = Column(Integer, default=0)
    summary         = Column(Text, nullable=True)
    findings        = Column(Text, default="[]")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

RBAC_RULES = [
    {"title":"No Role-Based Access Control","keywords":["no rbac","no role","flat permissions","everyone admin","all access","no access control"],"severity":"CRITICAL","category":"RBAC","fix":"Implement RBAC with defined roles. Apply least-privilege principle. Separate duties."},
    {"title":"Admin Role Over-Assignment","keywords":["too many admins","everyone admin","admin overuse","excessive admin","admin sprawl","unnecessary admin"],"severity":"CRITICAL","category":"Privilege","fix":"Audit all admin assignments. Remove unnecessary admin rights. Implement time-bound elevated access."},
    {"title":"No MFA Enforcement","keywords":["no mfa","mfa not enforced","mfa disabled","two factor disabled","no 2fa","mfa optional"],"severity":"CRITICAL","category":"Authentication","fix":"Enforce MFA for all users. Use hardware keys for privileged accounts. Block access without MFA."},
    {"title":"SSO Not Configured","keywords":["no sso","no single sign on","local accounts only","no federated","no saml","no oidc","no okta"],"severity":"HIGH","category":"SSO","fix":"Implement SSO via SAML 2.0 or OIDC. Connect to corporate IdP. Disable local account creation."},
    {"title":"No Privileged Access Management","keywords":["no pam","no privileged","no vault","no jump server","no bastion","shared admin","shared root"],"severity":"CRITICAL","category":"PAM","fix":"Deploy PAM solution. Use just-in-time access. Record all privileged sessions. Rotate credentials automatically."},
    {"title":"Stale Accounts Not Removed","keywords":["stale accounts","dormant users","inactive users","old accounts","no deprovisioning","leaver accounts"],"severity":"HIGH","category":"Lifecycle","fix":"Automate deprovisioning. Review accounts quarterly. Disable after 90 days of inactivity."},
    {"title":"No Access Review Process","keywords":["no access review","no recertification","no user review","no quarterly review","no access audit"],"severity":"HIGH","category":"Governance","fix":"Implement quarterly access reviews. Use automated recertification. Remove unused access."},
    {"title":"Service Accounts With Human Privileges","keywords":["service account human","shared account","generic account","service account login","human service account"],"severity":"HIGH","category":"Service Accounts","fix":"Separate service and human accounts. Use managed identities. Disable console login for service accounts."},
    {"title":"No Session Management","keywords":["no session timeout","session never expires","no idle timeout","unlimited session","session management"],"severity":"MEDIUM","category":"Session","fix":"Set session timeout (15 min idle). Enforce re-authentication for sensitive actions. Implement session revocation."},
    {"title":"Password Policy Insufficient","keywords":["weak password","no password policy","short password","no complexity","password reuse","no rotation"],"severity":"HIGH","category":"Credentials","fix":"Enforce strong passwords (12+ chars). Block common passwords. Implement breach password detection."},
]

SSO_PROVIDERS = {
    "okta":       {"name":"Okta","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
    "azure_ad":   {"name":"Azure AD / Entra ID","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
    "google":     {"name":"Google Workspace","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
    "onelogin":   {"name":"OneLogin","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
    "ping":       {"name":"PingIdentity","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
    "keycloak":   {"name":"Keycloak (Self-hosted)","protocol":"OIDC/SAML","mfa":True,"provisioning":"SCIM"},
}

DEFAULT_ROLES = [
    {"name":"Super Admin","type":"admin","permissions":["*"],"description":"Full platform access — assign sparingly"},
    {"name":"Security Analyst","type":"analyst","permissions":["scan:read","scan:create","report:read","alert:read","threat:read"],"description":"Can run scans and view reports"},
    {"name":"Compliance Officer","type":"compliance","permissions":["compliance:read","compliance:create","report:read","report:export"],"description":"Compliance assessments and reporting"},
    {"name":"SOC Analyst","type":"soc","permissions":["alert:read","alert:update","incident:read","incident:create","siem:read"],"description":"Security operations monitoring"},
    {"name":"Developer","type":"developer","permissions":["scan:read","codescan:create","codescan:read","report:read"],"description":"Code security scanning only"},
    {"name":"Read Only","type":"readonly","permissions":["scan:read","report:read"],"description":"View-only access to reports"},
]

def assess_rbac(description, organisation):
    desc_lower = description.lower()
    findings = []
    for rule in RBAC_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({"title":rule["title"],"severity":rule["severity"],"category":rule["category"],"fix":rule["fix"]})

    sso_configured = 1 if any(p in desc_lower for p in ["sso","saml","oidc","okta","azure ad","google workspace","single sign on"]) else 0
    mfa_enforced   = 1 if any(m in desc_lower for m in ["mfa enforced","mfa enabled","two factor","2fa","hardware key","fido"]) else 0
    over_priv      = sum(1 for f in findings if f["category"] in ["Privilege","RBAC","PAM"])
    risk           = round(min(len(findings)*10 + (1-sso_configured)*15 + (1-mfa_enforced)*20, 100.0), 1)

    summary = (f"Enterprise RBAC + SSO assessment for {organisation}. "
               f"Risk score: {risk}/100. {len(findings)} issue(s) found. "
               f"SSO: {'Configured' if sso_configured else 'Not configured'}. "
               f"MFA: {'Enforced' if mfa_enforced else 'Not enforced'}. "
               f"{over_priv} privilege issue(s) detected.")

    return findings, risk, sso_configured, mfa_enforced, over_priv, summary

@enterprise_rbac_bp.route("/api/enterprise-rbac/assess", methods=["POST"])
@jwt_required()
def assess():
    data         = request.get_json(silent=True) or {}
    organisation = data.get("organisation", "My Organisation")
    description  = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    findings, risk, sso, mfa, over_priv, summary = assess_rbac(description, organisation)

    a = RBACAssessment(user_id=get_jwt_identity(), organisation=organisation, total_roles=len(DEFAULT_ROLES), over_privileged=over_priv, sso_configured=sso, mfa_enforced=mfa, risk_score=risk, issues=len(findings), summary=summary, findings=json.dumps(findings), node_meta="{}")
    db.session.add(a); db.session.commit()

    return jsonify({"assessment_id":a.id,"organisation":organisation,"risk_score":risk,"sso_configured":sso,"mfa_enforced":mfa,"over_privileged":over_priv,"issues":len(findings),"findings":findings,"default_roles":DEFAULT_ROLES,"sso_providers":list(SSO_PROVIDERS.values()),"summary":summary}), 200

@enterprise_rbac_bp.route("/api/enterprise-rbac/roles", methods=["GET"])
@jwt_required()
def get_roles():
    return jsonify({"roles":DEFAULT_ROLES,"total":len(DEFAULT_ROLES)}), 200

@enterprise_rbac_bp.route("/api/enterprise-rbac/history", methods=["GET"])
@jwt_required()
def history():
    assessments = RBACAssessment.query.filter_by(user_id=get_jwt_identity()).order_by(RBACAssessment.created_at.desc()).limit(50).all()
    return jsonify({"assessments":[{"assessment_id":a.id,"organisation":a.organisation,"risk_score":a.risk_score,"sso_configured":a.sso_configured,"mfa_enforced":a.mfa_enforced,"issues":a.issues,"created_at":a.created_at.isoformat()} for a in assessments]}), 200

@enterprise_rbac_bp.route("/api/enterprise-rbac/health", methods=["GET"])
def health():
    return jsonify({"module":"Enterprise RBAC + SSO","version":"1.0.0","default_roles":len(DEFAULT_ROLES),"sso_providers":len(SSO_PROVIDERS),"status":"operational"}), 200
