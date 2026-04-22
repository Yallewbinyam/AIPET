# ============================================================
# AIPET X — IAM Exposure Analyzer (Wiz Gap — Phase 1)
# Identity Risk | Permission Analysis | Privilege Paths
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

iam_exposure_bp = Blueprint("iam_exposure", __name__)

class IAMExposureScan(db.Model):
    __tablename__ = "iam_exposure_scans"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(Integer, nullable=False)
    cloud_provider = Column(String(32), default="aws")
    risk_score     = Column(Float, default=0.0)
    severity       = Column(String(16), default="LOW")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    identities_at_risk = Column(Integer, default=0)
    summary        = Column(Text, nullable=True)
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta      = Column(Text, default="{}")
    findings       = relationship("IAMExposureFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class IAMExposureFinding(db.Model):
    __tablename__ = "iam_exposure_findings"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(64), ForeignKey("iam_exposure_scans.id"), nullable=False)
    category       = Column(String(64))
    title          = Column(String(256))
    severity       = Column(String(16))
    identity_type  = Column(String(64))
    identity_name  = Column(String(256), nullable=True)
    description    = Column(Text)
    remediation    = Column(Text)
    blast_radius   = Column(String(32), default="LOW")
    node_meta      = Column(Text, default="{}")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

IAM_RULES = [
    # Privilege Escalation
    {"id":"IAM-PE-001","category":"Privilege Escalation","title":"IAM Policy Allows Creating Admin Users","keywords":["create user","iam:CreateUser","iam:AttachUserPolicy","create admin","add user to group"],"severity":"CRITICAL","identity":"IAM Policy","blast_radius":"HIGH","remediation":"Remove iam:CreateUser and iam:AttachUserPolicy from non-admin roles. Enforce separation of duties."},
    {"id":"IAM-PE-002","category":"Privilege Escalation","title":"PassRole Permission Allows Privilege Escalation","keywords":["iam:PassRole","pass role","passrole","role passing","lambda passrole","ec2 passrole"],"severity":"CRITICAL","identity":"IAM Role","blast_radius":"HIGH","remediation":"Restrict iam:PassRole to specific roles. Never allow PassRole with wildcard resources."},
    {"id":"IAM-PE-003","category":"Privilege Escalation","title":"UpdateAssumeRolePolicy Escalation Path","keywords":["UpdateAssumeRolePolicy","assume role policy","trust policy update","modify trust","sts assume"],"severity":"CRITICAL","identity":"IAM Role","blast_radius":"HIGH","remediation":"Restrict UpdateAssumeRolePolicy. Require MFA for role assumption. Monitor all trust policy changes."},
    # Excessive Permissions
    {"id":"IAM-EP-001","category":"Excessive Permissions","title":"Administrator Access Policy Attached","keywords":["AdministratorAccess","administrator policy","admin policy attached","full admin","*:* policy","all actions all resources"],"severity":"CRITICAL","identity":"IAM User/Role","blast_radius":"CRITICAL","remediation":"Remove AdministratorAccess. Replace with least-privilege policies scoped to required services."},
    {"id":"IAM-EP-002","category":"Excessive Permissions","title":"Wildcard Resource in IAM Policy","keywords":["resource: *","resource *","all resources","arn:*","wildcard resource","* resource"],"severity":"HIGH","identity":"IAM Policy","blast_radius":"HIGH","remediation":"Replace wildcard resources with specific ARNs. Scope all policies to minimum required resources."},
    {"id":"IAM-EP-003","category":"Excessive Permissions","title":"Unused Permissions in Role","keywords":["unused permission","last used","never used","stale permission","excess permission","permission not used"],"severity":"MEDIUM","identity":"IAM Role","blast_radius":"MEDIUM","remediation":"Use IAM Access Analyzer to identify and remove unused permissions. Apply just-enough-access."},
    {"id":"IAM-EP-004","category":"Excessive Permissions","title":"Cross-Account Admin Access","keywords":["cross account","cross-account admin","external account","account trust","third party admin","external admin"],"severity":"CRITICAL","identity":"IAM Role","blast_radius":"CRITICAL","remediation":"Review all cross-account trust relationships. Require ExternalId condition. Enforce MFA."},
    # Credential Issues
    {"id":"IAM-CR-001","category":"Credential Security","title":"Access Keys Not Rotated","keywords":["key rotation","access key age","old access key","unrotated key","key not rotated","90 days key"],"severity":"HIGH","identity":"IAM User","blast_radius":"MEDIUM","remediation":"Rotate all access keys every 90 days. Use IAM Roles instead of long-lived access keys."},
    {"id":"IAM-CR-002","category":"Credential Security","title":"MFA Not Enabled on Privileged Account","keywords":["no mfa","mfa disabled","privileged no mfa","console no mfa","mfa not enforced"],"severity":"CRITICAL","identity":"IAM User","blast_radius":"HIGH","remediation":"Enforce MFA via IAM policy condition aws:MultiFactorAuthPresent. Block console without MFA."},
    {"id":"IAM-CR-003","category":"Credential Security","title":"Root Account Has Access Keys","keywords":["root access key","root key","root account key","root credentials","root iam key"],"severity":"CRITICAL","identity":"Root Account","blast_radius":"CRITICAL","remediation":"Delete all root account access keys immediately. Use IAM users/roles for all programmatic access."},
    {"id":"IAM-CR-004","category":"Credential Security","title":"Inactive IAM Users with Active Credentials","keywords":["inactive user","dormant user","inactive account","never logged in","old iam user","stale user"],"severity":"HIGH","identity":"IAM User","blast_radius":"MEDIUM","remediation":"Disable inactive users after 90 days. Implement automated deprovisioning. Review quarterly."},
    # Service Account Risk
    {"id":"IAM-SA-001","category":"Service Account Risk","title":"Service Account Used by Multiple Workloads","keywords":["shared service account","multiple workload","service account shared","one sa multiple","common service account"],"severity":"HIGH","identity":"Service Account","blast_radius":"HIGH","remediation":"Create dedicated service accounts per workload. Apply least-privilege per service account."},
    {"id":"IAM-SA-002","category":"Service Account Risk","title":"Service Account with Cloud Admin Role","keywords":["sa admin","service account admin","workload admin","sa owner role","sa editor role"],"severity":"CRITICAL","identity":"Service Account","blast_radius":"CRITICAL","remediation":"Remove admin roles from service accounts. Use workload identity with minimal permissions."},
    {"id":"IAM-SA-003","category":"Service Account Risk","title":"Static Service Account Key in Use","keywords":["static sa key","service account key","sa json key","sa credentials file","service account file"],"severity":"HIGH","identity":"Service Account","blast_radius":"HIGH","remediation":"Replace static keys with Workload Identity Federation. Rotate existing keys every 90 days."},
    # Federation & SSO
    {"id":"IAM-FD-001","category":"Federation Risk","title":"Overly Permissive SAML Federation","keywords":["saml federation","saml trust","federation trust","idp trust","saml role","federated admin"],"severity":"HIGH","identity":"Federated Identity","blast_radius":"HIGH","remediation":"Restrict SAML trust to specific IdP entity IDs. Apply condition keys to limit federated access."},
    {"id":"IAM-FD-002","category":"Federation Risk","title":"OIDC Provider Trusted Without Conditions","keywords":["oidc trust","oidc provider","github actions oidc","oidc no condition","oidc wildcard"],"severity":"HIGH","identity":"OIDC Provider","blast_radius":"HIGH","remediation":"Add sub, aud and iss conditions to all OIDC trust policies. Restrict to specific repositories/subjects."},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}
BLAST_W = {"CRITICAL":2.0,"HIGH":1.5,"MEDIUM":1.0,"LOW":0.5}

def run_iam_scan(description, provider):
    desc_lower = description.lower()
    findings = []
    for rule in IAM_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({
                "category":     rule["category"],
                "title":        rule["title"],
                "severity":     rule["severity"],
                "identity_type":rule["identity"],
                "identity_name":f"{provider.upper()} Identity",
                "description":  f"IAM exposure detected: {rule['title']}. This creates a {rule['blast_radius']} blast radius risk in your {provider.upper()} environment.",
                "remediation":  rule["remediation"],
                "blast_radius": rule["blast_radius"],
            })
    return findings

def calc_risk(findings):
    if not findings: return 0.0
    raw = sum(SEV_W.get(f["severity"],0) * BLAST_W.get(f["blast_radius"],1.0) for f in findings)
    return round(min(raw * 1.2, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@iam_exposure_bp.route("/api/iam-exposure/scan", methods=["POST"])
@jwt_required()
def scan():
    data     = request.get_json(silent=True) or {}
    provider = data.get("cloud_provider", "aws")
    desc     = data.get("description", "")
    if not desc.strip(): return jsonify({"error":"No description provided"}), 400
    findings = run_iam_scan(desc, provider)
    score    = calc_risk(findings)
    sev      = overall_sev(score)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    at_risk  = len(set(f["identity_type"] for f in findings))
    summary  = f"IAM Exposure Analysis complete for {provider.upper()}. Risk: {score}/100. {len(findings)} finding(s) — {critical} critical. {at_risk} identity type(s) at risk."
    s = IAMExposureScan(user_id=get_jwt_identity(), cloud_provider=provider, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, identities_at_risk=at_risk, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(IAMExposureFinding(scan_id=s.id, category=f["category"], title=f["title"], severity=f["severity"], identity_type=f["identity_type"], identity_name=f["identity_name"], description=f["description"], remediation=f["remediation"], blast_radius=f["blast_radius"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"risk_score":score,"severity":sev,"total_findings":len(findings),"critical_count":critical,"identities_at_risk":at_risk,"summary":summary}), 200

@iam_exposure_bp.route("/api/iam-exposure/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = IAMExposureScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = IAMExposureFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"cloud_provider":s.cloud_provider,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"identities_at_risk":s.identities_at_risk,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"category":f.category,"title":f.title,"severity":f.severity,"identity_type":f.identity_type,"identity_name":f.identity_name,"description":f.description,"remediation":f.remediation,"blast_radius":f.blast_radius} for f in findings]}), 200

@iam_exposure_bp.route("/api/iam-exposure/history", methods=["GET"])
@jwt_required()
def history():
    scans = IAMExposureScan.query.filter_by(user_id=get_jwt_identity()).order_by(IAMExposureScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"cloud_provider":s.cloud_provider,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"identities_at_risk":s.identities_at_risk,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@iam_exposure_bp.route("/api/iam-exposure/health", methods=["GET"])
def health():
    return jsonify({"module":"IAM Exposure Analyzer","phase":"Wiz Gap — Phase 1","version":"1.0.0","rules":len(IAM_RULES),"status":"operational"}), 200
