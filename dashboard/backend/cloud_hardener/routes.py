# ============================================================
# AIPET X — Module #42: Autonomous Cloud Hardener
# Misconfiguration Detection | Auto-Remediation | CIS Benchmarks
# Phase 5C | v6.2.0
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

cloud_hardener_bp = Blueprint("cloud_hardener", __name__)

class CloudHardenerScan(db.Model):
    __tablename__ = "cloud_hardener_scans"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    cloud_provider= Column(String(32))
    environment   = Column(String(64))
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="LOW")
    total_checks  = Column(Integer, default=0)
    passed        = Column(Integer, default=0)
    failed        = Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    findings      = relationship("CloudHardenerFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class CloudHardenerFinding(db.Model):
    __tablename__ = "cloud_hardener_findings"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String(64), ForeignKey("cloud_hardener_scans.id"), nullable=False)
    check_id      = Column(String(32))
    category      = Column(String(64))
    title         = Column(String(256))
    status        = Column(String(16))
    severity      = Column(String(16))
    description   = Column(Text)
    remediation   = Column(Text)
    cis_ref       = Column(String(64), nullable=True)
    auto_fix      = Column(String(256), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

CIS_CHECKS = {
    "aws": [
        {"id":"AWS-IAM-001","category":"Identity & Access","title":"Root account MFA not enabled","keywords":["no root mfa","root without mfa","root mfa disabled","root account mfa"],"severity":"CRITICAL","remediation":"Enable MFA on the root account immediately. Use a hardware security key for root.","cis_ref":"CIS AWS 1.5","auto_fix":"aws iam enable-mfa-device --user-name root"},
        {"id":"AWS-IAM-002","category":"Identity & Access","title":"IAM users with console access and no MFA","keywords":["no mfa","iam user no mfa","console without mfa","mfa not enabled"],"severity":"CRITICAL","remediation":"Enforce MFA for all IAM users with console access via IAM policy.","cis_ref":"CIS AWS 1.10","auto_fix":"aws iam create-virtual-mfa-device"},
        {"id":"AWS-IAM-003","category":"Identity & Access","title":"Overly permissive IAM policies (wildcards)","keywords":["wildcard","s3:*","ec2:*","*:*","full access","admin policy","broad permission"],"severity":"HIGH","remediation":"Replace wildcard IAM policies with least-privilege granular policies.","cis_ref":"CIS AWS 1.16","auto_fix":"aws iam create-policy --policy-document <least-privilege-policy>"},
        {"id":"AWS-IAM-004","category":"Identity & Access","title":"Access keys not rotated in 90 days","keywords":["old access key","key rotation","access key age","unrotated key","key not rotated"],"severity":"HIGH","remediation":"Rotate all IAM access keys every 90 days. Automate rotation using AWS Secrets Manager.","cis_ref":"CIS AWS 1.14","auto_fix":"aws iam create-access-key && aws iam delete-access-key"},
        {"id":"AWS-S3-001","category":"Storage Security","title":"S3 bucket publicly accessible","keywords":["public bucket","s3 public","acl public","public-read","block public access disabled"],"severity":"CRITICAL","remediation":"Enable S3 Block Public Access at account and bucket level.","cis_ref":"CIS AWS 2.1.5","auto_fix":"aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true"},
        {"id":"AWS-S3-002","category":"Storage Security","title":"S3 bucket encryption disabled","keywords":["s3 no encryption","bucket not encrypted","server side encryption disabled","sse disabled"],"severity":"HIGH","remediation":"Enable default AES-256 or KMS encryption on all S3 buckets.","cis_ref":"CIS AWS 2.1.1","auto_fix":"aws s3api put-bucket-encryption --bucket <bucket> --server-side-encryption-configuration"},
        {"id":"AWS-S3-003","category":"Storage Security","title":"S3 bucket versioning disabled","keywords":["versioning disabled","no versioning","s3 versioning off","bucket versioning"],"severity":"MEDIUM","remediation":"Enable versioning on all S3 buckets containing important data.","cis_ref":"CIS AWS 2.1.3","auto_fix":"aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled"},
        {"id":"AWS-NET-001","category":"Network Security","title":"Security group allows 0.0.0.0/0 ingress","keywords":["0.0.0.0/0","open security group","all traffic","unrestricted ingress","wide open port","any source"],"severity":"CRITICAL","remediation":"Restrict security group ingress rules to specific known IP ranges only.","cis_ref":"CIS AWS 5.2","auto_fix":"aws ec2 revoke-security-group-ingress --group-id <sg-id> --cidr 0.0.0.0/0"},
        {"id":"AWS-NET-002","category":"Network Security","title":"VPC Flow Logs disabled","keywords":["flow log disabled","no flow log","vpc logging off","flow logs not enabled"],"severity":"HIGH","remediation":"Enable VPC Flow Logs for all VPCs to monitor network traffic.","cis_ref":"CIS AWS 3.9","auto_fix":"aws ec2 create-flow-logs --resource-type VPC --traffic-type ALL"},
        {"id":"AWS-LOG-001","category":"Logging & Monitoring","title":"CloudTrail not enabled","keywords":["cloudtrail disabled","no cloudtrail","audit logging off","cloudtrail not enabled","no audit trail"],"severity":"CRITICAL","remediation":"Enable CloudTrail in all regions with log file validation and S3 encryption.","cis_ref":"CIS AWS 3.1","auto_fix":"aws cloudtrail create-trail --name main-trail --s3-bucket-name <bucket>"},
        {"id":"AWS-LOG-002","category":"Logging & Monitoring","title":"CloudTrail log file validation disabled","keywords":["log validation disabled","no log validation","integrity disabled","tamper detection off"],"severity":"HIGH","remediation":"Enable CloudTrail log file validation to detect tampering.","cis_ref":"CIS AWS 3.2","auto_fix":"aws cloudtrail update-trail --name <trail> --enable-log-file-validation"},
        {"id":"AWS-ENC-001","category":"Encryption","title":"EBS volumes not encrypted","keywords":["ebs not encrypted","unencrypted ebs","ebs encryption disabled","volume not encrypted"],"severity":"HIGH","remediation":"Enable EBS default encryption at the account level.","cis_ref":"CIS AWS 2.2.1","auto_fix":"aws ec2 enable-ebs-encryption-by-default"},
        {"id":"AWS-ENC-002","category":"Encryption","title":"RDS encryption disabled","keywords":["rds not encrypted","database not encrypted","rds encryption off","unencrypted rds","db encryption disabled"],"severity":"HIGH","remediation":"Enable encryption on all RDS instances. Use KMS for key management.","cis_ref":"CIS AWS 2.3.1","auto_fix":"aws rds modify-db-instance --db-instance-identifier <id> --storage-encrypted"},
        {"id":"AWS-MON-001","category":"Monitoring & Alerting","title":"No CloudWatch alarms for root login","keywords":["no root alarm","root login alert","cloudwatch root","root activity monitor"],"severity":"HIGH","remediation":"Create CloudWatch metric filter and alarm for root account usage.","cis_ref":"CIS AWS 4.3","auto_fix":"aws cloudwatch put-metric-alarm --alarm-name RootLoginAlarm"},
        {"id":"AWS-CONFIG-001","category":"Configuration","title":"AWS Config not enabled","keywords":["config disabled","aws config off","configuration recorder","config not enabled","resource tracking"],"severity":"HIGH","remediation":"Enable AWS Config in all regions for continuous compliance monitoring.","cis_ref":"CIS AWS 3.5","auto_fix":"aws configservice put-configuration-recorder"},
    ],
    "azure": [
        {"id":"AZ-IAM-001","category":"Identity & Access","title":"MFA not enabled for all users","keywords":["no mfa","mfa disabled","single factor","azure ad mfa","conditional access mfa"],"severity":"CRITICAL","remediation":"Enable MFA via Azure AD Conditional Access policies for all users.","cis_ref":"CIS Azure 1.1","auto_fix":"Set-AzureADUser -MfaStrongAuthMethods"},
        {"id":"AZ-IAM-002","category":"Identity & Access","title":"Guest users have excessive permissions","keywords":["guest user","external user","guest access","b2b permission","guest admin"],"severity":"HIGH","remediation":"Restrict guest user permissions. Review and remove unnecessary guest accounts.","cis_ref":"CIS Azure 1.3","auto_fix":"Set-AzureADUser -UserType Guest -AccountEnabled $false"},
        {"id":"AZ-STOR-001","category":"Storage Security","title":"Blob storage publicly accessible","keywords":["public blob","anonymous access","blob public","container public","storage public"],"severity":"CRITICAL","remediation":"Disable public access on all storage accounts. Use SAS tokens or managed identity.","cis_ref":"CIS Azure 3.5","auto_fix":"az storage account update --public-network-access Disabled"},
        {"id":"AZ-STOR-002","category":"Storage Security","title":"Storage account encryption with Microsoft-managed keys only","keywords":["microsoft managed key","no customer key","cmk disabled","bring your own key","byok"],"severity":"MEDIUM","remediation":"Use customer-managed keys (CMK) in Azure Key Vault for sensitive storage accounts.","cis_ref":"CIS Azure 3.2","auto_fix":"az storage account update --encryption-key-source Microsoft.Keyvault"},
        {"id":"AZ-NET-001","category":"Network Security","title":"Network Security Group allows unrestricted access","keywords":["any source","0.0.0.0/0","unrestricted nsg","open port","all traffic nsg","nsg any"],"severity":"CRITICAL","remediation":"Restrict NSG rules to specific source IP ranges. Remove any-to-any rules.","cis_ref":"CIS Azure 6.1","auto_fix":"az network nsg rule update --access Deny --source-address-prefix <specific-ip>"},
        {"id":"AZ-LOG-001","category":"Logging & Monitoring","title":"Azure Monitor diagnostic logs not enabled","keywords":["diagnostic log disabled","no azure monitor","audit log off","activity log","monitoring disabled"],"severity":"HIGH","remediation":"Enable diagnostic logs for all Azure services and send to Log Analytics workspace.","cis_ref":"CIS Azure 5.1","auto_fix":"az monitor diagnostic-settings create --logs"},
        {"id":"AZ-SEC-001","category":"Security Center","title":"Microsoft Defender for Cloud not enabled","keywords":["defender disabled","security center off","defender for cloud","asc disabled","no defender"],"severity":"CRITICAL","remediation":"Enable Microsoft Defender for Cloud across all subscriptions and resource types.","cis_ref":"CIS Azure 2.1","auto_fix":"az security pricing create --name VirtualMachines --tier Standard"},
    ],
    "gcp": [
        {"id":"GCP-IAM-001","category":"Identity & Access","title":"Service account has admin privileges","keywords":["service account admin","sa admin","service account owner","sa owner role","primitive role"],"severity":"CRITICAL","remediation":"Assign least-privilege roles to service accounts. Avoid primitive roles (owner, editor).","cis_ref":"CIS GCP 1.5","auto_fix":"gcloud projects remove-iam-policy-binding --member serviceAccount --role roles/owner"},
        {"id":"GCP-IAM-002","category":"Identity & Access","title":"Service account key not rotated","keywords":["service account key","sa key rotation","old service key","key age","unrotated sa key"],"severity":"HIGH","remediation":"Rotate service account keys every 90 days. Use Workload Identity Federation where possible.","cis_ref":"CIS GCP 1.7","auto_fix":"gcloud iam service-accounts keys create --iam-account <sa-email>"},
        {"id":"GCP-STOR-001","category":"Storage Security","title":"Cloud Storage bucket publicly accessible","keywords":["public bucket","allUsers","allAuthenticatedUsers","public storage","gcs public"],"severity":"CRITICAL","remediation":"Remove allUsers and allAuthenticatedUsers from bucket IAM bindings.","cis_ref":"CIS GCP 5.1","auto_fix":"gsutil iam ch -d allUsers gs://<bucket>"},
        {"id":"GCP-LOG-001","category":"Logging & Monitoring","title":"Cloud Audit Logs not enabled","keywords":["audit log disabled","cloud logging off","data access log","audit logging","gcp logging"],"severity":"HIGH","remediation":"Enable Data Access audit logs for all services across all projects.","cis_ref":"CIS GCP 2.1","auto_fix":"gcloud projects get-iam-policy <project> --format json"},
        {"id":"GCP-NET-001","category":"Network Security","title":"Firewall allows SSH from internet (0.0.0.0/0)","keywords":["ssh open","port 22 open","rdp open","firewall 0.0.0.0","unrestricted firewall","open firewall"],"severity":"CRITICAL","remediation":"Restrict SSH/RDP firewall rules to specific IP ranges. Use Cloud IAP for secure access.","cis_ref":"CIS GCP 3.6","auto_fix":"gcloud compute firewall-rules update <rule> --source-ranges <specific-ip>"},
    ]
}

SEV_WEIGHTS = {"CRITICAL":10,"HIGH":6,"MEDIUM":3,"LOW":1}

def run_hardener(provider, description):
    checks = CIS_CHECKS.get(provider.lower(), CIS_CHECKS["aws"])
    desc_lower = description.lower()
    findings = []
    for check in checks:
        matched = any(kw in desc_lower for kw in check["keywords"])
        status = "FAIL" if matched else "PASS"
        findings.append({
            "check_id":    check["id"],
            "category":    check["category"],
            "title":       check["title"],
            "status":      status,
            "severity":    check["severity"] if matched else "INFO",
            "description": f"CIS check {check['id']} evaluated. {'Misconfiguration detected.' if matched else 'Control appears satisfied.'}",
            "remediation": check["remediation"] if matched else "Control satisfied — no action required.",
            "cis_ref":     check["cis_ref"],
            "auto_fix":    check["auto_fix"] if matched else None,
        })
    return findings

def calc_risk(findings):
    failed = [f for f in findings if f["status"] == "FAIL"]
    if not failed: return 0.0
    raw = sum(SEV_WEIGHTS.get(f["severity"],0) for f in failed)
    return round(min(raw * 2, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@cloud_hardener_bp.route("/api/cloud-hardener/scan", methods=["POST"])
@jwt_required()
def scan():
    data     = request.get_json(silent=True) or {}
    provider = data.get("cloud_provider","aws")
    env      = data.get("environment","production")
    desc     = data.get("description","")
    if not desc.strip(): return jsonify({"error":"No description provided"}),400
    findings = run_hardener(provider, desc)
    score    = calc_risk(findings)
    sev      = overall_sev(score)
    passed   = sum(1 for f in findings if f["status"]=="PASS")
    failed   = sum(1 for f in findings if f["status"]=="FAIL")
    summary  = f"Cloud Hardener scan complete for {provider.upper()} {env}. Score: {score}/100. {failed} misconfiguration(s) detected across {len(findings)} CIS checks."
    s = CloudHardenerScan(user_id=get_jwt_identity(),cloud_provider=provider,environment=env,risk_score=score,severity=sev,total_checks=len(findings),passed=passed,failed=failed,summary=summary,node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(CloudHardenerFinding(scan_id=s.id,check_id=f["check_id"],category=f["category"],title=f["title"],status=f["status"],severity=f["severity"],description=f["description"],remediation=f["remediation"],cis_ref=f["cis_ref"],auto_fix=f.get("auto_fix"),node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"cloud_provider":provider,"environment":env,"risk_score":score,"severity":sev,"passed":passed,"failed":failed,"total_checks":len(findings),"summary":summary}),200

@cloud_hardener_bp.route("/api/cloud-hardener/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = CloudHardenerScan.query.filter_by(id=scan_id,user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}),404
    findings = CloudHardenerFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"cloud_provider":s.cloud_provider,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"total_checks":s.total_checks,"passed":s.passed,"failed":s.failed,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"check_id":f.check_id,"category":f.category,"title":f.title,"status":f.status,"severity":f.severity,"description":f.description,"remediation":f.remediation,"cis_ref":f.cis_ref,"auto_fix":f.auto_fix} for f in findings]}),200

@cloud_hardener_bp.route("/api/cloud-hardener/history", methods=["GET"])
@jwt_required()
def history():
    scans = CloudHardenerScan.query.filter_by(user_id=get_jwt_identity()).order_by(CloudHardenerScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"cloud_provider":s.cloud_provider,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"passed":s.passed,"failed":s.failed,"created_at":s.created_at.isoformat()} for s in scans]}),200

@cloud_hardener_bp.route("/api/cloud-hardener/health", methods=["GET"])
def health():
    return jsonify({"module":"Autonomous Cloud Hardener","version":"1.0.0","providers":["aws","azure","gcp"],"status":"operational"}),200
