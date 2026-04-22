# ============================================================
# AIPET X — Cloud Runtime Scanner (Wiz Gap — Phase 1)
# Runtime Threat Detection | Exposure Analysis | Zero Trust
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

cloud_runtime_bp = Blueprint("cloud_runtime", __name__)

class CloudRuntimeScan(db.Model):
    __tablename__ = "cloud_runtime_scans"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    cloud_provider= Column(String(32), default="aws")
    environment   = Column(String(64), default="production")
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="LOW")
    total_findings= Column(Integer, default=0)
    critical_count= Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    findings      = relationship("CloudRuntimeFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class CloudRuntimeFinding(db.Model):
    __tablename__ = "cloud_runtime_findings"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String(64), ForeignKey("cloud_runtime_scans.id"), nullable=False)
    category      = Column(String(64))
    title         = Column(String(256))
    severity      = Column(String(16))
    description   = Column(Text)
    resource      = Column(String(256), nullable=True)
    remediation   = Column(Text, nullable=True)
    wiz_ref       = Column(String(64), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

RUNTIME_RULES = [
    # Container Runtime
    {"id":"CRT-001","category":"Container Runtime","title":"Privileged Container Running","keywords":["privileged container","--privileged","privilege escalation","root container","privileged mode"],"severity":"CRITICAL","remediation":"Remove --privileged flag. Use specific Linux capabilities instead. Apply seccomp and AppArmor profiles.","wiz_ref":"WIZ-CRT-001"},
    {"id":"CRT-002","category":"Container Runtime","title":"Container Running as Root","keywords":["running as root","root user","uid 0","user root","no non-root"],"severity":"HIGH","remediation":"Add USER directive in Dockerfile. Run containers as non-root user (UID > 1000).","wiz_ref":"WIZ-CRT-002"},
    {"id":"CRT-003","category":"Container Runtime","title":"Writable Root Filesystem","keywords":["writable filesystem","read-only false","mutable container","write access root"],"severity":"HIGH","remediation":"Set readOnlyRootFilesystem: true in pod security context. Mount writable volumes only where needed.","wiz_ref":"WIZ-CRT-003"},
    {"id":"CRT-004","category":"Container Runtime","title":"No Resource Limits Set","keywords":["no resource limit","unlimited cpu","unlimited memory","no limits","resource quota missing"],"severity":"MEDIUM","remediation":"Set CPU and memory requests and limits on all containers to prevent resource exhaustion.","wiz_ref":"WIZ-CRT-004"},
    # Network Exposure
    {"id":"NET-001","category":"Network Exposure","title":"Public Endpoint Without Authentication","keywords":["public endpoint","unauthenticated api","no auth","open endpoint","publicly accessible api"],"severity":"CRITICAL","remediation":"Add authentication to all public endpoints. Implement API gateway with JWT or API key validation.","wiz_ref":"WIZ-NET-001"},
    {"id":"NET-002","category":"Network Exposure","title":"Exposed Database Port","keywords":["database port","3306","5432","27017","6379","exposed db","public database"],"severity":"CRITICAL","remediation":"Move database to private subnet. Block public access. Use VPC endpoints and security groups.","wiz_ref":"WIZ-NET-002"},
    {"id":"NET-003","category":"Network Exposure","title":"Unrestricted Egress Traffic","keywords":["unrestricted egress","all outbound","egress 0.0.0.0","open egress","no egress filter"],"severity":"HIGH","remediation":"Implement egress filtering. Allow only required outbound traffic. Use network policies in Kubernetes.","wiz_ref":"WIZ-NET-003"},
    {"id":"NET-004","category":"Network Exposure","title":"Service Mesh Not Enforcing mTLS","keywords":["no mtls","mtls disabled","plain text service","unencrypted service mesh","istio permissive"],"severity":"HIGH","remediation":"Enable STRICT mTLS mode in service mesh. Rotate certificates automatically every 24 hours.","wiz_ref":"WIZ-NET-004"},
    # IAM Runtime
    {"id":"IAM-001","category":"IAM Runtime","title":"Overly Permissive Workload Identity","keywords":["workload identity","service account admin","sa full access","workload admin role","overbroad iam"],"severity":"CRITICAL","remediation":"Apply least-privilege IAM to workload identities. Use Workload Identity Federation instead of static keys.","wiz_ref":"WIZ-IAM-001"},
    {"id":"IAM-002","category":"IAM Runtime","title":"Long-lived Credentials in Runtime","keywords":["static credential","long lived key","hardcoded credential","access key in pod","secret in env"],"severity":"CRITICAL","remediation":"Replace static credentials with dynamic short-lived tokens via IRSA/Workload Identity. Rotate all keys.","wiz_ref":"WIZ-IAM-002"},
    {"id":"IAM-003","category":"IAM Runtime","title":"No Pod Security Policy","keywords":["no pod security","psp disabled","pod security missing","no security context","admission controller"],"severity":"HIGH","remediation":"Enable Pod Security Admission. Apply restricted security profile to all namespaces.","wiz_ref":"WIZ-IAM-003"},
    # Data Exposure
    {"id":"DAT-001","category":"Data Exposure","title":"Unencrypted Data in Transit","keywords":["http not https","unencrypted transit","no tls","plain http","ssl disabled"],"severity":"CRITICAL","remediation":"Enforce TLS 1.2+ on all endpoints. Redirect HTTP to HTTPS. Use HSTS headers.","wiz_ref":"WIZ-DAT-001"},
    {"id":"DAT-002","category":"Data Exposure","title":"Secrets Exposed in Environment Variables","keywords":["secret in env","password env","api key environment","env var secret","plaintext secret env"],"severity":"CRITICAL","remediation":"Move secrets to Secrets Manager or Vault. Inject via CSI driver, not environment variables.","wiz_ref":"WIZ-DAT-002"},
    {"id":"DAT-003","category":"Data Exposure","title":"Sensitive Data in Logs","keywords":["password in log","credential in log","pii in log","card number log","secret logged"],"severity":"HIGH","remediation":"Implement log scrubbing. Use structured logging with field-level redaction for sensitive data.","wiz_ref":"WIZ-DAT-003"},
    # Vulnerability
    {"id":"VUL-001","category":"Vulnerability","title":"Critical CVE in Running Image","keywords":["cve","critical vulnerability","unpatched image","vulnerable image","outdated container"],"severity":"CRITICAL","remediation":"Rebuild image with patched base. Implement image scanning in CI/CD. Enforce admission control.","wiz_ref":"WIZ-VUL-001"},
    {"id":"VUL-002","category":"Vulnerability","title":"Outdated Base Image","keywords":["outdated image","old base","deprecated image","end of life","eol image","stale image"],"severity":"HIGH","remediation":"Update base image to latest LTS. Automate image rebuilds weekly. Use distroless where possible.","wiz_ref":"WIZ-VUL-002"},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}

def run_runtime_scan(description, provider):
    desc_lower = description.lower()
    findings = []
    for rule in RUNTIME_RULES:
        if any(kw in desc_lower for kw in rule["keywords"]):
            findings.append({
                "category":    rule["category"],
                "title":       rule["title"],
                "severity":    rule["severity"],
                "description": f"Runtime risk detected: {rule['title']}. Matched pattern in submitted cloud configuration.",
                "resource":    f"{provider.upper()} Runtime Resource",
                "remediation": rule["remediation"],
                "wiz_ref":     rule["wiz_ref"],
            })
    return findings

def calc_risk(findings):
    if not findings: return 0.0
    return round(min(sum(SEV_W.get(f["severity"],0) for f in findings) * 1.5, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@cloud_runtime_bp.route("/api/cloud-runtime/scan", methods=["POST"])
@jwt_required()
def scan():
    data     = request.get_json(silent=True) or {}
    provider = data.get("cloud_provider", "aws")
    env      = data.get("environment", "production")
    desc     = data.get("description", "")
    if not desc.strip(): return jsonify({"error":"No description provided"}), 400
    findings  = run_runtime_scan(desc, provider)
    score     = calc_risk(findings)
    sev       = overall_sev(score)
    critical  = sum(1 for f in findings if f["severity"] == "CRITICAL")
    summary   = f"Cloud Runtime Scan complete for {provider.upper()} {env}. Risk: {score}/100. {len(findings)} finding(s) — {critical} critical."
    s = CloudRuntimeScan(user_id=get_jwt_identity(), cloud_provider=provider, environment=env, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(CloudRuntimeFinding(scan_id=s.id, category=f["category"], title=f["title"], severity=f["severity"], description=f["description"], resource=f["resource"], remediation=f["remediation"], wiz_ref=f["wiz_ref"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"risk_score":score,"severity":sev,"total_findings":len(findings),"critical_count":critical,"summary":summary}), 200

@cloud_runtime_bp.route("/api/cloud-runtime/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = CloudRuntimeScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = CloudRuntimeFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"cloud_provider":s.cloud_provider,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"category":f.category,"title":f.title,"severity":f.severity,"description":f.description,"resource":f.resource,"remediation":f.remediation,"wiz_ref":f.wiz_ref} for f in findings]}), 200

@cloud_runtime_bp.route("/api/cloud-runtime/history", methods=["GET"])
@jwt_required()
def history():
    scans = CloudRuntimeScan.query.filter_by(user_id=get_jwt_identity()).order_by(CloudRuntimeScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"cloud_provider":s.cloud_provider,"environment":s.environment,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@cloud_runtime_bp.route("/api/cloud-runtime/health", methods=["GET"])
def health():
    return jsonify({"module":"Cloud Runtime Scanner","phase":"Wiz Gap — Phase 1","version":"1.0.0","rules":len(RUNTIME_RULES),"status":"operational"}), 200
