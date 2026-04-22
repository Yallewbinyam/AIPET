# ============================================================
# AIPET X — Kubernetes Runtime Analyzer (Wiz Gap — Phase 1)
# K8s Security | Pod Analysis | RBAC | Network Policy
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

k8s_analyzer_bp = Blueprint("k8s_analyzer", __name__)

class K8sScan(db.Model):
    __tablename__ = "k8s_scans"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    cluster_name  = Column(String(256), default="my-cluster")
    k8s_version   = Column(String(32), default="unknown")
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="LOW")
    total_findings= Column(Integer, default=0)
    critical_count= Column(Integer, default=0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    findings      = relationship("K8sFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class K8sFinding(db.Model):
    __tablename__ = "k8s_findings"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String(64), ForeignKey("k8s_scans.id"), nullable=False)
    category      = Column(String(64))
    title         = Column(String(256))
    severity      = Column(String(16))
    resource_type = Column(String(64))
    namespace     = Column(String(128), nullable=True)
    description   = Column(Text)
    remediation   = Column(Text)
    cis_ref       = Column(String(64), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

K8S_RULES = [
    # Pod Security
    {"id":"K8S-POD-001","category":"Pod Security","title":"Privileged Pod Running","keywords":["privileged pod","privileged: true","privilege escalation","allowPrivilegeEscalation"],"severity":"CRITICAL","resource":"Pod","remediation":"Set privileged: false and allowPrivilegeEscalation: false in securityContext.","cis":"CIS K8s 5.2.1"},
    {"id":"K8S-POD-002","category":"Pod Security","title":"Pod Running as Root","keywords":["runAsRoot","run as root","runAsUser: 0","root user pod","no runAsNonRoot"],"severity":"HIGH","resource":"Pod","remediation":"Set runAsNonRoot: true and runAsUser > 1000 in pod securityContext.","cis":"CIS K8s 5.2.6"},
    {"id":"K8S-POD-003","category":"Pod Security","title":"Host Network Access Enabled","keywords":["hostNetwork: true","host network","hostPID","hostIPC","host namespace"],"severity":"CRITICAL","resource":"Pod","remediation":"Set hostNetwork: false. Never share host namespaces with containers.","cis":"CIS K8s 5.2.4"},
    {"id":"K8S-POD-004","category":"Pod Security","title":"No Liveness or Readiness Probe","keywords":["no liveness","no readiness","missing probe","no health check","probe not configured"],"severity":"LOW","resource":"Pod","remediation":"Add livenessProbe and readinessProbe to all container specs.","cis":"CIS K8s 5.4.1"},
    {"id":"K8S-POD-005","category":"Pod Security","title":"Writable Root Filesystem","keywords":["readOnlyRootFilesystem: false","writable root","mutable filesystem","no read only root"],"severity":"HIGH","resource":"Pod","remediation":"Set readOnlyRootFilesystem: true in container securityContext.","cis":"CIS K8s 5.2.7"},
    # RBAC
    {"id":"K8S-RBAC-001","category":"RBAC","title":"ClusterAdmin Role Binding","keywords":["cluster-admin","clusteradmin","cluster admin binding","wildcard role","* verbs"],"severity":"CRITICAL","resource":"ClusterRoleBinding","remediation":"Remove cluster-admin bindings. Apply least-privilege RBAC. Use namespace-scoped roles.","cis":"CIS K8s 5.1.1"},
    {"id":"K8S-RBAC-002","category":"RBAC","title":"Service Account with Excessive Permissions","keywords":["service account","sa permission","automountServiceAccountToken","sa cluster role","broad sa"],"severity":"HIGH","resource":"ServiceAccount","remediation":"Set automountServiceAccountToken: false. Bind only required permissions to service accounts.","cis":"CIS K8s 5.1.6"},
    {"id":"K8S-RBAC-003","category":"RBAC","title":"Default Service Account Used","keywords":["default service account","default sa","no dedicated sa","using default account"],"severity":"MEDIUM","resource":"ServiceAccount","remediation":"Create dedicated service accounts per workload. Disable default service account token mounting.","cis":"CIS K8s 5.1.5"},
    {"id":"K8S-RBAC-004","category":"RBAC","title":"Wildcard Permissions in Role","keywords":["wildcard permission","* resources","* verbs","all verbs","all resources role"],"severity":"CRITICAL","resource":"Role","remediation":"Replace wildcard permissions with explicit resource and verb lists. Apply principle of least privilege.","cis":"CIS K8s 5.1.3"},
    # Network Policy
    {"id":"K8S-NET-001","category":"Network Policy","title":"No Network Policy Defined","keywords":["no network policy","missing networkpolicy","no ingress policy","no egress policy","unrestricted pod communication"],"severity":"HIGH","resource":"NetworkPolicy","remediation":"Define NetworkPolicy for all namespaces. Start with default-deny-all and allow only required traffic.","cis":"CIS K8s 5.3.2"},
    {"id":"K8S-NET-002","category":"Network Policy","title":"All Ingress Traffic Allowed","keywords":["allow all ingress","ingress from all","0.0.0.0 ingress","open ingress","unrestricted ingress pod"],"severity":"HIGH","resource":"NetworkPolicy","remediation":"Restrict ingress to specific namespaces and pods. Apply namespace selector in NetworkPolicy.","cis":"CIS K8s 5.3.1"},
    {"id":"K8S-NET-003","category":"Network Policy","title":"All Egress Traffic Allowed","keywords":["allow all egress","egress to all","open egress pod","unrestricted egress pod","no egress policy"],"severity":"HIGH","resource":"NetworkPolicy","remediation":"Restrict egress to required destinations. Block unexpected outbound connections from pods.","cis":"CIS K8s 5.3.1"},
    # Secrets Management
    {"id":"K8S-SEC-001","category":"Secrets Management","title":"Secrets Not Encrypted at Rest","keywords":["etcd not encrypted","secrets not encrypted","no encryption provider","secret encryption disabled","etcd plaintext"],"severity":"CRITICAL","resource":"Secret","remediation":"Enable EncryptionConfiguration for etcd. Use KMS provider for envelope encryption of secrets.","cis":"CIS K8s 1.2.33"},
    {"id":"K8S-SEC-002","category":"Secrets Management","title":"Secret Mounted as Environment Variable","keywords":["secret env var","secretKeyRef","env from secret","secret in env","mountsecret env"],"severity":"HIGH","resource":"Pod","remediation":"Mount secrets as files via CSI driver, not environment variables. Use Vault agent injector.","cis":"CIS K8s 5.4.1"},
    {"id":"K8S-SEC-003","category":"Secrets Management","title":"Secret in ConfigMap","keywords":["secret in configmap","password configmap","credential configmap","api key configmap","token configmap"],"severity":"CRITICAL","resource":"ConfigMap","remediation":"Move all secrets from ConfigMaps to Kubernetes Secrets or external secret manager.","cis":"CIS K8s 5.4.1"},
    # Control Plane
    {"id":"K8S-CP-001","category":"Control Plane","title":"API Server Anonymous Auth Enabled","keywords":["anonymous auth","--anonymous-auth=true","anonymous request","unauthenticated api","no auth api server"],"severity":"CRITICAL","resource":"APIServer","remediation":"Set --anonymous-auth=false on API server. Require authentication for all API requests.","cis":"CIS K8s 1.2.1"},
    {"id":"K8S-CP-002","category":"Control Plane","title":"Audit Logging Disabled","keywords":["audit log disabled","no audit","audit policy missing","--audit-log-path missing","k8s audit off"],"severity":"HIGH","resource":"APIServer","remediation":"Enable audit logging with comprehensive policy. Send logs to centralized SIEM.","cis":"CIS K8s 1.2.22"},
    {"id":"K8S-CP-003","category":"Control Plane","title":"Admission Controllers Not Configured","keywords":["no admission controller","admission disabled","no pod security admission","no opa","no gatekeeper"],"severity":"HIGH","resource":"APIServer","remediation":"Enable Pod Security Admission. Deploy OPA Gatekeeper for policy enforcement.","cis":"CIS K8s 1.2.10"},
    # Image Security
    {"id":"K8S-IMG-001","category":"Image Security","title":"Image Pulled Without Digest","keywords":["latest tag","no image digest","mutable tag","image tag latest","no sha256 digest"],"severity":"MEDIUM","resource":"Pod","remediation":"Pin all images to specific SHA256 digest. Never use :latest tag in production.","cis":"CIS K8s 5.5.1"},
    {"id":"K8S-IMG-002","category":"Image Security","title":"No Image Scanning Policy","keywords":["no image scan","image scan disabled","unscanned image","no trivy","no image policy"],"severity":"HIGH","resource":"Pod","remediation":"Integrate Trivy or Snyk into CI/CD. Block deployment of images with critical CVEs.","cis":"CIS K8s 5.5.1"},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}

def run_k8s_scan(description, cluster_name):
    desc_lower = description.lower()
    findings = []
    for rule in K8S_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({
                "category":     rule["category"],
                "title":        rule["title"],
                "severity":     rule["severity"],
                "resource_type":rule["resource"],
                "namespace":    "default",
                "description":  f"Kubernetes misconfiguration detected: {rule['title']} in cluster {cluster_name}.",
                "remediation":  rule["remediation"],
                "cis_ref":      rule["cis"],
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

@k8s_analyzer_bp.route("/api/k8s/scan", methods=["POST"])
@jwt_required()
def scan():
    data         = request.get_json(silent=True) or {}
    cluster_name = data.get("cluster_name", "my-cluster")
    k8s_version  = data.get("k8s_version", "1.28")
    desc         = data.get("description", "")
    if not desc.strip(): return jsonify({"error":"No description provided"}), 400
    findings  = run_k8s_scan(desc, cluster_name)
    score     = calc_risk(findings)
    sev       = overall_sev(score)
    critical  = sum(1 for f in findings if f["severity"] == "CRITICAL")
    summary   = f"K8s Runtime Analysis complete for cluster {cluster_name} (v{k8s_version}). Risk: {score}/100. {len(findings)} finding(s) — {critical} critical across {len(set(f['category'] for f in findings))} categories."
    s = K8sScan(user_id=get_jwt_identity(), cluster_name=cluster_name, k8s_version=k8s_version, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(K8sFinding(scan_id=s.id, category=f["category"], title=f["title"], severity=f["severity"], resource_type=f["resource_type"], namespace=f["namespace"], description=f["description"], remediation=f["remediation"], cis_ref=f["cis_ref"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"cluster_name":cluster_name,"risk_score":score,"severity":sev,"total_findings":len(findings),"critical_count":critical,"summary":summary}), 200

@k8s_analyzer_bp.route("/api/k8s/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = K8sScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = K8sFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"cluster_name":s.cluster_name,"k8s_version":s.k8s_version,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"category":f.category,"title":f.title,"severity":f.severity,"resource_type":f.resource_type,"namespace":f.namespace,"description":f.description,"remediation":f.remediation,"cis_ref":f.cis_ref} for f in findings]}), 200

@k8s_analyzer_bp.route("/api/k8s/history", methods=["GET"])
@jwt_required()
def history():
    scans = K8sScan.query.filter_by(user_id=get_jwt_identity()).order_by(K8sScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"cluster_name":s.cluster_name,"k8s_version":s.k8s_version,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@k8s_analyzer_bp.route("/api/k8s/health", methods=["GET"])
def health():
    return jsonify({"module":"Kubernetes Runtime Analyzer","phase":"Wiz Gap — Phase 1","version":"1.0.0","rules":len(K8S_RULES),"status":"operational"}), 200
