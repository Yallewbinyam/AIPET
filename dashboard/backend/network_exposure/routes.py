# ============================================================
# AIPET X — Cloud Network Exposure Graph (Wiz Gap — Phase 1)
# Network Topology | Exposure Paths | Attack Surface Mapping
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

network_exposure_bp = Blueprint("network_exposure", __name__)

class NetworkExposureScan(db.Model):
    __tablename__ = "network_exposure_scans"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(Integer, nullable=False)
    environment    = Column(String(64), default="production")
    cloud_provider = Column(String(32), default="aws")
    risk_score     = Column(Float, default=0.0)
    severity       = Column(String(16), default="LOW")
    total_paths    = Column(Integer, default=0)
    critical_paths = Column(Integer, default=0)
    exposed_assets = Column(Integer, default=0)
    summary        = Column(Text, nullable=True)
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta      = Column(Text, default="{}")
    paths          = relationship("NetworkExposurePath", backref="scan", lazy=True, cascade="all, delete-orphan")
    assets         = relationship("NetworkExposureAsset", backref="scan", lazy=True, cascade="all, delete-orphan")

class NetworkExposurePath(db.Model):
    __tablename__ = "network_exposure_paths"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(64), ForeignKey("network_exposure_scans.id"), nullable=False)
    path_type      = Column(String(64))
    source         = Column(String(256))
    destination    = Column(String(256))
    severity       = Column(String(16))
    protocol       = Column(String(32), nullable=True)
    port           = Column(String(32), nullable=True)
    description    = Column(Text)
    remediation    = Column(Text)
    node_meta      = Column(Text, default="{}")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

class NetworkExposureAsset(db.Model):
    __tablename__ = "network_exposure_assets"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(64), ForeignKey("network_exposure_scans.id"), nullable=False)
    asset_type     = Column(String(64))
    asset_name     = Column(String(256))
    exposure_level = Column(String(32))
    public_ip      = Column(String(64), nullable=True)
    open_ports     = Column(Text, nullable=True)
    risk_level     = Column(String(16))
    node_meta      = Column(Text, default="{}")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

EXPOSURE_RULES = [
    {"type":"Internet Exposure","title":"Database Directly Exposed to Internet","keywords":["database internet","rds public","db exposed","database public","mysql internet","postgres internet","mongo exposed"],"severity":"CRITICAL","source":"Internet","dest":"Database","protocol":"TCP","port":"3306/5432/27017","remediation":"Move database to private subnet. Use VPC endpoints. Allow only app tier access via security group."},
    {"type":"Internet Exposure","title":"Admin Port Exposed to Internet","keywords":["ssh internet","rdp internet","port 22 public","port 3389 public","admin port exposed","management port internet"],"severity":"CRITICAL","source":"Internet","dest":"Admin Interface","protocol":"TCP","port":"22/3389","remediation":"Restrict SSH/RDP to VPN or bastion host only. Use Systems Manager Session Manager instead."},
    {"type":"Internet Exposure","title":"Internal API Exposed Without WAF","keywords":["api no waf","internal api public","api exposed","no web application firewall","api internet no protection"],"severity":"HIGH","source":"Internet","dest":"Internal API","protocol":"HTTPS","port":"443","remediation":"Place WAF in front of all public APIs. Enable OWASP rule sets. Add rate limiting and DDoS protection."},
    {"type":"Internet Exposure","title":"Storage Bucket Publicly Readable","keywords":["s3 public","bucket exposed","public storage","blob public","gcs public","storage internet"],"severity":"CRITICAL","source":"Internet","dest":"Storage Bucket","protocol":"HTTPS","port":"443","remediation":"Enable Block Public Access. Remove public ACLs. Use pre-signed URLs for authorized access."},
    {"type":"Lateral Movement","title":"Unrestricted East-West Traffic","keywords":["east west","lateral movement","no segmentation","flat network","unrestricted vpc","no micro segmentation"],"severity":"HIGH","source":"Compromised Host","dest":"Internal Services","protocol":"ANY","port":"ANY","remediation":"Implement micro-segmentation. Deploy Zero Trust network policies. Restrict service-to-service communication."},
    {"type":"Lateral Movement","title":"Overly Permissive Security Group","keywords":["security group all","sg 0.0.0.0","permissive sg","open security group","sg any source","allow all sg"],"severity":"HIGH","source":"Any Source","dest":"Internal Resources","protocol":"ANY","port":"ALL","remediation":"Restrict security groups to minimum required ports and source IPs. Remove any 0.0.0.0/0 ingress rules."},
    {"type":"Data Exfiltration","title":"Unrestricted Outbound Internet Access","keywords":["unrestricted outbound","open egress","all outbound allowed","no egress filter","internet egress unrestricted"],"severity":"HIGH","source":"Internal Network","dest":"Internet","protocol":"ANY","port":"ANY","remediation":"Implement egress filtering via NAT Gateway with restricted routes. Block unexpected outbound connections."},
    {"type":"Data Exfiltration","title":"DNS Exfiltration Path Available","keywords":["dns tunnel","dns exfil","dns over https","unrestricted dns","dns bypass"],"severity":"HIGH","source":"Internal Host","dest":"External DNS","protocol":"UDP","port":"53","remediation":"Use DNS firewall to block suspicious domains. Monitor DNS query volume. Block direct internet DNS."},
    {"type":"Privilege Path","title":"Public-to-Admin Privilege Escalation Path","keywords":["privilege escalation path","public to admin","internet to privileged","escalation path","hop to admin"],"severity":"CRITICAL","source":"Internet","dest":"Admin/Root Access","protocol":"HTTPS","port":"443","remediation":"Break the escalation path. Enforce MFA on all privileged access. Deploy PAM solution."},
    {"type":"Privilege Path","title":"Service Account Internet Reachable","keywords":["service account public","sa internet","workload identity exposed","sa reachable internet","exposed workload identity"],"severity":"CRITICAL","source":"Internet","dest":"Service Account","protocol":"HTTPS","port":"443","remediation":"Restrict service account usage to internal workloads only. Use Workload Identity Federation."},
    {"type":"Unencrypted Traffic","title":"Unencrypted Internal Traffic","keywords":["http internal","unencrypted internal","plain text traffic","no tls internal","http not https internal"],"severity":"MEDIUM","source":"Internal Service A","dest":"Internal Service B","protocol":"HTTP","port":"80","remediation":"Enforce TLS for all internal traffic. Deploy service mesh with mTLS. Redirect HTTP to HTTPS."},
    {"type":"Unencrypted Traffic","title":"Load Balancer Accepting HTTP","keywords":["lb http","load balancer http","alb http","elb http","http listener","no https redirect"],"severity":"MEDIUM","source":"Internet","dest":"Load Balancer","protocol":"HTTP","port":"80","remediation":"Remove HTTP listener. Enforce HTTPS only. Add HTTP to HTTPS redirect rule. Enable HSTS."},
]

ASSET_RULES = [
    {"asset":"Web Server","keywords":["web server","nginx","apache","httpd","web tier"],"exposure":"Public","ports":"80,443"},
    {"asset":"Database Server","keywords":["database","rds","mysql","postgres","mongodb","redis"],"exposure":"Should be Private","ports":"3306,5432,27017,6379"},
    {"asset":"Kubernetes API","keywords":["k8s api","kubernetes api","api server","kubectl","kube-apiserver"],"exposure":"Should be Private","ports":"6443"},
    {"asset":"Admin Console","keywords":["admin console","management ui","admin panel","control plane","bastion"],"exposure":"Restricted","ports":"22,3389,8443"},
    {"asset":"Storage Bucket","keywords":["s3","gcs","blob","storage bucket","object storage"],"exposure":"Should be Private","ports":"443"},
    {"asset":"Message Queue","keywords":["kafka","sqs","rabbitmq","mq","queue","pubsub"],"exposure":"Should be Private","ports":"9092,5672"},
    {"asset":"Cache Layer","keywords":["redis","memcached","elasticache","cache","in-memory"],"exposure":"Should be Private","ports":"6379,11211"},
    {"asset":"CI/CD Pipeline","keywords":["jenkins","gitlab","github actions","cicd","pipeline","build server"],"exposure":"Restricted","ports":"8080,443"},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}

def run_exposure_scan(description, provider, environment):
    desc_lower = description.lower()
    paths, assets = [], []

    for rule in EXPOSURE_RULES:
        if any(kw in desc_lower for kw in rule["keywords"]):
            paths.append({
                "path_type":   rule["type"],
                "source":      rule["source"],
                "destination": rule["dest"],
                "severity":    rule["severity"],
                "protocol":    rule["protocol"],
                "port":        rule["port"],
                "description": f"Exposure path detected: {rule['title']} in {environment} {provider.upper()} environment.",
                "remediation": rule["remediation"],
            })

    for asset in ASSET_RULES:
        if any(kw in desc_lower for kw in asset["keywords"]):
            is_exposed = any(kw in desc_lower for kw in ["exposed","public","internet","open","0.0.0.0"])
            assets.append({
                "asset_type":    asset["asset"],
                "asset_name":    f"{asset['asset']} ({environment})",
                "exposure_level":asset["exposure"] if not is_exposed else "PUBLIC — EXPOSED",
                "public_ip":     "0.0.0.0" if is_exposed else "Private",
                "open_ports":    asset["ports"],
                "risk_level":    "CRITICAL" if is_exposed and "Private" in asset["exposure"] else "MEDIUM",
            })

    return paths, assets

def calc_risk(paths):
    if not paths: return 0.0
    return round(min(sum(SEV_W.get(p["severity"],0) for p in paths) * 1.5, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@network_exposure_bp.route("/api/network-exposure/scan", methods=["POST"])
@jwt_required()
def scan():
    data     = request.get_json(silent=True) or {}
    provider = data.get("cloud_provider", "aws")
    env      = data.get("environment", "production")
    desc     = data.get("description", "")
    if not desc.strip(): return jsonify({"error":"No description provided"}), 400

    paths, assets = run_exposure_scan(desc, provider, env)
    score    = calc_risk(paths)
    sev      = overall_sev(score)
    critical = sum(1 for p in paths if p["severity"] == "CRITICAL")

    summary = (f"Network Exposure Graph scan complete for {provider.upper()} {env}. "
               f"Risk: {score}/100. {len(paths)} exposure path(s) — {critical} critical. "
               f"{len(assets)} asset(s) mapped.")

    s = NetworkExposureScan(user_id=get_jwt_identity(), environment=env, cloud_provider=provider, risk_score=score, severity=sev, total_paths=len(paths), critical_paths=critical, exposed_assets=len(assets), summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()

    for p in paths:
        db.session.add(NetworkExposurePath(scan_id=s.id, path_type=p["path_type"], source=p["source"], destination=p["destination"], severity=p["severity"], protocol=p["protocol"], port=p["port"], description=p["description"], remediation=p["remediation"], node_meta="{}"))

    for a in assets:
        db.session.add(NetworkExposureAsset(scan_id=s.id, asset_type=a["asset_type"], asset_name=a["asset_name"], exposure_level=a["exposure_level"], public_ip=a["public_ip"], open_ports=a["open_ports"], risk_level=a["risk_level"], node_meta="{}"))

    db.session.commit()
    return jsonify({"scan_id":s.id,"risk_score":score,"severity":sev,"total_paths":len(paths),"critical_paths":critical,"exposed_assets":len(assets),"summary":summary}), 200

@network_exposure_bp.route("/api/network-exposure/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = NetworkExposureScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    paths  = NetworkExposurePath.query.filter_by(scan_id=scan_id).all()
    assets = NetworkExposureAsset.query.filter_by(scan_id=scan_id).all()
    types  = list(dict.fromkeys(p.path_type for p in paths))
    return jsonify({
        "scan_id":s.id,"environment":s.environment,"cloud_provider":s.cloud_provider,
        "risk_score":s.risk_score,"severity":s.severity,"total_paths":s.total_paths,
        "critical_paths":s.critical_paths,"exposed_assets":s.exposed_assets,
        "summary":s.summary,"created_at":s.created_at.isoformat(),"path_types":types,
        "paths":[{"path_type":p.path_type,"source":p.source,"destination":p.destination,"severity":p.severity,"protocol":p.protocol,"port":p.port,"description":p.description,"remediation":p.remediation} for p in paths],
        "assets":[{"asset_type":a.asset_type,"asset_name":a.asset_name,"exposure_level":a.exposure_level,"public_ip":a.public_ip,"open_ports":a.open_ports,"risk_level":a.risk_level} for a in assets]
    }), 200

@network_exposure_bp.route("/api/network-exposure/history", methods=["GET"])
@jwt_required()
def history():
    scans = NetworkExposureScan.query.filter_by(user_id=get_jwt_identity()).order_by(NetworkExposureScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"environment":s.environment,"cloud_provider":s.cloud_provider,"risk_score":s.risk_score,"severity":s.severity,"total_paths":s.total_paths,"critical_paths":s.critical_paths,"exposed_assets":s.exposed_assets,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@network_exposure_bp.route("/api/network-exposure/health", methods=["GET"])
def health():
    return jsonify({"module":"Cloud Network Exposure Graph","phase":"Wiz Gap — Phase 1","version":"1.0.0","rules":len(EXPOSURE_RULES),"status":"operational"}), 200
