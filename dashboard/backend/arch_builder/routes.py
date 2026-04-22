# ============================================================
# AIPET X — Module #44: Autonomous Architecture Builder
# Zero Trust Design | Secure Cloud Architecture | IaC Generation
# Phase 5C | v6.2.0
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

arch_builder_bp = Blueprint("arch_builder", __name__)

class ArchBuilderDesign(db.Model):
    __tablename__ = "arch_builder_designs"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    title         = Column(String(256))
    cloud_provider= Column(String(32))
    arch_type     = Column(String(64))
    security_score= Column(Float, default=0.0)
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    components    = relationship("ArchBuilderComponent", backref="design", lazy=True, cascade="all, delete-orphan")

class ArchBuilderComponent(db.Model):
    __tablename__ = "arch_builder_components"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    design_id     = Column(String(64), ForeignKey("arch_builder_designs.id"), nullable=False)
    layer         = Column(String(64))
    component     = Column(String(256))
    service       = Column(String(256))
    purpose       = Column(Text)
    security_note = Column(Text, nullable=True)
    iac_snippet   = Column(Text, nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

ARCH_TEMPLATES = {
    "web_app": {
        "title": "Secure Web Application Architecture",
        "score": 92,
        "components": [
            {"layer":"Edge","component":"CDN + WAF","service":"CloudFront + AWS WAF","purpose":"Global content delivery with DDoS protection and OWASP Top 10 filtering.","security_note":"Enable WAF rules for SQLi, XSS, RCE. Set rate limiting at edge.","iac_snippet":"aws_wafv2_web_acl main { scope=CLOUDFRONT, default_action=allow }"},
            {"layer":"DNS","component":"DNS with DNSSEC","service":"Route 53","purpose":"Resilient DNS routing with DNSSEC to prevent spoofing and cache poisoning.","security_note":"Enable DNSSEC. Use health checks and failover routing for availability.","iac_snippet":"aws_route53_zone main { name=yourdomain.com, dnssec_config=SIGNING }"},
            {"layer":"Identity","component":"Identity Provider + MFA","service":"AWS Cognito / Azure AD","purpose":"Centralised identity management with MFA and OAuth2/OIDC for all users.","security_note":"Enforce MFA for all users. Use short-lived JWTs. Implement token rotation.","iac_snippet":"aws_cognito_user_pool main { mfa_configuration=ON, password_policy={min_length=16} }"},
            {"layer":"Network","component":"Zero Trust VPC","service":"VPC + Private Subnets + NACLs","purpose":"Micro-segmented VPC with public/private/data subnet tiers. No direct internet to app layer.","security_note":"Block all inbound by default. Use security groups as firewalls. Enable VPC Flow Logs.","iac_snippet":"aws_vpc main { cidr=10.0.0.0/16, enable_dns_hostnames=true, flow_logs=ALL }"},
            {"layer":"Compute","component":"Auto-scaling App Tier","service":"ECS Fargate / Cloud Run","purpose":"Containerised application with auto-scaling and immutable infrastructure.","security_note":"Run as non-root. Use read-only filesystems. Scan images in CI/CD pipeline.","iac_snippet":"aws_ecs_task_definition app { requires_compatibilities=FARGATE, network_mode=awsvpc }"},
            {"layer":"API","component":"API Gateway + Rate Limiting","service":"AWS API Gateway / Kong","purpose":"Centralised API management with auth, rate limiting and audit logging.","security_note":"Enforce JWT auth. Enable request throttling. Log all API calls.","iac_snippet":"aws_api_gateway_rest_api main { name=secure-api, throttling_burst_limit=5000 }"},
            {"layer":"Data","component":"Encrypted Database","service":"RDS Aurora / Azure SQL","purpose":"Multi-AZ encrypted database with automated backups and private subnet placement.","security_note":"Enable encryption at rest and in transit. Restrict to app tier only. Enable audit logging.","iac_snippet":"aws_db_instance main { storage_encrypted=true, multi_az=true, publicly_accessible=false }"},
            {"layer":"Secrets","component":"Secrets Manager","service":"AWS Secrets Manager / Vault","purpose":"Centralised secrets with automatic rotation for credentials and API keys.","security_note":"Never hardcode secrets. Rotate all credentials every 90 days. Audit all access.","iac_snippet":"aws_secretsmanager_secret db { name=db-credentials, rotation_days=90 }"},
            {"layer":"Observability","component":"SIEM + Monitoring","service":"CloudWatch + GuardDuty","purpose":"Centralised logging, threat detection and security posture management.","security_note":"Enable GuardDuty in all regions. Set alarms for security events. Retain logs 1 year.","iac_snippet":"aws_guardduty_detector main { enable=true, publishing_frequency=SIX_HOURS }"},
            {"layer":"Backup","component":"Immutable Backup","service":"AWS Backup","purpose":"Automated daily backups with immutable retention and cross-region replication.","security_note":"Enable backup vault lock. Test restores monthly. Store in separate AWS account.","iac_snippet":"aws_backup_plan main { rule={ schedule=cron(0 2 * * ? *), lifecycle={delete_after=90} } }"},
        ]
    },
    "microservices": {
        "title": "Secure Microservices Architecture",
        "score": 90,
        "components": [
            {"layer":"Service Mesh","component":"Zero Trust Service Mesh","service":"Istio / Linkerd","purpose":"mTLS between all services. Automatic certificate rotation. Policy-based traffic control.","security_note":"Enable mTLS for all service-to-service communication. Implement circuit breakers.","iac_snippet":"istio PeerAuthentication { mtls.mode=STRICT, namespace=default }"},
            {"layer":"Container","component":"Kubernetes + Pod Security","service":"EKS / AKS / GKE","purpose":"Managed Kubernetes with pod security policies, RBAC and network policies.","security_note":"Enable Pod Security Standards restricted profile. Use OPA/Gatekeeper. Scan with Trivy.","iac_snippet":"Namespace labels { pod-security.kubernetes.io/enforce=restricted }"},
            {"layer":"Identity","component":"Workload Identity","service":"SPIRE / AWS IRSA","purpose":"Cryptographic workload identity using SPIFFE/SPIRE. No static credentials for services.","security_note":"Bind IAM roles to Kubernetes service accounts. Never mount static credentials in pods.","iac_snippet":"aws_iam_role sa_role { assume_role_policy=oidc_provider, session_duration=3600 }"},
            {"layer":"API","component":"API Gateway + Auth Sidecar","service":"Kong / Envoy","purpose":"Centralised API gateway with JWT validation. All traffic authenticated and authorised.","security_note":"Verify every request. Log all API calls. Enforce rate limiting per service.","iac_snippet":"istio VirtualService secure-routing { retries={attempts=3}, timeout=30s }"},
            {"layer":"Secrets","component":"Dynamic Secrets","service":"HashiCorp Vault","purpose":"Dynamic short-lived credentials for all services. No long-lived static secrets.","security_note":"Use Vault agent injector for Kubernetes. Rotate secrets automatically. Audit all access.","iac_snippet":"vault database/roles/app { default_ttl=1h, max_ttl=24h, db_name=mydb }"},
            {"layer":"Observability","component":"Distributed Tracing + SIEM","service":"Jaeger / Datadog","purpose":"End-to-end distributed tracing with security event correlation.","security_note":"Correlate traces with security events. Alert on anomalous patterns. Retain logs 90+ days.","iac_snippet":"helm jaeger { repository=jaegertracing, namespace=monitoring, replicas=3 }"},
        ]
    },
    "iot": {
        "title": "Secure IoT Architecture",
        "score": 88,
        "components": [
            {"layer":"Device","component":"Secure Device Identity","service":"AWS IoT Core / Azure IoT Hub","purpose":"X.509 certificate-based device authentication. Unique identity per device.","security_note":"Provision unique certificates per device. Implement certificate revocation. Use TPM.","iac_snippet":"aws_iot_certificate device { active=true, certificate_pem=file(cert.pem) }"},
            {"layer":"Communication","component":"Encrypted MQTT","service":"AWS IoT Core","purpose":"TLS 1.2+ encrypted MQTT with topic-level access control policies per device.","security_note":"Enforce TLS on all IoT communication. Implement per-device topic policies.","iac_snippet":"aws_iot_policy device_policy { name=device-policy, actions=[iot:Publish, iot:Subscribe] }"},
            {"layer":"Gateway","component":"IoT Edge Gateway","service":"AWS IoT Greengrass","purpose":"Local processing gateway with offline capability and data validation before cloud.","security_note":"Harden gateway OS. Implement allowlist for device connections. Enable local audit logging.","iac_snippet":"aws_greengrassv2_deployment gateway { target_arn=arn:aws:iot:region:account:thinggroup/factory }"},
            {"layer":"Ingestion","component":"Secure Data Pipeline","service":"IoT Core + Kinesis","purpose":"Validated schema-enforced data ingestion with anomaly detection.","security_note":"Validate all device messages. Alert on anomalous patterns. Implement device quarantine.","iac_snippet":"aws_kinesis_stream iot_data { shard_count=1, encryption_type=KMS }"},
            {"layer":"Storage","component":"Encrypted Time-Series DB","service":"AWS Timestream","purpose":"Encrypted time-series database for IoT telemetry with retention policies.","security_note":"Encrypt all IoT data at rest. Implement retention policies. Restrict access to authorised services.","iac_snippet":"aws_timestreamwrite_database iot { database_name=iot-telemetry, kms_key_id=aws_kms_key.iot }"},
            {"layer":"Security","component":"Device Anomaly Detection","service":"AWS IoT Device Defender","purpose":"Continuous monitoring of device behaviour with ML-based anomaly detection.","security_note":"Set baseline device behaviour profiles. Alert on deviations. Automate quarantine.","iac_snippet":"aws_iot_account_audit_configuration main { audit_checks=[authenticated_cognito_role_check] }"},
        ]
    },
    "zero_trust": {
        "title": "Zero Trust Network Architecture",
        "score": 95,
        "components": [
            {"layer":"Identity","component":"Identity-First Access","service":"Okta / Azure AD","purpose":"All access decisions based on verified identity. Continuous auth with risk-based MFA.","security_note":"Never trust network location. Verify identity for every request. Adaptive MFA.","iac_snippet":"okta_policy_mfa default { name=Zero Trust MFA, status=ACTIVE, mfa_required=true }"},
            {"layer":"Device","component":"Device Trust + Compliance","service":"Intune / CrowdStrike","purpose":"Device health verification before any access. Non-compliant devices blocked.","security_note":"Check device health at every access. Require encryption, EDR and patch compliance.","iac_snippet":"azurerm_conditional_access_policy device { require_compliant_device=true, state=enabled }"},
            {"layer":"Network","component":"Software-Defined Perimeter","service":"Zscaler / Cloudflare Access","purpose":"Application-level micro-perimeters replace network perimeters. No implicit network trust.","security_note":"Implement app-level access policies. Log all access attempts. Monitor sessions continuously.","iac_snippet":"cloudflare_access_application app { name=Internal App, domain=app.company.com, type=self_hosted }"},
            {"layer":"Application","component":"App-Level Authorization","service":"OPA / AWS Verified Access","purpose":"Policy-based app authorization with ABAC enforced at application layer.","security_note":"Enforce least-privilege at app level. Log all authorization decisions. Review policies quarterly.","iac_snippet":"opa policy authz { default allow=false, allow if user.roles[_]==admin AND resource.sensitivity!=top_secret }"},
            {"layer":"Data","component":"Data-Centric Security","service":"AWS Macie / Purview","purpose":"Data classification and protection controls that follow the data regardless of location.","security_note":"Classify all data. Apply protection based on classification. Monitor data access and movement.","iac_snippet":"aws_macie2_account main { finding_publishing_frequency=SIX_HOURS, status=ENABLED }"},
            {"layer":"Monitoring","component":"Continuous Verification","service":"UEBA + SIEM + SOAR","purpose":"Continuous monitoring with ML-based anomaly detection and automated response.","security_note":"Monitor all access continuously. Alert on policy violations. Automate response for threats.","iac_snippet":"aws_securityhub_account main { auto_enable_controls=true, enable_default_standards=true }"},
        ]
    }
}

KEYWORD_MAP = [
    {"type":"microservices","keywords":["microservice","kubernetes","k8s","container","docker","service mesh","api gateway"]},
    {"type":"iot","keywords":["iot","mqtt","coap","sensor","device","industrial","ot","scada","embedded"]},
    {"type":"zero_trust","keywords":["zero trust","ztna","beyondcorp","sdp","never trust","identity first","sase"]},
    {"type":"web_app","keywords":["web","application","saas","api","frontend","backend","database","webapp"]},
]

def classify_arch(description):
    desc_lower = description.lower()
    for item in KEYWORD_MAP:
        if any(kw in desc_lower for kw in item["keywords"]):
            return item["type"]
    return "web_app"

@arch_builder_bp.route("/api/arch-builder/design", methods=["POST"])
@jwt_required()
def design():
    data     = request.get_json(silent=True) or {}
    title    = data.get("title","My Architecture")
    provider = data.get("cloud_provider","aws")
    desc     = data.get("description","")
    arch_type= data.get("arch_type","") or classify_arch(desc)
    if not desc.strip(): return jsonify({"error":"No description provided"}),400
    template = ARCH_TEMPLATES.get(arch_type, ARCH_TEMPLATES["web_app"])
    d = ArchBuilderDesign(user_id=get_jwt_identity(),title=title or template["title"],cloud_provider=provider,arch_type=arch_type,security_score=template["score"],summary=f"Secure {template['title']} generated for {provider.upper()}. {len(template['components'])} architecture components with Zero Trust principles. Security score: {template['score']}/100.",node_meta="{}")
    db.session.add(d); db.session.flush()
    for c in template["components"]:
        db.session.add(ArchBuilderComponent(design_id=d.id,layer=c["layer"],component=c["component"],service=c["service"],purpose=c["purpose"],security_note=c["security_note"],iac_snippet=c["iac_snippet"],node_meta="{}"))
    db.session.commit()
    return jsonify({"design_id":d.id,"title":d.title,"arch_type":arch_type,"cloud_provider":provider,"security_score":template["score"],"component_count":len(template["components"]),"summary":d.summary}),200

@arch_builder_bp.route("/api/arch-builder/designs/<design_id>", methods=["GET"])
@jwt_required()
def get_design(design_id):
    d = ArchBuilderDesign.query.filter_by(id=design_id,user_id=get_jwt_identity()).first()
    if not d: return jsonify({"error":"Not found"}),404
    components = ArchBuilderComponent.query.filter_by(design_id=design_id).all()
    layers = list(dict.fromkeys(c.layer for c in components))
    return jsonify({"design_id":d.id,"title":d.title,"arch_type":d.arch_type,"cloud_provider":d.cloud_provider,"security_score":d.security_score,"summary":d.summary,"created_at":d.created_at.isoformat(),"layers":layers,"components":[{"layer":c.layer,"component":c.component,"service":c.service,"purpose":c.purpose,"security_note":c.security_note,"iac_snippet":c.iac_snippet} for c in components]}),200

@arch_builder_bp.route("/api/arch-builder/history", methods=["GET"])
@jwt_required()
def history():
    designs = ArchBuilderDesign.query.filter_by(user_id=get_jwt_identity()).order_by(ArchBuilderDesign.created_at.desc()).limit(50).all()
    return jsonify({"designs":[{"design_id":d.id,"title":d.title,"arch_type":d.arch_type,"cloud_provider":d.cloud_provider,"security_score":d.security_score,"created_at":d.created_at.isoformat()} for d in designs]}),200

@arch_builder_bp.route("/api/arch-builder/health", methods=["GET"])
def health():
    return jsonify({"module":"Autonomous Architecture Builder","version":"1.0.0","arch_types":list(ARCH_TEMPLATES.keys()),"status":"operational"}),200
