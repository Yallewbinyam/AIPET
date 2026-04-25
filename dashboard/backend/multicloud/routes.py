"""
AIPET X — Multi-Cloud Security Routes

Endpoints:
  GET    /api/multicloud/accounts          — list all cloud accounts
  POST   /api/multicloud/accounts          — register cloud account
  DELETE /api/multicloud/accounts/<id>     — remove account
  POST   /api/multicloud/accounts/<id>/scan— scan account for assets+findings
  GET    /api/multicloud/assets            — all discovered assets
  GET    /api/multicloud/findings          — all findings with filters
  GET    /api/multicloud/stats             — dashboard metrics
"""
import json
import random
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.multicloud.models import CloudAccount, CloudAsset, CloudFinding
from dashboard.backend.siem.models import SiemEvent

multicloud_bp = Blueprint("multicloud", __name__)


# ── Cloud security check definitions ────────────────────────

# Security findings per provider — realistic misconfigurations
PROVIDER_FINDINGS = {
    "aws": [
        {
            "finding_type": "public_storage",
            "severity":     "Critical",
            "title":        "S3 bucket publicly accessible — data exposure risk",
            "description":  "An S3 bucket has public read access enabled. "
                           "Any internet user can list and download bucket contents "
                           "including IoT device configurations and certificates.",
            "resource":     "s3://iot-device-configs-prod",
            "remediation":  "Remove public ACL from S3 bucket. "
                           "Enable S3 Block Public Access at account level. "
                           "Review bucket policy for overly permissive rules.",
            "mitre_id":     "T1530",
        },
        {
            "finding_type": "open_security_group",
            "severity":     "Critical",
            "title":        "EC2 security group allows all inbound traffic (0.0.0.0/0)",
            "description":  "An EC2 security group has an inbound rule permitting "
                           "all traffic from any IP address on all ports. "
                           "IoT management server is exposed to the entire internet.",
            "resource":     "sg-0abc123def456789 (IoT Management Server)",
            "remediation":  "Remove 0.0.0.0/0 inbound rules. "
                           "Restrict access to specific IP ranges or VPC CIDRs only.",
            "mitre_id":     "T1190",
        },
        {
            "finding_type": "no_logging",
            "severity":     "High",
            "title":        "AWS CloudTrail logging disabled in IoT region",
            "description":  "CloudTrail is not enabled in the eu-west-2 region. "
                           "All API calls, configuration changes, and user actions "
                           "in this region are unaudited and undetectable.",
            "resource":     "CloudTrail — eu-west-2",
            "remediation":  "Enable CloudTrail in all active regions. "
                           "Enable log file validation. "
                           "Send CloudTrail logs to CloudWatch for alerting.",
            "mitre_id":     "T1562.008",
        },
        {
            "finding_type": "overprivileged_role",
            "severity":     "High",
            "title":        "IAM role has AdministratorAccess — violates least privilege",
            "description":  "An IAM role used by IoT Lambda functions has "
                           "AdministratorAccess policy attached. This role can "
                           "perform any action on any AWS resource.",
            "resource":     "iot-processor-lambda-role",
            "remediation":  "Replace AdministratorAccess with specific permissions. "
                           "Apply principle of least privilege. "
                           "Use IAM Access Analyzer to identify unused permissions.",
            "mitre_id":     "T1078.004",
        },
        {
            "finding_type": "unencrypted_storage",
            "severity":     "Medium",
            "title":        "RDS database not encrypted at rest",
            "description":  "An RDS instance storing IoT telemetry data does not "
                           "have encryption at rest enabled. Data is stored in "
                           "plaintext on underlying storage.",
            "resource":     "iot-telemetry-db.eu-west-2.rds.amazonaws.com",
            "remediation":  "Enable RDS encryption using AWS KMS. "
                           "Create encrypted snapshot and restore to new instance.",
            "mitre_id":     "T1530",
        },
    ],
    "azure": [
        {
            "finding_type": "iot_hub_exposed",
            "severity":     "Critical",
            "title":        "Azure IoT Hub management API publicly accessible",
            "description":  "The Azure IoT Hub service endpoint is accessible "
                           "from the internet without IP restrictions. "
                           "Device registration and management APIs are exposed.",
            "resource":     "iot-hub-production.azure-devices.net",
            "remediation":  "Configure IoT Hub IP filter rules. "
                           "Use Private Endpoint for IoT Hub. "
                           "Restrict management API to VNet only.",
            "mitre_id":     "T1190",
        },
        {
            "finding_type": "missing_mfa",
            "severity":     "High",
            "title":        "Azure AD accounts without MFA — privileged users at risk",
            "description":  "3 Azure AD accounts with Owner or Contributor roles "
                           "do not have Multi-Factor Authentication enforced. "
                           "A single compromised password gives full subscription access.",
            "resource":     "Azure AD — 3 privileged accounts without MFA",
            "remediation":  "Enable Conditional Access policy requiring MFA. "
                           "Use Azure AD Identity Protection. "
                           "Enforce MFA via Security Defaults or named policies.",
            "mitre_id":     "T1078",
        },
        {
            "finding_type": "unencrypted_storage",
            "severity":     "High",
            "title":        "Azure Blob Storage container with HTTP access enabled",
            "description":  "A storage container allows HTTP (unencrypted) access. "
                           "IoT device firmware and configuration files can be "
                           "intercepted in transit.",
            "resource":     "storageaccount.blob.core.windows.net/iot-firmware",
            "remediation":  "Enable 'Secure transfer required' on storage account. "
                           "Disable HTTP access and enforce HTTPS only.",
            "mitre_id":     "T1557",
        },
        {
            "finding_type": "no_logging",
            "severity":     "Medium",
            "title":        "Azure Monitor diagnostic logs not configured",
            "description":  "Azure IoT Hub and Key Vault resources have no "
                           "diagnostic logging configured. Security events, "
                           "access attempts, and configuration changes are not captured.",
            "resource":     "IoT Hub + Key Vault — diagnostic settings missing",
            "remediation":  "Enable diagnostic settings on all resources. "
                           "Send logs to Log Analytics workspace. "
                           "Configure alerts for critical events.",
            "mitre_id":     "T1562",
        },
    ],
    "gcp": [
        {
            "finding_type": "public_storage",
            "severity":     "Critical",
            "title":        "GCS bucket allUsers has storage.objects.get permission",
            "description":  "A Google Cloud Storage bucket grants read access "
                           "to allUsers (public internet). IoT device certificates "
                           "and private keys may be exposed.",
            "resource":     "gs://iot-certs-backup",
            "remediation":  "Remove allUsers and allAuthenticatedUsers from IAM. "
                           "Enable uniform bucket-level access. "
                           "Audit bucket contents for sensitive files.",
            "mitre_id":     "T1530",
        },
        {
            "finding_type": "overprivileged_role",
            "severity":     "High",
            "title":        "GCP service account has project Owner role",
            "description":  "A service account used by IoT processing pipelines "
                           "has project Owner IAM role. Compromise of this account "
                           "gives full control of the entire GCP project.",
            "resource":     "iot-processor@project.iam.gserviceaccount.com",
            "remediation":  "Replace Owner role with specific roles (e.g., pubsub.publisher). "
                           "Apply principle of least privilege to all service accounts.",
            "mitre_id":     "T1078.004",
        },
        {
            "finding_type": "open_security_group",
            "severity":     "High",
            "title":        "GCP firewall rule allows SSH from 0.0.0.0/0",
            "description":  "A VPC firewall rule permits SSH access (port 22) "
                           "from all IP addresses. IoT gateway VMs are exposed "
                           "to brute force and exploitation attempts.",
            "resource":     "default-allow-ssh (VPC firewall rule)",
            "remediation":  "Restrict SSH to specific admin IP ranges. "
                           "Use Identity-Aware Proxy (IAP) for SSH access. "
                           "Remove default-allow-ssh rule.",
            "mitre_id":     "T1190",
        },
    ],
    "onprem": [
        {
            "finding_type": "weak_credentials",
            "severity":     "Critical",
            "title":        "On-premise management server using default credentials",
            "description":  "VMware vCenter server is accessible with default "
                           "administrator credentials. All virtual machines hosting "
                           "IoT workloads can be compromised.",
            "resource":     "vcenter.internal — admin/vmware (default)",
            "remediation":  "Change all default credentials immediately. "
                           "Enable vCenter SSO with AD integration. "
                           "Implement privileged access workstation (PAW) policy.",
            "mitre_id":     "T1078",
        },
        {
            "finding_type": "unencrypted_storage",
            "severity":     "High",
            "title":        "On-premise NAS share without encryption",
            "description":  "Network Attached Storage share containing IoT device "
                           "logs and configurations is accessible over SMB without "
                           "encryption. Traffic visible on internal network.",
            "resource":     "\\\\nas01\\iot-logs (SMBv1 without signing)",
            "remediation":  "Disable SMBv1. Enable SMB signing and encryption. "
                           "Migrate to SMBv3 with AES-128-CCM encryption.",
            "mitre_id":     "T1557",
        },
    ],
}

# Asset types per provider
ASSET_TEMPLATES = {
    "aws": [
        {"asset_type": "vm",        "name": "IoT Management Server",    "public": True,  "encrypted": True  },
        {"asset_type": "iot_hub",   "name": "AWS IoT Core",             "public": True,  "encrypted": True  },
        {"asset_type": "storage",   "name": "S3 IoT Config Bucket",     "public": True,  "encrypted": False },
        {"asset_type": "database",  "name": "IoT Telemetry RDS",        "public": False, "encrypted": False },
        {"asset_type": "function",  "name": "IoT Lambda Processor",     "public": False, "encrypted": True  },
        {"asset_type": "container", "name": "ECS IoT Gateway",          "public": False, "encrypted": True  },
    ],
    "azure": [
        {"asset_type": "iot_hub",   "name": "Azure IoT Hub Production", "public": True,  "encrypted": True  },
        {"asset_type": "vm",        "name": "IoT Edge Gateway VM",      "public": True,  "encrypted": True  },
        {"asset_type": "storage",   "name": "Blob IoT Firmware Store",  "public": False, "encrypted": False },
        {"asset_type": "function",  "name": "Azure IoT Function App",   "public": False, "encrypted": True  },
        {"asset_type": "kubernetes","name": "AKS IoT Processing Cluster","public": False, "encrypted": True  },
    ],
    "gcp": [
        {"asset_type": "iot_hub",   "name": "Cloud IoT Core",           "public": True,  "encrypted": True  },
        {"asset_type": "storage",   "name": "GCS IoT Certs Backup",     "public": True,  "encrypted": True  },
        {"asset_type": "vm",        "name": "IoT Gateway GCE Instance", "public": True,  "encrypted": True  },
        {"asset_type": "function",  "name": "Cloud Functions IoT",      "public": False, "encrypted": True  },
    ],
    "onprem": [
        {"asset_type": "vm",        "name": "VMware IoT Management",    "public": False, "encrypted": True  },
        {"asset_type": "storage",   "name": "NAS IoT Logs",             "public": False, "encrypted": False },
        {"asset_type": "network",   "name": "IoT VLAN Gateway",         "public": False, "encrypted": True  },
    ],
}


def _simulate_cloud_scan(account):
    """
    Simulate cloud security posture assessment for an account.
    Returns (assets, findings) lists.

    In production this calls real cloud APIs:
      AWS:   boto3 Security Hub + Config
      Azure: Azure Security Center + Defender for IoT
      GCP:   Security Command Center + Asset Inventory
    """
    provider     = account.provider
    asset_tmpls  = ASSET_TEMPLATES.get(provider, [])
    finding_defs = PROVIDER_FINDINGS.get(provider, [])

    assets   = []
    findings = []
    now      = datetime.now(timezone.utc)

    # Create asset records
    for i, tmpl in enumerate(asset_tmpls):
        asset = CloudAsset(
            account_id = account.id,
            asset_id   = f"{provider}-{tmpl['asset_type']}-{i+1:03d}",
            name       = tmpl["name"],
            asset_type = tmpl["asset_type"],
            provider   = provider,
            region     = account.region or "eu-west-2",
            public     = tmpl["public"],
            encrypted  = tmpl["encrypted"],
            risk_score = 0,
        )
        assets.append(asset)

    # Generate findings — Critical always included
    for fdef in finding_defs:
        if fdef["severity"] == "Critical" or random.random() > 0.25:
            findings.append(fdef)

    return assets, findings


# ── Account endpoints ────────────────────────────────────────

@multicloud_bp.route("/api/multicloud/accounts", methods=["GET"])
@jwt_required()
def list_accounts():
    """List all registered cloud accounts."""
    accounts = CloudAccount.query.order_by(
        CloudAccount.created_at.asc()).all()
    return jsonify({"accounts": [a.to_dict() for a in accounts]})


@multicloud_bp.route("/api/multicloud/accounts", methods=["POST"])
@jwt_required()
def register_account():
    """Register a new cloud account."""
    data = request.get_json(silent=True) or {}
    if not data.get("name") or not data.get("provider"):
        return jsonify({"error": "name and provider required"}), 400

    valid = ["aws", "azure", "gcp", "onprem"]
    if data["provider"] not in valid:
        return jsonify({"error": f"provider must be one of: {valid}"}), 400

    account = CloudAccount(
        name       = data["name"],
        provider   = data["provider"],
        account_id = data.get("account_id"),
        region     = data.get("region", "eu-west-2"),
        status     = "connected",
        created_by = int(get_jwt_identity()),
    )
    db.session.add(account)
    db.session.commit()
    return jsonify({"success": True, "account": account.to_dict()}), 201


@multicloud_bp.route("/api/multicloud/accounts/<int:account_id>", methods=["DELETE"])
@jwt_required()
def delete_account(account_id):
    """Remove a cloud account."""
    account = CloudAccount.query.get_or_404(account_id)
    db.session.delete(account)
    db.session.commit()
    return jsonify({"success": True})


@multicloud_bp.route("/api/multicloud/accounts/<int:account_id>/scan", methods=["POST"])
@jwt_required()
def scan_account(account_id):
    """
    Scan a cloud account for assets and security findings.
    Simulates cloud security posture assessment.

    In production integrates with:
      AWS:   Security Hub, Config, GuardDuty
      Azure: Defender for Cloud, Sentinel
      GCP:   Security Command Center
    """
    account = CloudAccount.query.get_or_404(account_id)

    # Remove old assets and findings for this account
    CloudFinding.query.filter_by(account_id=account_id).delete()
    CloudAsset.query.filter_by(account_id=account_id).delete()
    db.session.flush()

    # Run simulated scan
    assets, finding_defs = _simulate_cloud_scan(account)

    # Save assets
    for asset in assets:
        db.session.add(asset)
    db.session.flush()

    # Save findings
    saved_findings = []
    for fdef in finding_defs:
        finding = CloudFinding(
            account_id   = account_id,
            provider     = account.provider,
            finding_type = fdef["finding_type"],
            severity     = fdef["severity"],
            title        = fdef["title"],
            description  = fdef.get("description"),
            resource     = fdef.get("resource"),
            remediation  = fdef.get("remediation"),
            mitre_id     = fdef.get("mitre_id"),
        )
        db.session.add(finding)
        saved_findings.append(finding)

    # Calculate risk scores for assets
    critical_count = len([f for f in saved_findings if f.severity == "Critical"])
    high_count     = len([f for f in saved_findings if f.severity == "High"])
    for asset in assets:
        score = 0
        if asset.public:      score += 30
        if not asset.encrypted: score += 20
        score += critical_count * 15
        score += high_count    * 8
        asset.risk_score = min(score, 100)

    # Update account stats
    account.asset_count   = len(assets)
    account.finding_count = len(saved_findings)
    account.last_scan     = datetime.now(timezone.utc)
    account.status        = "connected"

    # Push critical findings to SIEM
    cloud_siem_events = []
    for f in saved_findings:
        if f.severity == "Critical":
            event = SiemEvent(
                event_type  = "cloud_finding",
                source      = f"AIPET Multi-Cloud ({account.provider.upper()})",
                severity    = "Critical",
                title       = f.title,
                description = f.description,
                mitre_id    = f.mitre_id,
            )
            db.session.add(event)
            cloud_siem_events.append(event)

    db.session.commit()

    for sev_event in cloud_siem_events:
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module    = "multicloud",
                source_table     = "siem_events",
                source_row_id    = sev_event.id,
                event_type       = sev_event.event_type,
                severity         = sev_event.severity.lower(),
                user_id          = sev_event.user_id,
                entity           = account.name or str(account_id),
                entity_type      = "service",
                title            = sev_event.title,
                mitre_techniques = [{"technique_id": sev_event.mitre_id, "confidence": 1.0}] if sev_event.mitre_id else None,
                payload          = {"original_siem_event_id": sev_event.id, "provider": account.provider},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in multicloud")

    return jsonify({
        "account":  account.to_dict(),
        "assets":   len(assets),
        "findings": len(saved_findings),
        "critical": critical_count,
    })


# ── Asset + finding endpoints ────────────────────────────────

@multicloud_bp.route("/api/multicloud/assets", methods=["GET"])
@jwt_required()
def list_assets():
    """All cloud assets with optional provider/type filter."""
    provider   = request.args.get("provider")
    asset_type = request.args.get("type")
    q          = CloudAsset.query.order_by(CloudAsset.risk_score.desc())
    if provider:
        q = q.filter_by(provider=provider)
    if asset_type:
        q = q.filter_by(asset_type=asset_type)
    assets = q.all()
    return jsonify({"assets": [a.to_dict() for a in assets]})


@multicloud_bp.route("/api/multicloud/findings", methods=["GET"])
@jwt_required()
def list_findings():
    """All cloud findings with optional severity/provider filter."""
    severity = request.args.get("severity")
    provider = request.args.get("provider")
    q        = CloudFinding.query.order_by(CloudFinding.created_at.desc())
    if severity:
        q = q.filter_by(severity=severity)
    if provider:
        q = q.filter_by(provider=provider)
    findings = q.limit(100).all()
    return jsonify({"findings": [f.to_dict() for f in findings]})


# ── Stats ────────────────────────────────────────────────────

@multicloud_bp.route("/api/multicloud/stats", methods=["GET"])
@jwt_required()
def cloud_stats():
    """Dashboard metrics for the Multi-Cloud page."""
    total_accounts  = CloudAccount.query.count()
    total_assets    = CloudAsset.query.count()
    public_assets   = CloudAsset.query.filter_by(public=True).count()
    unenc_assets    = CloudAsset.query.filter_by(encrypted=False).count()
    total_findings  = CloudFinding.query.count()
    critical_findings=CloudFinding.query.filter_by(severity="Critical").count()

    # Per-provider breakdown
    providers = {}
    for p in ["aws","azure","gcp","onprem"]:
        acc = CloudAccount.query.filter_by(provider=p).first()
        providers[p] = {
            "accounts": CloudAccount.query.filter_by(provider=p).count(),
            "assets":   CloudAsset.query.filter_by(provider=p).count(),
            "findings": CloudFinding.query.filter_by(provider=p).count(),
            "critical": CloudFinding.query.filter_by(
                provider=p, severity="Critical").count(),
        }

    return jsonify({
        "total_accounts":   total_accounts,
        "total_assets":     total_assets,
        "public_assets":    public_assets,
        "unencrypted_assets": unenc_assets,
        "total_findings":   total_findings,
        "critical_findings":critical_findings,
        "providers":        providers,
    })
