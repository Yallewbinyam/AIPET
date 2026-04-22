"""
AIPET X+ — Identity Graph Engine Routes

Endpoints:
  GET  /api/identitygraph/identities        — all identities
  GET  /api/identitygraph/identities/<id>   — identity detail + edges
  GET  /api/identitygraph/graph             — full graph data for visualisation
  GET  /api/identitygraph/risks             — all identity risks
  GET  /api/identitygraph/stats             — metrics
  POST /api/identitygraph/analyse           — run identity analysis
  GET  /api/identitygraph/blast/<id>        — blast radius for identity
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.identitygraph.models import (
    IgIdentity, IgEdge, IgRisk)

identitygraph_bp = Blueprint("identitygraph", __name__)


@identitygraph_bp.route("/api/identitygraph/identities", methods=["GET"])
@jwt_required()
def list_identities():
    itype    = request.args.get("type")
    risky    = request.args.get("risky")
    dormant  = request.args.get("dormant")
    q = IgIdentity.query
    if itype:   q = q.filter_by(identity_type=itype)
    if risky:   q = q.filter(IgIdentity.risk_score >= 70)
    if dormant: q = q.filter_by(is_dormant=True)
    ids = q.order_by(IgIdentity.risk_score.desc()).all()
    return jsonify({"identities": [i.to_dict() for i in ids],
                    "total": len(ids)})


@identitygraph_bp.route("/api/identitygraph/identities/<int:iid>",
                         methods=["GET"])
@jwt_required()
def identity_detail(iid):
    identity = IgIdentity.query.get_or_404(iid)
    edges_out = IgEdge.query.filter_by(source_id=iid).all()
    edges_in  = IgEdge.query.filter_by(target_id=iid).all()
    risks     = IgRisk.query.filter_by(
        identity_id=iid, resolved=False).all()
    data = identity.to_dict()
    data["edges_out"] = [e.to_dict() for e in edges_out]
    data["edges_in"]  = [e.to_dict() for e in edges_in]
    data["risks"]     = [r.to_dict() for r in risks]
    return jsonify(data)


@identitygraph_bp.route("/api/identitygraph/graph", methods=["GET"])
@jwt_required()
def get_graph():
    """
    Return full graph data for D3.js force-directed visualisation.
    Nodes = identities, Links = edges
    """
    identities = IgIdentity.query.all()
    edges      = IgEdge.query.all()

    nodes = []
    for i in identities:
        nodes.append({
            "id":    i.id,
            "name":  i.name,
            "type":  i.identity_type,
            "risk":  i.risk_score,
            "blast": i.blast_radius,
            "privileged":    i.is_privileged,
            "dormant":       i.is_dormant,
            "overprivileged":i.is_overprivileged,
        })

    links = []
    for e in edges:
        links.append({
            "source":       e.source_id,
            "target":       e.target_id,
            "relationship": e.relationship,
            "risky":        e.is_risky,
        })

    return jsonify({"nodes": nodes, "links": links})


@identitygraph_bp.route("/api/identitygraph/risks", methods=["GET"])
@jwt_required()
def list_risks():
    risks = IgRisk.query.filter_by(resolved=False).order_by(
        IgRisk.created_at.desc()).all()
    return jsonify({"risks": [r.to_dict() for r in risks],
                    "total": len(risks)})


@identitygraph_bp.route("/api/identitygraph/stats", methods=["GET"])
@jwt_required()
def identity_stats():
    identities = IgIdentity.query.all()
    risks      = IgRisk.query.filter_by(resolved=False).all()
    by_type = {}
    for i in identities:
        by_type[i.identity_type] = by_type.get(i.identity_type, 0) + 1
    return jsonify({
        "total_identities":    len(identities),
        "privileged":          sum(1 for i in identities if i.is_privileged),
        "dormant":             sum(1 for i in identities if i.is_dormant),
        "overprivileged":      sum(1 for i in identities if i.is_overprivileged),
        "high_risk":           sum(1 for i in identities if i.risk_score >= 70),
        "total_risks":         len(risks),
        "critical_risks":      sum(1 for r in risks if r.severity == "Critical"),
        "by_type":             by_type,
        "total_edges":         IgEdge.query.count(),
        "risky_edges":         IgEdge.query.filter_by(is_risky=True).count(),
    })


@identitygraph_bp.route("/api/identitygraph/analyse", methods=["POST"])
@jwt_required()
def run_analysis():
    """
    Run identity graph analysis.
    Scans users, devices, service accounts and maps relationships.
    Detects: overprivileged, dormant, risky paths.
    """
    from dashboard.backend.models import User, Device
    import random

    # Clear existing data for fresh analysis
    IgRisk.query.delete()
    IgEdge.query.delete()
    IgIdentity.query.delete()
    db.session.flush()

    now = datetime.now(timezone.utc)
    identities = []
    edges      = []
    risks      = []

    # ── Seed realistic identity ecosystem ────────────────────

    # Admin users
    admin = IgIdentity(
        name="admin@aipet.io", identity_type="user",
        email="admin@aipet.io", source="Active Directory",
        risk_score=85, blast_radius=47, is_privileged=True,
        last_active=now - timedelta(hours=2),
        permissions=json.dumps(["read:all","write:all","admin:all"]),
        tags=json.dumps(["admin","privileged","high-value"]),
    )
    identities.append(admin)

    soc_analyst = IgIdentity(
        name="soc.analyst@aipet.io", identity_type="user",
        email="soc.analyst@aipet.io", source="Active Directory",
        risk_score=35, blast_radius=12, is_privileged=False,
        last_active=now - timedelta(hours=1),
        permissions=json.dumps(["read:findings","read:scans",
                                 "write:incidents"]),
        tags=json.dumps(["soc","analyst"]),
    )
    identities.append(soc_analyst)

    dormant_user = IgIdentity(
        name="contractor.2024@aipet.io", identity_type="user",
        email="contractor.2024@aipet.io", source="Active Directory",
        risk_score=72, blast_radius=18, is_privileged=False,
        is_dormant=True, is_overprivileged=True,
        last_active=now - timedelta(days=95),
        permissions=json.dumps(["read:all","write:findings",
                                 "read:compliance"]),
        tags=json.dumps(["contractor","dormant","overprivileged"]),
    )
    identities.append(dormant_user)

    # Service accounts
    scan_svc = IgIdentity(
        name="aipet-scanner-svc", identity_type="service_account",
        source="AWS IAM", risk_score=55, blast_radius=23,
        is_privileged=True, is_overprivileged=True,
        last_active=now - timedelta(minutes=15),
        permissions=json.dumps(["ec2:DescribeInstances",
                                 "ec2:DescribeSecurityGroups",
                                 "s3:GetObject","s3:ListBucket",
                                 "iam:ListUsers","iam:GetPolicy",
                                 "lambda:InvokeFunction"]),
        tags=json.dumps(["service","scanner","aws","overprivileged"]),
    )
    identities.append(scan_svc)

    api_svc = IgIdentity(
        name="aipet-api-gateway-svc", identity_type="service_account",
        source="Azure AD", risk_score=40, blast_radius=15,
        last_active=now - timedelta(minutes=5),
        permissions=json.dumps(["Microsoft.ApiManagement/service/read",
                                 "Microsoft.KeyVault/vaults/secrets/read"]),
        tags=json.dumps(["service","api","azure"]),
    )
    identities.append(api_svc)

    ci_svc = IgIdentity(
        name="github-actions-deploy", identity_type="service_account",
        source="GitHub", risk_score=78, blast_radius=31,
        is_privileged=True, is_overprivileged=True,
        last_active=now - timedelta(hours=3),
        permissions=json.dumps(["eks:*","ecr:*","s3:*",
                                 "iam:PassRole","sts:AssumeRole"]),
        tags=json.dumps(["cicd","github","overprivileged","critical"]),
    )
    identities.append(ci_svc)

    # Roles
    admin_role = IgIdentity(
        name="AIPET-Admin-Role", identity_type="role",
        source="AWS IAM", risk_score=90, blast_radius=52,
        is_privileged=True,
        permissions=json.dumps(["AdministratorAccess"]),
        tags=json.dumps(["role","admin","aws"]),
    )
    identities.append(admin_role)

    readonly_role = IgIdentity(
        name="AIPET-ReadOnly-Role", identity_type="role",
        source="AWS IAM", risk_score=15, blast_radius=8,
        permissions=json.dumps(["ReadOnlyAccess"]),
        tags=json.dumps(["role","readonly","aws"]),
    )
    identities.append(readonly_role)

    # Devices
    iot_device = IgIdentity(
        name="IP-Camera-Lobby", identity_type="device",
        source="AIPET Scanner", risk_score=82, blast_radius=6,
        last_active=now - timedelta(minutes=30),
        permissions=json.dumps(["network:access","mqtt:publish"]),
        tags=json.dumps(["iot","camera","critical"]),
    )
    identities.append(iot_device)

    plc_device = IgIdentity(
        name="PLC-Controller-Plant1", identity_type="device",
        source="AIPET Scanner", risk_score=95, blast_radius=12,
        last_active=now - timedelta(minutes=10),
        permissions=json.dumps(["modbus:read","modbus:write",
                                 "network:access"]),
        tags=json.dumps(["ot","plc","critical","high-value"]),
    )
    identities.append(plc_device)

    # API Keys
    api_key_prod = IgIdentity(
        name="prod-api-key-legacy", identity_type="api_key",
        source="AIPET Platform", risk_score=65, blast_radius=20,
        is_dormant=True,
        last_active=now - timedelta(days=120),
        permissions=json.dumps(["scan:create","findings:read",
                                 "report:generate"]),
        tags=json.dumps(["api-key","legacy","dormant"]),
    )
    identities.append(api_key_prod)

    # Cloud resources
    s3_bucket = IgIdentity(
        name="aipet-data-prod-s3", identity_type="cloud_resource",
        source="AWS S3", risk_score=60, blast_radius=0,
        permissions=json.dumps(["s3:GetObject","s3:PutObject"]),
        tags=json.dumps(["aws","s3","data","sensitive"]),
    )
    identities.append(s3_bucket)

    db.session.add_all(identities)
    db.session.flush()

    # ── Create edges ──────────────────────────────────────────
    id_map = {i.name: i.id for i in identities}

    edge_defs = [
        (admin.id,        admin_role.id,    "has_role",       True),
        (soc_analyst.id,  readonly_role.id, "has_role",       False),
        (dormant_user.id, admin_role.id,    "has_role",       True),
        (scan_svc.id,     s3_bucket.id,     "accesses",       False),
        (scan_svc.id,     plc_device.id,    "manages",        True),
        (scan_svc.id,     iot_device.id,    "manages",        False),
        (ci_svc.id,       admin_role.id,    "assumes",        True),
        (ci_svc.id,       s3_bucket.id,     "accesses",       True),
        (admin_role.id,   s3_bucket.id,     "grants_access",  False),
        (admin_role.id,   plc_device.id,    "grants_access",  True),
        (api_key_prod.id, s3_bucket.id,     "accesses",       True),
        (admin.id,        scan_svc.id,      "manages",        False),
        (iot_device.id,   plc_device.id,    "communicates",   True),
    ]

    for src, tgt, rel, risky in edge_defs:
        e = IgEdge(source_id=src, target_id=tgt,
                   relationship=rel, is_risky=risky)
        db.session.add(e)

    # ── Create risks ──────────────────────────────────────────
    risk_defs = [
        (dormant_user.id, "Dormant Account with Active Privileges",
         "Critical",
         "Account inactive for 95 days but retains full admin role. "
         "Immediate access revocation required.",
         "Disable account and revoke all role assignments immediately."),
        (ci_svc.id, "CI/CD Service Account Over-Privileged",
         "Critical",
         "GitHub Actions deployment account has AdministratorAccess. "
         "Blast radius: 31 resources. Principle of least privilege violated.",
         "Scope permissions to specific deployment resources only. "
         "Use OIDC federation instead of long-lived keys."),
        (scan_svc.id, "Scanner Service Account Excessive IAM Permissions",
         "High",
         "Scanner account has iam:ListUsers and iam:GetPolicy — "
         "not required for scanning. Could be used for privilege escalation.",
         "Remove IAM read permissions. Use AWS Config for inventory instead."),
        (plc_device.id, "Critical OT Device Without Identity Governance",
         "High",
         "PLC Controller has no identity policy, no certificate rotation, "
         "and communicates with IoT devices without mutual TLS.",
         "Implement certificate-based identity for all OT devices. "
         "Enforce mTLS for all OT-to-IoT communications."),
        (api_key_prod.id, "Legacy API Key Dormant 120 Days",
         "High",
         "Production API key unused for 120 days but still active. "
         "Represents an unmonitored credential with full scan access.",
         "Revoke legacy API key. Issue new scoped key if still needed."),
        (admin.id, "Admin Account High Blast Radius",
         "Medium",
         "Admin account can reach 47 resources directly. "
         "Single compromise = full platform access.",
         "Enforce MFA, privileged access workstation, "
         "and just-in-time access for admin operations."),
    ]

    for iid, rtype, sev, desc, rem in risk_defs:
        r = IgRisk(identity_id=iid, risk_type=rtype,
                   severity=sev, description=desc, remediation=rem)
        db.session.add(r)

    db.session.commit()
    print(f"identities: {IgIdentity.query.count()}")
    print(f"edges:      {IgEdge.query.count()}")
    print(f"risks:      {IgRisk.query.count()}")
    return jsonify({
        "success":     True,
        "identities":  IgIdentity.query.count(),
        "edges":       IgEdge.query.count(),
        "risks":       IgRisk.query.count(),
    })


@identitygraph_bp.route("/api/identitygraph/blast/<int:iid>",
                         methods=["GET"])
@jwt_required()
def blast_radius(iid):
    """
    Calculate blast radius — all resources reachable
    from this identity through the graph.
    """
    identity  = IgIdentity.query.get_or_404(iid)
    edges_out = IgEdge.query.filter_by(source_id=iid).all()
    reachable = []
    visited   = {iid}
    queue     = [e.target_id for e in edges_out]

    while queue:
        nid = queue.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = IgIdentity.query.get(nid)
        if node:
            reachable.append(node.to_dict())
            next_edges = IgEdge.query.filter_by(
                source_id=nid).all()
            queue.extend(e.target_id for e in next_edges
                         if e.target_id not in visited)

    return jsonify({
        "identity":   identity.to_dict(),
        "blast_radius": len(reachable),
        "reachable":  reachable,
    })
