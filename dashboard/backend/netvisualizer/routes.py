"""
AIPET X — Cloud-Network Visualizer Routes (Capability 15, v1)

Endpoints:
  GET    /api/netvisualizer/graph         — all user-owned nodes + edges
  GET    /api/netvisualizer/nodes         — node list (filterable by ?zone)
  GET    /api/netvisualizer/nodes/<id>    — node detail + edges + issues
  GET    /api/netvisualizer/issues        — issue list (filter by status/severity)
  PUT    /api/netvisualizer/issues/<id>   — update issue status
  POST   /api/netvisualizer/scan          — re-ingest from real_scan_results
  GET    /api/netvisualizer/stats         — aggregate counts

Capability 15 v1 ships a real Nmap-driven topology graph. Each
POST /scan reads the calling user's RealScanResult.results_json,
classifies each host's zone, and rebuilds the user's section of
the nv_nodes / nv_edges / nv_issues tables. The frontend
NetVisualizerPage already renders a d3 force-directed graph
reading from /graph; pre-Cap-15 the tables were empty.

User scoping (no schema migration):
- NvNode.node_meta is JSON-serialized text. We store
  {"user_id": <int>, ...} on every node we ingest.
- NvEdge and NvIssue have no node_meta column. Their ownership is
  derived transitively via FK to NvNode (source_id / target_id /
  node_id). _scope_node_ids(user_id) is the single source of truth.

Zone classification (per spec):
- port_count > 10                                  -> ot
- private RFC1918 (10/8, 172.16/12, 192.168/16)    -> corporate
- everything else                                   -> dmz

Edge inference (per spec):
- same-subnet hosts (IPv4 first three octets match) -> lateral edge
- non-private (internet-facing) host -> "Internet" -> host edge
- a synthetic NvNode named "Internet" with zone=internet is
  ingested per user when at least one internet-facing host exists

Issue generation (per spec):
- cve_count >= 3 OR KEV-listed CVE present OR risk_score >= 70
  -> one NvIssue row per offending host with severity from risk

Idempotency:
- POST /scan is "full refresh of user's network state". On each
  call we DELETE the user's existing nv_nodes / nv_edges / nv_issues
  and reinsert from current scan data. v1 trade-off: NvIssue.status
  history (open / resolved) is reset on every scan. Acceptable for
  v1; the v1.1 cleanup pass that consolidates netvisualizer+map will
  add issue diffing.
"""
import ipaddress
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.netvisualizer.models import NvNode, NvEdge, NvIssue
from dashboard.backend.real_scanner.routes import RealScanResult
from dashboard.backend.live_cves.models import KevCatalogEntry

netvisualizer_bp = Blueprint("netvisualizer", __name__)


# ── Constants ────────────────────────────────────────────────
HIGH_PORT_COUNT_OT_THRESHOLD = 10   # >10 open ports -> OT zone (per spec)
HIGH_RISK_SCORE_FLOOR        = 70   # >=70 -> generate NvIssue
HIGH_CVE_COUNT_FLOOR         = 3    # >=3 -> generate NvIssue
RECENT_SCANS_LIMIT           = 20


# ── User-scoping helpers (no schema change) ─────────────────

def _node_user_id(node):
    """Pull user_id out of NvNode.node_meta (JSON-serialized Text)."""
    if not node.node_meta:
        return None
    try:
        meta = json.loads(node.node_meta)
        return meta.get("user_id")
    except (ValueError, TypeError):
        return None


def _set_user_meta(node, user_id, **extra):
    """Store {'user_id': N, ...} into NvNode.node_meta as JSON text."""
    payload = {"user_id": int(user_id)}
    payload.update(extra)
    node.node_meta = json.dumps(payload, default=str)


def _scope_node_ids(user_id):
    """Return set of NvNode.id values owned by user_id.

    Source of truth for transitive owner-filtering on NvEdge and
    NvIssue. v1 reads NvNode rows in Python; per-user node count is
    expected in the dozens-to-low-hundreds at v1 scale, so the
    Python filter is fine and avoids JSON-operator queries that
    diverge between PostgreSQL and SQLite (test) backends.
    """
    user_id = int(user_id)
    return {
        n.id
        for n in NvNode.query.all()
        if _node_user_id(n) == user_id
    }


# ── Zone / edge / issue classifiers ─────────────────────────

def _is_private_ip(ip):
    """True for RFC1918 private addresses; tolerant of malformed input."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _classify_zone(host):
    """Return zone string per spec.

    >10 open ports -> ot   (overrides IP class because OT/ICS hosts
                            commonly sit on private subnets but
                            warrant the OT zone label)
    private IP     -> corporate
    public IP      -> dmz
    """
    open_ports = host.get("open_ports") or []
    port_count = host.get("port_count")
    if port_count is None:
        port_count = len(open_ports)
    if port_count > HIGH_PORT_COUNT_OT_THRESHOLD:
        return "ot"
    if _is_private_ip(host.get("ip")):
        return "corporate"
    return "dmz"


def _subnet_key(ip):
    """First three octets of an IPv4 address. None for non-IPv4."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if addr.version != 4:
        return None
    parts = ip.split(".")
    if len(parts) < 3:
        return None
    return ".".join(parts[:3])


def _should_create_issue(host, kev_hits):
    """Per spec: CVE_count >= 3 OR KEV-listed OR risk_score >= 70."""
    cve_count = host.get("cve_count") or len(host.get("cves") or [])
    risk = host.get("risk_score") or 0
    if cve_count >= HIGH_CVE_COUNT_FLOOR:
        return True
    if risk >= HIGH_RISK_SCORE_FLOOR:
        return True
    host_cve_ids = {
        (c.get("cve_id") if isinstance(c, dict) else c)
        for c in (host.get("cves") or [])
    }
    return bool(host_cve_ids & kev_hits)


def _issue_severity_for(host, kev_hits):
    """Critical when KEV-listed; High when risk >= 70; else Medium."""
    host_cve_ids = {
        (c.get("cve_id") if isinstance(c, dict) else c)
        for c in (host.get("cves") or [])
    }
    if host_cve_ids & kev_hits:
        return "Critical"
    if (host.get("risk_score") or 0) >= HIGH_RISK_SCORE_FLOOR:
        return "High"
    return "Medium"


def _classify_node_type(host):
    """Best-effort guess at NvNode.node_type from open services."""
    services = {
        (p.get("service") or "").lower()
        for p in (host.get("open_ports") or [])
        if isinstance(p, dict)
    }
    if {"mqtt", "modbus", "iec-104"} & services:
        return "iot_device"
    if {"mysql", "postgresql", "mssql", "mongodb", "redis"} & services:
        return "database"
    return "server"


def _collect_user_hosts(user_id):
    """Flatten the user's most recent complete scans into dict[ip]->host."""
    scans = (RealScanResult.query
             .filter_by(user_id=user_id, status="complete")
             .order_by(RealScanResult.finished_at.desc().nullslast())
             .limit(RECENT_SCANS_LIMIT)
             .all())
    hosts_by_ip = {}
    for scan in scans:
        try:
            results = json.loads(scan.results_json or "[]")
        except (ValueError, TypeError):
            continue
        if not isinstance(results, list):
            continue
        for host in results:
            if not isinstance(host, dict):
                continue
            ip = host.get("ip")
            if not ip or ip in hosts_by_ip:
                continue
            hosts_by_ip[ip] = host
    return hosts_by_ip


def _kev_hits_for_hosts(hosts_by_ip):
    """One IN-query for every CVE the user's hosts mention. Returns
    set of CVE IDs that appear in kev_catalog. Empty if no CVEs."""
    all_cve_ids = set()
    for host in hosts_by_ip.values():
        for c in (host.get("cves") or []):
            cid = c.get("cve_id") if isinstance(c, dict) else c
            if cid:
                all_cve_ids.add(cid)
    if not all_cve_ids:
        return set()
    return {
        row.cve_id
        for row in KevCatalogEntry.query.filter(
            KevCatalogEntry.cve_id.in_(all_cve_ids)
        ).all()
    }


def _purge_user_state(user_id):
    """Delete user-owned NvIssue, NvEdge, NvNode rows in FK-safe order."""
    node_ids = _scope_node_ids(user_id)
    if not node_ids:
        return
    NvIssue.query.filter(NvIssue.node_id.in_(node_ids)).delete(
        synchronize_session=False
    )
    NvEdge.query.filter(
        (NvEdge.source_id.in_(node_ids)) |
        (NvEdge.target_id.in_(node_ids))
    ).delete(synchronize_session=False)
    NvNode.query.filter(NvNode.id.in_(node_ids)).delete(
        synchronize_session=False
    )
    db.session.commit()


def _ingest_for_user(user_id):
    """Rebuild user's nv_nodes / nv_edges / nv_issues from the freshest
    RealScanResult data. Returns counts for the API response."""
    user_id = int(user_id)
    hosts_by_ip = _collect_user_hosts(user_id)
    kev_hits = _kev_hits_for_hosts(hosts_by_ip)

    _purge_user_state(user_id)

    if not hosts_by_ip:
        db.session.commit()
        return {"nodes": 0, "edges": 0, "issues": 0, "high_risk": 0}

    # ── 1. Insert host nodes ──
    inserted_nodes_by_ip = {}
    has_internet_facing = False
    for ip, host in hosts_by_ip.items():
        zone = _classify_zone(host)
        node_type = _classify_node_type(host)
        risk = int(host.get("risk_score") or 0)
        port_count = host.get("port_count") or len(host.get("open_ports") or [])
        is_internet_facing = not _is_private_ip(ip)
        if is_internet_facing:
            has_internet_facing = True

        node = NvNode(
            name            = ip,
            node_type       = node_type,
            zone            = zone,
            ip_address      = ip,
            risk_score      = risk,
            internet_facing = is_internet_facing,
            encrypted       = True,
            issue_count     = 0,
            status          = "active",
        )
        _set_user_meta(
            node, user_id,
            port_count = port_count,
            cve_count  = host.get("cve_count")
                         or len(host.get("cves") or []),
            ingested_at= datetime.now(timezone.utc).isoformat(),
        )
        db.session.add(node)
        inserted_nodes_by_ip[ip] = node

    db.session.flush()

    # ── 2. Synthetic Internet node when any host is reachable
    # from outside, so the perimeter edge has a source.
    internet_node = None
    if has_internet_facing:
        internet_node = NvNode(
            name            = "Internet",
            node_type       = "internet",
            zone            = "internet",
            ip_address      = None,
            risk_score      = 0,
            internet_facing = True,
            encrypted       = False,
            issue_count     = 0,
            status          = "active",
        )
        _set_user_meta(internet_node, user_id, synthetic=True)
        db.session.add(internet_node)
        db.session.flush()

    # ── 3. Edges ──
    edges_added = 0

    # 3a. internet -> host for every internet-facing host.
    if internet_node is not None:
        for ip, node in inserted_nodes_by_ip.items():
            if not node.internet_facing:
                continue
            db.session.add(NvEdge(
                source_id    = internet_node.id,
                target_id    = node.id,
                protocol     = "tcp",
                port         = None,
                encrypted    = False,
                risk_level   = "high" if node.risk_score >= 60 else "medium",
                cross_zone   = True,
                bidirectional= False,
                traffic_gbday= 0.0,
            ))
            edges_added += 1

    # 3b. lateral edges between hosts that share a /24 subnet.
    by_subnet = {}
    for ip, node in inserted_nodes_by_ip.items():
        key = _subnet_key(ip)
        if not key:
            continue
        by_subnet.setdefault(key, []).append(node)
    for nodes_in_subnet in by_subnet.values():
        if len(nodes_in_subnet) < 2:
            continue
        for i in range(len(nodes_in_subnet)):
            for j in range(i + 1, len(nodes_in_subnet)):
                a, b = nodes_in_subnet[i], nodes_in_subnet[j]
                db.session.add(NvEdge(
                    source_id    = a.id,
                    target_id    = b.id,
                    protocol     = "lateral",
                    port         = None,
                    encrypted    = True,
                    risk_level   = "low",
                    cross_zone   = (a.zone != b.zone),
                    bidirectional= True,
                    traffic_gbday= 0.0,
                ))
                edges_added += 1

    # ── 4. Issues ──
    issues_added = 0
    high_risk = 0
    for ip, host in hosts_by_ip.items():
        node = inserted_nodes_by_ip[ip]
        if node.risk_score >= HIGH_RISK_SCORE_FLOOR:
            high_risk += 1
        if not _should_create_issue(host, kev_hits):
            continue
        severity = _issue_severity_for(host, kev_hits)
        host_cve_ids = [
            (c.get("cve_id") if isinstance(c, dict) else c)
            for c in (host.get("cves") or [])
        ]
        kev_cves = [c for c in host_cve_ids if c in kev_hits]
        cve_count = host.get("cve_count") or len(host.get("cves") or [])

        if kev_cves:
            title = f"KEV-listed CVE active on {ip} ({kev_cves[0]})"
            description = (
                f"Host {ip} carries CVE {kev_cves[0]}, listed in CISA's "
                f"Known Exploited Vulnerabilities catalog. Active "
                f"exploitation has been observed in the wild."
            )
            remediation = (
                f"Patch {kev_cves[0]} immediately. CISA KEV listing "
                f"implies a federal patch deadline applies."
            )
        elif cve_count >= HIGH_CVE_COUNT_FLOOR:
            title = f"{cve_count} CVEs on {ip}"
            description = (
                f"Host {ip} carries {cve_count} known vulnerabilities at "
                f"scan time. Review and prioritise by CVSS."
            )
            remediation = "Patch the highest-CVSS CVEs first."
        else:
            title = f"High risk score on {ip} ({node.risk_score}/100)"
            description = (
                f"Host {ip} scored {node.risk_score} in the most recent "
                f"scan. Review open ports, services, and exposure."
            )
            remediation = (
                "Reduce attack surface: close unused ports, restrict "
                "service binding, patch outdated software."
            )

        issue = NvIssue(
            node_id     = node.id,
            severity    = severity,
            title       = title,
            description = description,
            remediation = remediation,
            status      = "open",
        )
        db.session.add(issue)
        issues_added += 1
        node.issue_count = (node.issue_count or 0) + 1

    db.session.commit()

    # ── 5. Recompute risk_score with cross-zone + issue-count signals
    # (matches the prior implementation's second pass, scoped to user).
    user_node_ids = {n.id for n in inserted_nodes_by_ip.values()}
    if internet_node is not None:
        user_node_ids.add(internet_node.id)
    user_nodes = NvNode.query.filter(NvNode.id.in_(user_node_ids)).all()
    user_edges = NvEdge.query.filter(
        (NvEdge.source_id.in_(user_node_ids)) |
        (NvEdge.target_id.in_(user_node_ids))
    ).all()
    for node in user_nodes:
        if _node_user_id(node) != user_id:
            continue
        derived = node.risk_score or 0
        if node.internet_facing:
            derived = max(derived, 30 + (node.issue_count or 0) * 15)
        if not node.encrypted:
            derived += 20
        cross_zone_count = sum(
            1 for e in user_edges
            if (e.source_id == node.id or e.target_id == node.id)
            and e.cross_zone
            and e.risk_level in ("high", "critical")
        )
        derived += cross_zone_count * 10
        node.risk_score = min(100, derived)
    db.session.commit()

    return {
        "nodes":     len(inserted_nodes_by_ip) + (1 if internet_node else 0),
        "edges":     edges_added,
        "issues":    issues_added,
        "high_risk": high_risk,
    }


# ── Routes ───────────────────────────────────────────────────

@netvisualizer_bp.route("/api/netvisualizer/graph", methods=["GET"])
@jwt_required()
def get_graph():
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    if not node_ids:
        return jsonify({"nodes": [], "edges": []})
    nodes = NvNode.query.filter(NvNode.id.in_(node_ids)).all()
    edges = NvEdge.query.filter(
        (NvEdge.source_id.in_(node_ids)) |
        (NvEdge.target_id.in_(node_ids))
    ).all()
    return jsonify({
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
    })


@netvisualizer_bp.route("/api/netvisualizer/nodes", methods=["GET"])
@jwt_required()
def list_nodes():
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    zone = request.args.get("zone")
    if not node_ids:
        return jsonify({"nodes": []})
    q = NvNode.query.filter(NvNode.id.in_(node_ids))
    if zone:
        q = q.filter_by(zone=zone)
    nodes = q.order_by(NvNode.risk_score.desc()).all()
    return jsonify({"nodes": [n.to_dict() for n in nodes]})


@netvisualizer_bp.route("/api/netvisualizer/nodes/<int:nid>", methods=["GET"])
@jwt_required()
def get_node(nid):
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    if nid not in node_ids:
        return jsonify({"error": "not_found"}), 404
    node = NvNode.query.get(nid)
    edges = NvEdge.query.filter(
        (NvEdge.source_id == nid) | (NvEdge.target_id == nid)
    ).all()
    issues = NvIssue.query.filter_by(node_id=nid).all()
    data = node.to_dict()
    data["connections"] = [e.to_dict() for e in edges]
    data["issues"]      = [i.to_dict() for i in issues]
    return jsonify(data)


@netvisualizer_bp.route("/api/netvisualizer/issues", methods=["GET"])
@jwt_required()
def list_issues():
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    severity = request.args.get("severity")
    status   = request.args.get("status", "open")
    if not node_ids:
        return jsonify({"issues": []})
    q = NvIssue.query.filter(NvIssue.node_id.in_(node_ids))
    if severity:
        q = q.filter_by(severity=severity)
    if status:
        q = q.filter_by(status=status)
    issues = q.order_by(NvIssue.created_at.desc()).all()
    return jsonify({"issues": [i.to_dict() for i in issues]})


@netvisualizer_bp.route("/api/netvisualizer/issues/<int:iid>", methods=["PUT"])
@jwt_required()
def update_issue(iid):
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    issue = NvIssue.query.get_or_404(iid)
    if issue.node_id not in node_ids:
        return jsonify({"error": "not_found"}), 404
    data = request.get_json(silent=True) or {}
    if "status" in data:
        issue.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "issue": issue.to_dict()})


@netvisualizer_bp.route("/api/netvisualizer/scan", methods=["POST"])
@jwt_required()
def scan_network():
    """Re-ingest the calling user's RealScanResult data into the
    netvisualizer tables. An empty scan inventory yields zero
    nodes/edges/issues with success=True (honest empty)."""
    user_id = int(get_jwt_identity())
    counts = _ingest_for_user(user_id)
    return jsonify({
        "success":       True,
        "nodes_updated": counts["nodes"],
        "edges_mapped":  counts["edges"],
        "issues_added":  counts["issues"],
        "high_risk":     counts["high_risk"],
    })


@netvisualizer_bp.route("/api/netvisualizer/stats", methods=["GET"])
@jwt_required()
def network_stats():
    user_id = int(get_jwt_identity())
    node_ids = _scope_node_ids(user_id)
    if not node_ids:
        return jsonify({
            "total_nodes": 0, "total_edges": 0, "total_issues": 0,
            "internet_facing": 0, "unencrypted_edges": 0,
            "cross_zone_edges": 0, "high_risk_nodes": 0,
            "critical_issues": 0, "by_zone": {}, "by_provider": {},
        })
    nodes = NvNode.query.filter(NvNode.id.in_(node_ids)).all()
    edges = NvEdge.query.filter(
        (NvEdge.source_id.in_(node_ids)) |
        (NvEdge.target_id.in_(node_ids))
    ).all()
    issues = NvIssue.query.filter(
        NvIssue.node_id.in_(node_ids),
        NvIssue.status == "open",
    ).all()
    by_zone     = {}
    by_provider = {}
    for n in nodes:
        by_zone[n.zone] = by_zone.get(n.zone, 0) + 1
        prov = n.cloud_provider or "On-Premise"
        by_provider[prov] = by_provider.get(prov, 0) + 1
    return jsonify({
        "total_nodes":       len(nodes),
        "total_edges":       len(edges),
        "total_issues":      len(issues),
        "internet_facing":   sum(1 for n in nodes if n.internet_facing),
        "unencrypted_edges": sum(1 for e in edges if not e.encrypted),
        "cross_zone_edges":  sum(1 for e in edges if e.cross_zone),
        "high_risk_nodes":   sum(1 for n in nodes if n.risk_score >= 70),
        "critical_issues":   sum(1 for i in issues if i.severity == "Critical"),
        "by_zone":           by_zone,
        "by_provider":       by_provider,
    })
