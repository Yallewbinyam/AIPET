"""
AIPET X — Digital Twin Routes

Endpoints:
  GET    /api/twin/nodes              — all twin nodes
  POST   /api/twin/nodes              — add node
  PUT    /api/twin/nodes/<id>         — update node position/state
  DELETE /api/twin/nodes/<id>         — remove node
  GET    /api/twin/edges              — all edges
  POST   /api/twin/edges              — add edge
  DELETE /api/twin/edges/<id>         — remove edge
  POST   /api/twin/sync               — sync twin with scan data
  POST   /api/twin/simulate/<node_id> — simulate node compromise
  GET    /api/twin/snapshots          — snapshot history
  POST   /api/twin/snapshot           — take manual snapshot
  GET    /api/twin/stats              — dashboard metrics
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, Scan, Finding
from dashboard.backend.digitaltwin.models import TwinNode, TwinEdge, TwinSnapshot
from dashboard.backend.siem.models import SiemEvent

twin_bp = Blueprint("twin", __name__)


# ── Node endpoints ───────────────────────────────────────────

@twin_bp.route("/api/twin/nodes", methods=["GET"])
@jwt_required()
def list_nodes():
    """All twin nodes ordered by risk score descending."""
    nodes = TwinNode.query.order_by(TwinNode.risk_score.desc()).all()
    return jsonify({"nodes": [n.to_dict() for n in nodes]})


@twin_bp.route("/api/twin/nodes", methods=["POST"])
@jwt_required()
def add_node():
    """Add a new device to the digital twin."""
    data = request.get_json(silent=True) or {}
    if not data.get("name") or not data.get("node_type"):
        return jsonify({"error": "name and node_type required"}), 400

    node = TwinNode(
        name           = data["name"],
        node_type      = data["node_type"],
        ip_address     = data.get("ip_address"),
        mac_address    = data.get("mac_address"),
        vendor         = data.get("vendor"),
        firmware       = data.get("firmware"),
        location       = data.get("location"),
        zone           = data.get("zone", "operations"),
        expected_state = data.get("expected_state"),
        x_pos          = data.get("x_pos", 0.0),
        y_pos          = data.get("y_pos", 0.0),
    )
    db.session.add(node)
    db.session.commit()
    return jsonify({"success": True, "node": node.to_dict()}), 201


@twin_bp.route("/api/twin/nodes/<int:node_id>", methods=["PUT"])
@jwt_required()
def update_node(node_id):
    """Update node position, state, or metadata."""
    node = TwinNode.query.get_or_404(node_id)
    data = request.get_json(silent=True) or {}
    for field in ["name","node_type","ip_address","vendor","firmware",
                  "location","zone","x_pos","y_pos","risk_score",
                  "diverged","online","actual_state","expected_state"]:
        if field in data:
            setattr(node, field, data[field])
    node.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "node": node.to_dict()})


@twin_bp.route("/api/twin/nodes/<int:node_id>", methods=["DELETE"])
@jwt_required()
def delete_node(node_id):
    """Remove a node and its edges from the twin."""
    node = TwinNode.query.get_or_404(node_id)
    # Remove connected edges first
    TwinEdge.query.filter(
        (TwinEdge.source_id == node_id) |
        (TwinEdge.target_id == node_id)
    ).delete()
    db.session.delete(node)
    db.session.commit()
    return jsonify({"success": True})


# ── Edge endpoints ───────────────────────────────────────────

@twin_bp.route("/api/twin/edges", methods=["GET"])
@jwt_required()
def list_edges():
    """All edges in the twin network."""
    edges = TwinEdge.query.filter_by(active=True).all()
    return jsonify({"edges": [e.to_dict() for e in edges]})


@twin_bp.route("/api/twin/edges", methods=["POST"])
@jwt_required()
def add_edge():
    """Add a connection between two twin nodes."""
    data = request.get_json(silent=True) or {}
    if not data.get("source_id") or not data.get("target_id"):
        return jsonify({"error": "source_id and target_id required"}), 400

    edge = TwinEdge(
        source_id  = data["source_id"],
        target_id  = data["target_id"],
        edge_type  = data.get("edge_type", "data_flow"),
        protocol   = data.get("protocol"),
        port       = data.get("port"),
        encrypted  = data.get("encrypted", True),
        bandwidth  = data.get("bandwidth"),
        latency_ms = data.get("latency_ms"),
    )
    db.session.add(edge)
    db.session.commit()
    return jsonify({"success": True, "edge": edge.to_dict()}), 201


@twin_bp.route("/api/twin/edges/<int:edge_id>", methods=["DELETE"])
@jwt_required()
def delete_edge(edge_id):
    """Remove a connection from the twin."""
    edge = TwinEdge.query.get_or_404(edge_id)
    db.session.delete(edge)
    db.session.commit()
    return jsonify({"success": True})


# ── Sync with scan data ──────────────────────────────────────

@twin_bp.route("/api/twin/sync", methods=["POST"])
@jwt_required()
def sync_twin():
    """
    Synchronise the digital twin with latest AIPET scan data.

    For each device found in scan findings:
      1. Find matching twin node by IP
      2. Update actual_state with observed findings
      3. Compare with expected_state
      4. Set diverged=True if they differ
      5. Recalculate risk score

    Divergence events are pushed to SIEM.
    """
    from sqlalchemy import distinct
    now = datetime.now(timezone.utc)

    # Get all unique IPs from findings
    ips = [row[0] for row in db.session.query(
        distinct(Finding.target)).filter(
        Finding.target.isnot(None)).all()]

    synced    = 0
    diverged  = 0

    for ip in ips:
        findings = Finding.query.filter_by(target=ip).all()
        node     = TwinNode.query.filter_by(ip_address=ip).first()

        if not node:
            continue

        # Build actual state from findings
        actual = {
            "ip":        ip,
            "findings":  [{"severity": f.severity, "attack": f.attack}
                          for f in findings],
            "risk_level": "Critical" if any(
                f.severity == "Critical" for f in findings)
                else "High" if any(
                f.severity == "High" for f in findings)
                else "Medium",
            "last_seen": str(now),
        }
        node.actual_state = json.dumps(actual)

        # Calculate risk score from findings
        score = 0
        for f in findings:
            if f.severity == "Critical": score += 25
            elif f.severity == "High":   score += 15
            elif f.severity == "Medium": score += 8
            elif f.severity == "Low":    score += 3
        node.risk_score = min(score, 100)

        # Check divergence — compare expected vs actual
        was_diverged = node.diverged
        if node.expected_state:
            try:
                expected = json.loads(node.expected_state)
                exp_risk = expected.get("risk_level", "Low")
                act_risk = actual["risk_level"]
                node.diverged = exp_risk != act_risk
            except Exception:
                node.diverged = len(findings) > 0
        else:
            node.diverged = len(findings) > 0

        # Push divergence event to SIEM if newly diverged
        if node.diverged and not was_diverged:
            event = SiemEvent(
                event_type  = "twin_divergence",
                source      = "AIPET Digital Twin",
                severity    = "High",
                title       = f"Digital Twin divergence: {node.name} ({ip})",
                description = f"Device actual state diverges from expected twin model. "
                             f"Risk level changed to {actual["risk_level"]}.",
                mitre_id    = "T1078",
            )
            db.session.add(event)
            diverged += 1

        node.updated_at = now
        synced += 1

    db.session.commit()
    return jsonify({
        "synced":   synced,
        "diverged": diverged,
        "message":  f"Synced {synced} nodes, {diverged} new divergences",
    })


# ── Attack simulation ────────────────────────────────────────

@twin_bp.route("/api/twin/simulate/<int:node_id>", methods=["POST"])
@jwt_required()
def simulate_compromise(node_id):
    """
    Simulate what happens if a specific node is compromised.

    The simulation:
      1. Marks the target node as compromised
      2. Traces all outbound edges from that node
      3. For each connected node, calculates propagation risk
         based on edge encryption and target node risk score
      4. Returns the blast radius — which devices are at risk

    This is the AIPET X equivalent of MITRE ATT&CK lateral movement
    simulation — showing exactly how an attacker would move.

    Takes a snapshot before simulation for comparison.
    """
    target = TwinNode.query.get_or_404(node_id)
    data   = request.get_json(silent=True) or {}

    # Take pre-simulation snapshot
    all_nodes = TwinNode.query.all()
    all_edges = TwinEdge.query.all()
    pre_snap  = TwinSnapshot(
        label          = f"Pre-simulation: {target.name}",
        snapshot_type  = "pre_simulation",
        node_count     = len(all_nodes),
        edge_count     = len(all_edges),
        diverged_count = sum(1 for n in all_nodes if n.diverged),
        risk_avg       = sum(n.risk_score for n in all_nodes) / max(len(all_nodes), 1),
        created_by     = int(get_jwt_identity()),
    )
    db.session.add(pre_snap)

    # Trace blast radius using BFS from compromised node
    blast_radius  = []
    visited       = {node_id}
    queue         = [node_id]

    while queue:
        current_id = queue.pop(0)
        # Find all edges from this node
        outbound = TwinEdge.query.filter_by(
            source_id=current_id, active=True).all()

        for edge in outbound:
            if edge.target_id not in visited:
                visited.add(edge.target_id)
                neighbor = TwinNode.query.get(edge.target_id)
                if neighbor:
                    # Propagation risk — higher if connection unencrypted
                    prop_risk = target.risk_score
                    if not edge.encrypted:
                        prop_risk = min(prop_risk + 20, 100)

                    blast_radius.append({
                        "node":        neighbor.to_dict(),
                        "edge":        edge.to_dict(),
                        "prop_risk":   prop_risk,
                        "attack_path": f"{target.name} → {neighbor.name}",
                        "vector":      "unencrypted" if not edge.encrypted
                                       else "lateral_movement",
                    })
                    # Continue propagation from high-risk neighbors
                    if prop_risk >= 50:
                        queue.append(edge.target_id)

    # Push simulation event to SIEM
    event = SiemEvent(
        event_type  = "twin_simulation",
        source      = "AIPET Digital Twin",
        severity    = "High",
        title       = f"Attack simulation: {target.name} compromised",
        description = f"Blast radius: {len(blast_radius)} devices at risk. "
                     f"Simulated lateral movement from {target.ip_address}.",
        mitre_id    = "T1021",
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "target":       target.to_dict(),
        "blast_radius": blast_radius,
        "affected":     len(blast_radius),
        "message":      f"{len(blast_radius)} devices reachable from {target.name}",
    })


# ── Snapshots ────────────────────────────────────────────────

@twin_bp.route("/api/twin/snapshots", methods=["GET"])
@jwt_required()
def list_snapshots():
    """Snapshot history — newest first."""
    snaps = TwinSnapshot.query.order_by(
        TwinSnapshot.created_at.desc()).limit(20).all()
    return jsonify({"snapshots": [s.to_dict() for s in snaps]})


@twin_bp.route("/api/twin/snapshot", methods=["POST"])
@jwt_required()
def take_snapshot():
    """Take a manual snapshot of current twin state."""
    data      = request.get_json(silent=True) or {}
    all_nodes = TwinNode.query.all()
    all_edges = TwinEdge.query.all()

    snap = TwinSnapshot(
        label          = data.get("label", "Manual snapshot"),
        snapshot_type  = "manual",
        node_count     = len(all_nodes),
        edge_count     = len(all_edges),
        diverged_count = sum(1 for n in all_nodes if n.diverged),
        risk_avg       = sum(n.risk_score for n in all_nodes) /
                         max(len(all_nodes), 1),
        data           = json.dumps([n.to_dict() for n in all_nodes]),
        created_by     = int(get_jwt_identity()),
    )
    db.session.add(snap)
    db.session.commit()
    return jsonify({"success": True, "snapshot": snap.to_dict()}), 201


# ── Stats ────────────────────────────────────────────────────

@twin_bp.route("/api/twin/stats", methods=["GET"])
@jwt_required()
def twin_stats():
    """Dashboard metrics."""
    nodes         = TwinNode.query.all()
    total_nodes   = len(nodes)
    diverged      = sum(1 for n in nodes if n.diverged)
    online        = sum(1 for n in nodes if n.online)
    high_risk     = sum(1 for n in nodes if n.risk_score >= 70)
    avg_risk      = sum(n.risk_score for n in nodes) / max(total_nodes, 1)
    total_edges   = TwinEdge.query.filter_by(active=True).count()
    unenc_edges   = TwinEdge.query.filter_by(
        active=True, encrypted=False).count()
    snapshots     = TwinSnapshot.query.count()

    return jsonify({
        "total_nodes":   total_nodes,
        "diverged":      diverged,
        "online":        online,
        "high_risk":     high_risk,
        "avg_risk":      round(avg_risk, 1),
        "total_edges":   total_edges,
        "unenc_edges":   unenc_edges,
        "snapshots":     snapshots,
    })
