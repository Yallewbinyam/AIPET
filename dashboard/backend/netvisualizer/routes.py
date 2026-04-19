"""
AIPET X — Cloud-Network Visualizer Routes
"""
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from dashboard.backend.models import db
from dashboard.backend.netvisualizer.models import NvNode, NvEdge, NvIssue

netvisualizer_bp = Blueprint("netvisualizer", __name__)


@netvisualizer_bp.route("/api/netvisualizer/graph", methods=["GET"])
@jwt_required()
def get_graph():
    nodes = NvNode.query.all()
    edges = NvEdge.query.all()
    return jsonify({
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
    })


@netvisualizer_bp.route("/api/netvisualizer/nodes", methods=["GET"])
@jwt_required()
def list_nodes():
    zone     = request.args.get("zone")
    q = NvNode.query
    if zone: q = q.filter_by(zone=zone)
    nodes = q.order_by(NvNode.risk_score.desc()).all()
    return jsonify({"nodes": [n.to_dict() for n in nodes]})


@netvisualizer_bp.route("/api/netvisualizer/nodes/<int:nid>", methods=["GET"])
@jwt_required()
def get_node(nid):
    node   = NvNode.query.get_or_404(nid)
    edges  = NvEdge.query.filter(
        (NvEdge.source_id == nid) | (NvEdge.target_id == nid)).all()
    issues = NvIssue.query.filter_by(node_id=nid).all()
    data   = node.to_dict()
    data["connections"] = [e.to_dict() for e in edges]
    data["issues"]      = [i.to_dict() for i in issues]
    return jsonify(data)


@netvisualizer_bp.route("/api/netvisualizer/issues", methods=["GET"])
@jwt_required()
def list_issues():
    severity = request.args.get("severity")
    status   = request.args.get("status", "open")
    q = NvIssue.query
    if severity: q = q.filter_by(severity=severity)
    if status:   q = q.filter_by(status=status)
    issues = q.order_by(NvIssue.created_at.desc()).all()
    return jsonify({"issues": [i.to_dict() for i in issues]})


@netvisualizer_bp.route("/api/netvisualizer/issues/<int:iid>", methods=["PUT"])
@jwt_required()
def update_issue(iid):
    issue = NvIssue.query.get_or_404(iid)
    data  = request.get_json(silent=True) or {}
    if "status" in data:
        issue.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "issue": issue.to_dict()})


@netvisualizer_bp.route("/api/netvisualizer/scan", methods=["POST"])
@jwt_required()
def scan_network():
    nodes = NvNode.query.all()
    edges = NvEdge.query.all()
    for node in nodes:
        issue_count = NvIssue.query.filter_by(
            node_id=node.id, status="open").count()
        node.issue_count = issue_count
        base = 0
        if node.internet_facing:  base += 30
        if not node.encrypted:    base += 20
        if issue_count > 0:       base += issue_count * 15
        cross_zone_count = sum(
            1 for e in edges
            if (e.source_id == node.id or e.target_id == node.id)
            and e.cross_zone and e.risk_level in ("high", "critical"))
        base += cross_zone_count * 10
        node.risk_score = min(100, base)
    db.session.commit()
    return jsonify({
        "success":       True,
        "nodes_updated": len(nodes),
        "edges_mapped":  len(edges),
        "high_risk":     sum(1 for n in nodes if n.risk_score >= 70),
    })


@netvisualizer_bp.route("/api/netvisualizer/stats", methods=["GET"])
@jwt_required()
def network_stats():
    nodes  = NvNode.query.all()
    edges  = NvEdge.query.all()
    issues = NvIssue.query.filter_by(status="open").all()
    by_zone     = {}
    by_provider = {}
    for n in nodes:
        by_zone[n.zone] = by_zone.get(n.zone, 0) + 1
        by_provider[n.cloud_provider or "On-Premise"] = \
            by_provider.get(n.cloud_provider or "On-Premise", 0) + 1
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
