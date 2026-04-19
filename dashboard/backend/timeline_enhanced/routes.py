"""
AIPET X — Unified Security Timeline Enhanced Routes

Endpoints:
  GET  /api/timeline_enhanced/events      — enriched event feed
  GET  /api/timeline_enhanced/clusters    — correlated event clusters
  POST /api/timeline_enhanced/collect     — collect events from all modules
  POST /api/timeline_enhanced/correlate   — run AI correlation
  GET  /api/timeline_enhanced/stats       — timeline metrics
  PUT  /api/timeline_enhanced/events/<id> — resolve event
"""
import json, os, urllib.request
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.timeline_enhanced.models import TeEvent, TeCluster

timeline_enhanced_bp = Blueprint("timeline_enhanced", __name__)

MODULE_META = {
    "behavioral":     {"color":"#a78bfa", "icon":"🧠", "label":"Behavioral AI"},
    "identity_graph": {"color":"#00e5ff", "icon":"🕸️", "label":"Identity Graph"},
    "drift":          {"color":"#ff8c00", "icon":"🎯", "label":"Drift Detector"},
    "dspm":           {"color":"#00e5ff", "icon":"🛡️", "label":"Data Security"},
    "api_security":   {"color":"#ff8c00", "icon":"🔌", "label":"API Security"},
    "supply_chain":   {"color":"#a78bfa", "icon":"🔗", "label":"Supply Chain"},
    "network":        {"color":"#00ff88", "icon":"🗺️", "label":"Network"},
    "compliance":     {"color":"#00ff88", "icon":"📋", "label":"Compliance"},
    "cost_security":  {"color":"#00ff88", "icon":"💰", "label":"Cost Security"},
    "resilience":     {"color":"#00ff88", "icon":"🛡️", "label":"Resilience"},
    "siem":           {"color":"#ff3b5c", "icon":"⚡", "label":"SIEM"},
    "scan":           {"color":"#00e5ff", "icon":"🔍", "label":"Scan"},
    "user":           {"color":"#64748b", "icon":"👤", "label":"User"},
}


@timeline_enhanced_bp.route("/api/timeline_enhanced/events", methods=["GET"])
@jwt_required()
def list_events():
    page      = int(request.args.get("page", 1))
    per_page  = min(int(request.args.get("per_page", 50)), 200)
    severity  = request.args.get("severity")
    module    = request.args.get("source_module")
    correlated= request.args.get("correlated")
    days      = int(request.args.get("days", 7))
    since     = datetime.now(timezone.utc) - timedelta(days=days)

    q = TeEvent.query.filter(TeEvent.created_at >= since)
    if severity:   q = q.filter_by(severity=severity)
    if module:     q = q.filter_by(source_module=module)
    if correlated is not None:
        q = q.filter_by(correlated=correlated.lower()=="true")

    total  = q.count()
    events = q.order_by(TeEvent.created_at.desc()).offset(
        (page-1)*per_page).limit(per_page).all()

    return jsonify({
        "events":   [e.to_dict() for e in events],
        "total":    total,
        "page":     page,
        "per_page": per_page,
    })


@timeline_enhanced_bp.route("/api/timeline_enhanced/clusters", methods=["GET"])
@jwt_required()
def list_clusters():
    status   = request.args.get("status", "active")
    clusters = TeCluster.query.filter_by(status=status).order_by(
        TeCluster.created_at.desc()).all()
    result = []
    for c in clusters:
        data = c.to_dict()
        data["events"] = [e.to_dict() for e in
            TeEvent.query.filter_by(cluster_id=c.id).order_by(
                TeEvent.created_at.asc()).all()]
        result.append(data)
    return jsonify({"clusters": result})


@timeline_enhanced_bp.route("/api/timeline_enhanced/collect", methods=["POST"])
@jwt_required()
def collect_events():
    """
    Collect events from all Phase 5B modules and add to enhanced timeline.
    This pulls real data from each module and creates enriched timeline events.
    """
    now    = datetime.now(timezone.utc)
    added  = 0

    try:
        # Pull from Behavioral AI
        from dashboard.backend.behavioral.models import BaAnomaly
        anomalies = BaAnomaly.query.filter_by(status="new").limit(5).all()
        for a in anomalies:
            existing = TeEvent.query.filter_by(
                source_module="behavioral", raw_ref_id=a.id).first()
            if not existing:
                db.session.add(TeEvent(
                    source_module = "behavioral",
                    event_type    = a.anomaly_type,
                    severity      = a.severity,
                    title         = a.title,
                    description   = a.description,
                    entity        = a.entity_name,
                    entity_type   = "device_or_user",
                    mitre_id      = a.mitre_id,
                    risk_score    = min(100, int(a.deviation * 10)),
                    raw_ref_id    = a.id,
                    created_at    = a.created_at or now,
                ))
                added += 1

        # Pull from Drift Detector
        from dashboard.backend.driftdetector.models import DdDrift
        drifts = DdDrift.query.filter_by(status="open").limit(5).all()
        for d in drifts:
            existing = TeEvent.query.filter_by(
                source_module="drift", raw_ref_id=d.id).first()
            if not existing:
                db.session.add(TeEvent(
                    source_module = "drift",
                    event_type    = d.drift_type,
                    severity      = d.severity,
                    title         = d.title,
                    description   = d.description,
                    entity        = d.identity_name,
                    entity_type   = "identity",
                    risk_score    = 80 if d.severity=="Critical" else 60,
                    raw_ref_id    = d.id,
                    created_at    = d.detected_at or now,
                ))
                added += 1

        # Pull from Network Visualizer
        from dashboard.backend.netvisualizer.models import NvIssue, NvNode
        net_issues = NvIssue.query.filter_by(status="open").limit(5).all()
        for i in net_issues:
            existing = TeEvent.query.filter_by(
                source_module="network", raw_ref_id=i.id).first()
            if not existing:
                node = NvNode.query.get(i.node_id) if i.node_id else None
                db.session.add(TeEvent(
                    source_module = "network",
                    event_type    = "network_issue",
                    severity      = i.severity,
                    title         = i.title,
                    description   = i.description,
                    entity        = node.name if node else "Unknown",
                    entity_type   = "network_node",
                    risk_score    = 85 if i.severity=="Critical" else 60,
                    raw_ref_id    = i.id,
                    created_at    = i.created_at or now,
                ))
                added += 1

        # Pull from API Security
        from dashboard.backend.apisecurity.models import AsFinding, AsEndpoint
        api_findings = AsFinding.query.filter_by(
            status="open", severity="Critical").limit(5).all()
        for f in api_findings:
            existing = TeEvent.query.filter_by(
                source_module="api_security", raw_ref_id=f.id).first()
            if not existing:
                ep = AsEndpoint.query.get(f.endpoint_id)
                db.session.add(TeEvent(
                    source_module = "api_security",
                    event_type    = f.finding_type,
                    severity      = f.severity,
                    title         = f.title,
                    description   = f.description,
                    entity        = f"{ep.method} {ep.path}" if ep else "Unknown",
                    entity_type   = "api_endpoint",
                    risk_score    = 90 if f.severity=="Critical" else 65,
                    raw_ref_id    = f.id,
                    created_at    = f.created_at or now,
                ))
                added += 1

        # Pull from Supply Chain
        from dashboard.backend.supplychain.models import ScVuln, ScComponent
        sc_vulns = ScVuln.query.filter_by(
            status="open", severity="Critical").limit(5).all()
        for v in sc_vulns:
            existing = TeEvent.query.filter_by(
                source_module="supply_chain", raw_ref_id=v.id).first()
            if not existing:
                comp = ScComponent.query.get(v.component_id)
                db.session.add(TeEvent(
                    source_module = "supply_chain",
                    event_type    = "critical_cve",
                    severity      = v.severity,
                    title         = f"{v.cve_id}: {v.title}",
                    description   = v.description,
                    entity        = f"{comp.name} v{comp.version}" if comp else "Unknown",
                    entity_type   = "software_component",
                    mitre_id      = None,
                    risk_score    = int(v.cvss_score * 10),
                    raw_ref_id    = v.id,
                    created_at    = v.created_at or now,
                ))
                added += 1

        # Pull from DSPM
        from dashboard.backend.dspm.models import DspmFinding, DspmDatastore
        dspm_findings = DspmFinding.query.filter_by(
            status="open", severity="Critical").limit(3).all()
        for f in dspm_findings:
            existing = TeEvent.query.filter_by(
                source_module="dspm", raw_ref_id=f.id).first()
            if not existing:
                store = DspmDatastore.query.get(f.datastore_id)
                db.session.add(TeEvent(
                    source_module = "dspm",
                    event_type    = f.finding_type,
                    severity      = f.severity,
                    title         = f.title,
                    description   = f.description,
                    entity        = store.name if store else "Unknown",
                    entity_type   = "data_store",
                    risk_score    = 95,
                    raw_ref_id    = f.id,
                    created_at    = f.created_at or now,
                ))
                added += 1

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "success":     True,
        "events_added":added,
        "total_events":TeEvent.query.count(),
    })


@timeline_enhanced_bp.route("/api/timeline_enhanced/correlate", methods=["POST"])
@jwt_required()
def correlate_events():
    """
    Use Claude AI to correlate related events into clusters.
    Groups events by entity, time window, and attack patterns.
    """
    # Get recent unclustered events
    since  = datetime.now(timezone.utc) - timedelta(days=7)
    events = TeEvent.query.filter(
        TeEvent.created_at >= since,
        TeEvent.cluster_id == None,
        TeEvent.severity.in_(["Critical","High"])
    ).order_by(TeEvent.created_at.desc()).limit(30).all()

    if not events:
        return jsonify({
            "success":  True,
            "message":  "No unclustered events to correlate",
            "clusters": 0,
        })

    # Group events by entity for correlation
    entity_groups = {}
    for e in events:
        key = e.entity or "unknown"
        if key not in entity_groups:
            entity_groups[key] = []
        entity_groups[key].append(e)

    clusters_created = 0

    for entity, entity_events in entity_groups.items():
        if len(entity_events) < 2:
            continue

        modules = list(set(e.source_module for e in entity_events))
        severities = [e.severity for e in entity_events]
        has_critical = "Critical" in severities

        # Build context for Claude
        event_summary = "\n".join([
            f"- [{e.severity}] [{e.source_module}] {e.title}"
            for e in entity_events[:8]
        ])

        prompt = f"""You are AIPET X security analyst. Analyze these correlated security events
for entity: {entity}

Events detected:
{event_summary}

Modules involved: {", ".join(modules)}

In 2-3 sentences, explain:
1. What is happening to this entity
2. What the likely attack pattern or risk is
3. What immediate action is needed

Be specific and actionable. No markdown."""

        ai_summary = f"Multiple security events detected across {len(modules)} modules for {entity}. Manual investigation required."

        try:
            api_key = os.environ.get("ANTHROPIC_API_KEY","")
            if api_key:
                payload = json.dumps({
                    "model":      "claude-opus-4-5",
                    "max_tokens": 200,
                    "messages":   [{"role":"user","content":prompt}],
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=payload,
                    headers={
                        "x-api-key":         api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type":      "application/json",
                    }, method="POST"
                )
                with urllib.request.urlopen(req, timeout=20) as resp:
                    result     = json.loads(resp.read().decode("utf-8"))
                    ai_summary = result["content"][0]["text"]
        except Exception:
            pass

        cluster = TeCluster(
            title    = f"Correlated Alert: {entity} — {len(entity_events)} events across {len(modules)} modules",
            cluster_type = "attack_chain" if has_critical else "anomaly_group",
            severity = "Critical" if has_critical else "High",
            event_count = len(entity_events),
            modules_involved = json.dumps(modules),
            ai_summary = ai_summary,
            status     = "active",
            started_at = min(e.created_at for e in entity_events),
        )
        db.session.add(cluster)
        db.session.flush()

        for e in entity_events:
            e.cluster_id  = cluster.id
            e.correlated  = True

        clusters_created += 1

    db.session.commit()
    return jsonify({
        "success":          True,
        "clusters_created": clusters_created,
        "events_correlated":sum(len(v) for v in entity_groups.values()
                               if len(v) >= 2),
    })


@timeline_enhanced_bp.route("/api/timeline_enhanced/events/<int:eid>",
                            methods=["PUT"])
@jwt_required()
def update_event(eid):
    event = TeEvent.query.get_or_404(eid)
    data  = request.get_json(silent=True) or {}
    if "resolved" in data:
        event.resolved = bool(data["resolved"])
    db.session.commit()
    return jsonify({"success": True, "event": event.to_dict()})


@timeline_enhanced_bp.route("/api/timeline_enhanced/stats", methods=["GET"])
@jwt_required()
def timeline_stats():
    events   = TeEvent.query.all()
    clusters = TeCluster.query.filter_by(status="active").all()

    by_module   = {}
    by_severity = {}
    for e in events:
        by_module[e.source_module]   = by_module.get(e.source_module, 0) + 1
        by_severity[e.severity]      = by_severity.get(e.severity, 0) + 1

    return jsonify({
        "total_events":     len(events),
        "total_clusters":   len(clusters),
        "correlated_events":sum(1 for e in events if e.correlated),
        "critical_events":  sum(1 for e in events if e.severity=="Critical"),
        "unresolved":       sum(1 for e in events if not e.resolved),
        "modules_covered":  len(by_module),
        "by_module":        by_module,
        "by_severity":      by_severity,
    })
