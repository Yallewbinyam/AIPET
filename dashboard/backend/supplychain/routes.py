"""
AIPET X — Supply Chain Security Routes

Endpoints:
  GET  /api/supplychain/components      — list components
  GET  /api/supplychain/components/<id> — component detail
  GET  /api/supplychain/vulns           — all vulnerabilities
  PUT  /api/supplychain/vulns/<id>      — update vuln status
  POST /api/supplychain/scan            — run SBOM scan
  POST /api/supplychain/sbom            — generate SBOM report
  GET  /api/supplychain/sboms           — list SBOM reports
  GET  /api/supplychain/stats           — metrics
"""
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.supplychain.models import ScComponent, ScVuln, ScSbom

supplychain_bp = Blueprint("supplychain", __name__)


@supplychain_bp.route("/api/supplychain/components", methods=["GET"])
@jwt_required()
def list_components():
    risk      = request.args.get("risk_level")
    ecosystem = request.args.get("ecosystem")
    q = ScComponent.query
    if risk:      q = q.filter_by(risk_level=risk)
    if ecosystem: q = q.filter_by(ecosystem=ecosystem)
    components = q.order_by(ScComponent.critical_vulns.desc(),
                            ScComponent.vuln_count.desc()).all()
    return jsonify({"components": [c.to_dict() for c in components],
                    "total": len(components)})


@supplychain_bp.route("/api/supplychain/components/<int:cid>",
                      methods=["GET"])
@jwt_required()
def get_component(cid):
    component = ScComponent.query.get_or_404(cid)
    vulns     = ScVuln.query.filter_by(component_id=cid).all()
    data      = component.to_dict()
    data["vulns"] = [v.to_dict() for v in vulns]
    return jsonify(data)


@supplychain_bp.route("/api/supplychain/vulns", methods=["GET"])
@jwt_required()
def list_vulns():
    severity = request.args.get("severity")
    status   = request.args.get("status", "open")
    kev      = request.args.get("cisa_kev")
    q = ScVuln.query
    if severity: q = q.filter_by(severity=severity)
    if status:   q = q.filter_by(status=status)
    if kev:      q = q.filter_by(cisa_kev=kev.lower()=="true")
    vulns = q.order_by(ScVuln.cvss_score.desc()).all()
    return jsonify({"vulns": [v.to_dict() for v in vulns]})


@supplychain_bp.route("/api/supplychain/vulns/<int:vid>",
                      methods=["PUT"])
@jwt_required()
def update_vuln(vid):
    vuln = ScVuln.query.get_or_404(vid)
    data = request.get_json(silent=True) or {}
    if "status" in data:
        vuln.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "vuln": vuln.to_dict()})


@supplychain_bp.route("/api/supplychain/scan", methods=["POST"])
@jwt_required()
def run_scan():
    """Re-scan all components and update risk levels."""
    components = ScComponent.query.all()
    for comp in components:
        vulns = ScVuln.query.filter_by(
            component_id=comp.id, status="open").all()
        comp.vuln_count    = len(vulns)
        comp.critical_vulns= sum(1 for v in vulns if v.severity=="Critical")
        if comp.critical_vulns > 0:
            comp.risk_level = "critical"
        elif comp.vuln_count > 2:
            comp.risk_level = "high"
        elif comp.vuln_count > 0:
            comp.risk_level = "medium"
        else:
            comp.risk_level = "safe"
        comp.last_updated = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({
        "success":    True,
        "components": len(components),
        "critical":   sum(1 for c in components if c.risk_level=="critical"),
    })


@supplychain_bp.route("/api/supplychain/sbom", methods=["POST"])
@jwt_required()
def generate_sbom():
    """Generate CycloneDX SBOM report."""
    data  = request.get_json(silent=True) or {}
    name  = data.get("name", f"AIPET SBOM {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    components = ScComponent.query.all()
    vulns      = ScVuln.query.filter_by(status="open").all()

    cyclonedx = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "version":     1,
        "metadata": {
            "timestamp": str(datetime.now(timezone.utc)),
            "tools":     [{"vendor":"AIPET","name":"AIPET X Supply Chain Scanner","version":"4.0.0"}],
            "component": {"type":"application","name":"AIPET X Platform","version":"4.0.0"},
        },
        "components": [
            {
                "type":      c.component_type,
                "name":      c.name,
                "version":   c.version,
                "supplier":  c.supplier,
                "licenses":  [{"license":{"id": c.license}}] if c.license else [],
                "purl":      f"pkg:{c.ecosystem}/{c.name}@{c.version}" if c.ecosystem else None,
            }
            for c in components
        ],
        "vulnerabilities": [
            {
                "id":          v.cve_id,
                "source":      {"name":"NVD","url":f"https://nvd.nist.gov/vuln/detail/{v.cve_id}"},
                "ratings":     [{"severity":v.severity.lower(),"score":v.cvss_score}],
                "description": v.description,
                "affects":     [{"ref": ScComponent.query.get(v.component_id).name}],
            }
            for v in vulns
        ],
    }

    sbom = ScSbom(
        name             = name,
        format           = "CycloneDX",
        version          = "1.4",
        components_count = len(components),
        vuln_count       = len(vulns),
        content          = json.dumps(cyclonedx, indent=2),
    )
    db.session.add(sbom)
    db.session.commit()
    return jsonify({
        "success":  True,
        "sbom":     sbom.to_dict(),
        "content":  cyclonedx,
    }), 201


@supplychain_bp.route("/api/supplychain/sboms", methods=["GET"])
@jwt_required()
def list_sboms():
    sboms = ScSbom.query.order_by(ScSbom.created_at.desc()).all()
    return jsonify({"sboms": [s.to_dict() for s in sboms]})


@supplychain_bp.route("/api/supplychain/stats", methods=["GET"])
@jwt_required()
def supply_stats():
    components = ScComponent.query.all()
    vulns      = ScVuln.query.filter_by(status="open").all()

    by_ecosystem = {}
    by_risk      = {}
    license_risks= {}

    for c in components:
        by_ecosystem[c.ecosystem or "unknown"] =             by_ecosystem.get(c.ecosystem or "unknown", 0) + 1
        by_risk[c.risk_level] = by_risk.get(c.risk_level, 0) + 1
        license_risks[c.license_risk] =             license_risks.get(c.license_risk, 0) + 1

    kev_count = sum(1 for v in vulns if v.cisa_kev)
    exploitable= sum(1 for v in vulns if v.exploit_public)

    return jsonify({
        "total_components":  len(components),
        "total_vulns":       len(vulns),
        "critical_components":sum(1 for c in components if c.risk_level=="critical"),
        "kev_vulns":         kev_count,
        "exploitable_vulns": exploitable,
        "direct_deps":       sum(1 for c in components if c.direct_dep),
        "transitive_deps":   sum(1 for c in components if not c.direct_dep),
        "by_ecosystem":      by_ecosystem,
        "by_risk":           by_risk,
        "license_risks":     license_risks,
    })
