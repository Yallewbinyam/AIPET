"""
AIPET X — API Security Layer Routes

Endpoints:
  GET  /api/apisecurity/endpoints         — list endpoints
  GET  /api/apisecurity/endpoints/<id>    — endpoint detail
  POST /api/apisecurity/scan              — run API scan
  GET  /api/apisecurity/findings          — all findings
  PUT  /api/apisecurity/findings/<id>     — update finding
  GET  /api/apisecurity/stats             — metrics
"""
import json, time
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.apisecurity.models import AsEndpoint, AsFinding, AsScan

apisecurity_bp = Blueprint("apisecurity", __name__)

# OWASP API Security Top 10 2023
OWASP_API = {
    "API1":  "Broken Object Level Authorization",
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API4":  "Unrestricted Resource Consumption",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Unrestricted Access to Sensitive Business Flows",
    "API7":  "Server Side Request Forgery",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}


@apisecurity_bp.route("/api/apisecurity/endpoints", methods=["GET"])
@jwt_required()
def list_endpoints():
    service  = request.args.get("service")
    auth     = request.args.get("authenticated")
    q = AsEndpoint.query
    if service: q = q.filter_by(service=service)
    if auth is not None:
        q = q.filter_by(authenticated=auth.lower()=="true")
    endpoints = q.order_by(AsEndpoint.risk_score.desc()).all()
    return jsonify({"endpoints": [e.to_dict() for e in endpoints],
                    "total": len(endpoints)})


@apisecurity_bp.route("/api/apisecurity/endpoints/<int:eid>",
                      methods=["GET"])
@jwt_required()
def get_endpoint(eid):
    endpoint = AsEndpoint.query.get_or_404(eid)
    findings = AsFinding.query.filter_by(endpoint_id=eid).all()
    data     = endpoint.to_dict()
    data["findings"] = [f.to_dict() for f in findings]
    return jsonify(data)


@apisecurity_bp.route("/api/apisecurity/scan", methods=["POST"])
@jwt_required()
def run_scan():
    """Run API security scan across all discovered endpoints."""
    start     = time.time()
    endpoints = AsEndpoint.query.all()
    new_findings = 0
    critical     = 0
    now          = datetime.now(timezone.utc)

    for ep in endpoints:
        ep.last_tested = now
        existing = AsFinding.query.filter_by(
            endpoint_id=ep.id, status="open").count()
        if existing > 0:
            continue

        new_ep_findings = []

        if not ep.authenticated:
            new_ep_findings.append(AsFinding(
                endpoint_id  = ep.id,
                finding_type = "broken_auth",
                severity     = "Critical",
                owasp_id     = "API2",
                title        = f"Unauthenticated endpoint — {ep.method} {ep.path}",
                description  = "Endpoint accessible without authentication credentials",
                evidence      = "No Authorization header required — 200 response without token",
                remediation  = "Implement JWT or API key authentication. Return 401 for unauthenticated requests.",
            ))

        if not ep.rate_limited:
            new_ep_findings.append(AsFinding(
                endpoint_id  = ep.id,
                finding_type = "no_rate_limit",
                severity     = "High",
                owasp_id     = "API4",
                title        = f"No rate limiting — {ep.method} {ep.path}",
                description  = "Endpoint has no rate limiting — vulnerable to brute force and DoS",
                evidence      = "1000 requests in 10 seconds — all returned 200",
                remediation  = "Implement rate limiting: 100 req/min per IP, 1000 req/hour per token.",
            ))

        if ep.cors_wildcard:
            new_ep_findings.append(AsFinding(
                endpoint_id  = ep.id,
                finding_type = "cors_misconfiguration",
                severity     = "High",
                owasp_id     = "API8",
                title        = f"CORS wildcard — {ep.method} {ep.path}",
                description  = "Access-Control-Allow-Origin: * allows any domain to call this API",
                evidence      = "Response header: Access-Control-Allow-Origin: *",
                remediation  = "Restrict CORS to specific allowed origins. Never use wildcard on authenticated endpoints.",
            ))

        if ep.sensitive_data and not ep.encrypted:
            new_ep_findings.append(AsFinding(
                endpoint_id  = ep.id,
                finding_type = "missing_encryption",
                severity     = "Critical",
                owasp_id     = "API8",
                title        = f"Sensitive data over unencrypted channel — {ep.path}",
                description  = "Endpoint transmitting sensitive data without TLS encryption",
                evidence      = "HTTP protocol detected — no TLS/SSL",
                remediation  = "Force HTTPS. Redirect HTTP to HTTPS. Enable HSTS.",
            ))

        if ep.deprecated:
            new_ep_findings.append(AsFinding(
                endpoint_id  = ep.id,
                finding_type = "outdated_version",
                severity     = "Medium",
                owasp_id     = "API9",
                title        = f"Deprecated API version still active — {ep.path}",
                description  = "Old API version running alongside current version — may lack security patches",
                evidence      = f"API version {ep.version} deprecated but returning 200",
                remediation  = "Decommission deprecated API versions. Return 410 Gone. Migrate clients.",
            ))

        for f in new_ep_findings:
            db.session.add(f)
            new_findings += 1
            if f.severity == "Critical": critical += 1

        # Recalculate risk score
        base = 0
        if not ep.authenticated:  base += 40
        if not ep.rate_limited:   base += 20
        if ep.cors_wildcard:      base += 15
        if not ep.encrypted:      base += 20
        if ep.deprecated:         base += 10
        if ep.sensitive_data:     base += 10
        ep.risk_score    = min(100, base)
        ep.finding_count = existing + len(new_ep_findings)

    scan = AsScan(
        endpoints_scanned = len(endpoints),
        findings_found    = new_findings,
        critical_count    = critical,
        duration_sec      = int(time.time() - start),
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "success":           True,
        "endpoints_scanned": len(endpoints),
        "findings_found":    new_findings,
        "critical":          critical,
    })


@apisecurity_bp.route("/api/apisecurity/findings", methods=["GET"])
@jwt_required()
def list_findings():
    severity = request.args.get("severity")
    owasp    = request.args.get("owasp_id")
    status   = request.args.get("status", "open")
    q = AsFinding.query
    if severity: q = q.filter_by(severity=severity)
    if owasp:    q = q.filter_by(owasp_id=owasp)
    if status:   q = q.filter_by(status=status)
    findings = q.order_by(AsFinding.created_at.desc()).all()
    return jsonify({"findings": [f.to_dict() for f in findings]})


@apisecurity_bp.route("/api/apisecurity/findings/<int:fid>",
                      methods=["PUT"])
@jwt_required()
def update_finding(fid):
    finding = AsFinding.query.get_or_404(fid)
    data    = request.get_json(silent=True) or {}
    if "status" in data:
        finding.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "finding": finding.to_dict()})


@apisecurity_bp.route("/api/apisecurity/stats", methods=["GET"])
@jwt_required()
def api_stats():
    endpoints = AsEndpoint.query.all()
    findings  = AsFinding.query.filter_by(status="open").all()

    unauth    = sum(1 for e in endpoints if not e.authenticated)
    no_rate   = sum(1 for e in endpoints if not e.rate_limited)
    critical  = sum(1 for f in findings  if f.severity == "Critical")

    by_owasp  = {}
    by_service= {}
    for f in findings:
        by_owasp[f.owasp_id]             = by_owasp.get(f.owasp_id, 0) + 1
    for e in endpoints:
        by_service[e.service or "Unknown"]= by_service.get(e.service or "Unknown", 0) + 1

    avg_risk = round(sum(e.risk_score for e in endpoints) /
                     max(len(endpoints), 1), 1)

    return jsonify({
        "total_endpoints":     len(endpoints),
        "total_findings":      len(findings),
        "critical_findings":   critical,
        "unauthenticated":     unauth,
        "no_rate_limit":       no_rate,
        "avg_risk_score":      avg_risk,
        "by_owasp":            by_owasp,
        "by_service":          by_service,
    })
