"""
AIPET X — DSPM-Lite Routes

Endpoints:
  GET  /api/dspm/datastores        — list all datastores
  GET  /api/dspm/datastores/<id>   — datastore detail + findings
  POST /api/dspm/scan              — run DSPM scan
  GET  /api/dspm/findings          — all findings
  PUT  /api/dspm/findings/<id>     — update finding status
  GET  /api/dspm/stats             — DSPM metrics
"""
import json, time, random
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.dspm.models import DspmDatastore, DspmFinding, DspmScan

dspm_bp = Blueprint("dspm", __name__)

SENSITIVITY_SCORE = {
    "public": 10, "internal": 30,
    "confidential": 60, "restricted": 80, "secret": 100
}

DATA_TYPES = {
    "PII":  { "label": "Personal Identifiable Information", "reg": "GDPR, NIS2"         },
    "PHI":  { "label": "Protected Health Information",      "reg": "HIPAA, DSPT"         },
    "PCI":  { "label": "Payment Card Data",                 "reg": "PCI-DSS"             },
    "OT":   { "label": "Operational Technology Data",       "reg": "NIS2, IEC 62443"     },
    "CRED": { "label": "Credentials/Secrets",               "reg": "ISO 27001, SOC 2"    },
    "IP":   { "label": "Intellectual Property",             "reg": "ISO 27001"           },
    "LOG":  { "label": "Security Logs",                     "reg": "NIS2, SOC 2"         },
    "CFG":  { "label": "Configuration Data",                "reg": "ISO 27001"           },
}


def _calculate_risk(store):
    """Calculate composite risk score for a datastore."""
    score = SENSITIVITY_SCORE.get(store.sensitivity, 30)
    if store.publicly_accessible:  score = min(100, score + 40)
    if not store.encrypted_at_rest: score = min(100, score + 20)
    if not store.encrypted_in_transit: score = min(100, score + 15)
    if store.access_control == "none": score = min(100, score + 25)
    return score


@dspm_bp.route("/api/dspm/datastores", methods=["GET"])
@jwt_required()
def list_datastores():
    sensitivity = request.args.get("sensitivity")
    store_type  = request.args.get("store_type")
    q = DspmDatastore.query
    if sensitivity: q = q.filter_by(sensitivity=sensitivity)
    if store_type:  q = q.filter_by(store_type=store_type)
    stores = q.order_by(DspmDatastore.risk_score.desc()).all()
    return jsonify({"datastores": [s.to_dict() for s in stores],
                    "total": len(stores)})


@dspm_bp.route("/api/dspm/datastores/<int:sid>", methods=["GET"])
@jwt_required()
def get_datastore(sid):
    store    = DspmDatastore.query.get_or_404(sid)
    findings = DspmFinding.query.filter_by(datastore_id=sid).all()
    data     = store.to_dict()
    data["findings"] = [f.to_dict() for f in findings]
    return jsonify(data)


@dspm_bp.route("/api/dspm/scan", methods=["POST"])
@jwt_required()
def run_scan():
    """Run DSPM scan — discovers and assesses all datastores."""
    start = time.time()
    stores   = DspmDatastore.query.all()
    findings = 0
    critical = 0

    for store in stores:
        store.risk_score  = _calculate_risk(store)
        store.last_scanned= datetime.now(timezone.utc)

        # Generate findings based on store properties
        existing = DspmFinding.query.filter_by(
            datastore_id=store.id, status="open").count()

        if existing == 0:
            new_findings = []

            if store.publicly_accessible and store.sensitivity in ("confidential","restricted","secret"):
                new_findings.append(DspmFinding(
                    datastore_id = store.id,
                    finding_type = "public_exposure",
                    severity     = "Critical",
                    title        = f"Sensitive data store publicly accessible — {store.name}",
                    description  = f"{store.sensitivity.title()} data exposed to public internet without authentication",
                    remediation  = "Immediately restrict public access. Apply authentication and network controls.",
                    regulation   = "GDPR Art.32, NIS2 Art.21",
                    status       = "open",
                ))

            if not store.encrypted_at_rest and store.sensitivity not in ("public","internal"):
                new_findings.append(DspmFinding(
                    datastore_id = store.id,
                    finding_type = "unencrypted_at_rest",
                    severity     = "High",
                    title        = f"Data not encrypted at rest — {store.name}",
                    description  = f"{store.sensitivity.title()} data stored without encryption",
                    remediation  = "Enable encryption at rest using AES-256. For AWS: enable S3 SSE. For databases: enable TDE.",
                    regulation   = "GDPR Art.32, ISO 27001 A.8.24",
                    status       = "open",
                ))

            if not store.encrypted_in_transit:
                new_findings.append(DspmFinding(
                    datastore_id = store.id,
                    finding_type = "unencrypted_transit",
                    severity     = "High" if store.sensitivity in ("confidential","restricted") else "Medium",
                    title        = f"Data transmitted without encryption — {store.name}",
                    description  = "Data in transit not protected with TLS/SSL",
                    remediation  = "Enforce TLS 1.2+ for all data in transit. Disable unencrypted endpoints.",
                    regulation   = "NIS2 Art.21, PCI-DSS Req.4",
                    status       = "open",
                ))

            if store.access_control == "none":
                new_findings.append(DspmFinding(
                    datastore_id = store.id,
                    finding_type = "no_access_control",
                    severity     = "Critical",
                    title        = f"No access controls on data store — {store.name}",
                    description  = "Data store has no authentication or authorisation controls",
                    remediation  = "Implement RBAC. Require authentication for all access. Apply least-privilege.",
                    regulation   = "ISO 27001 A.8.3, SOC 2 CC6.1",
                    status       = "open",
                ))

            for f in new_findings:
                db.session.add(f)
                findings += 1
                if f.severity == "Critical": critical += 1

            store.finding_count = existing + len(new_findings)

    scan = DspmScan(
        datastores_found = len(stores),
        findings_found   = findings,
        critical_count   = critical,
        duration_sec     = int(time.time() - start),
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "success":          True,
        "datastores_scanned": len(stores),
        "findings_found":   findings,
        "critical":         critical,
        "duration_sec":     scan.duration_sec,
    })


@dspm_bp.route("/api/dspm/findings", methods=["GET"])
@jwt_required()
def list_findings():
    severity = request.args.get("severity")
    status   = request.args.get("status")
    q = DspmFinding.query
    if severity: q = q.filter_by(severity=severity)
    if status:   q = q.filter_by(status=status)
    findings = q.order_by(DspmFinding.created_at.desc()).all()
    return jsonify({"findings": [f.to_dict() for f in findings]})


@dspm_bp.route("/api/dspm/findings/<int:fid>", methods=["PUT"])
@jwt_required()
def update_finding(fid):
    finding = DspmFinding.query.get_or_404(fid)
    data    = request.get_json(silent=True) or {}
    if "status" in data:
        finding.status = data["status"]
    db.session.commit()
    return jsonify({"success": True, "finding": finding.to_dict()})


@dspm_bp.route("/api/dspm/stats", methods=["GET"])
@jwt_required()
def dspm_stats():
    stores   = DspmDatastore.query.all()
    findings = DspmFinding.query.all()

    by_sensitivity = {}
    by_type        = {}
    for s in stores:
        by_sensitivity[s.sensitivity] = by_sensitivity.get(s.sensitivity, 0) + 1
        by_type[s.store_type]         = by_type.get(s.store_type, 0) + 1

    total_records = sum(s.record_count for s in stores)
    unencrypted   = sum(1 for s in stores if not s.encrypted_at_rest)
    public_stores = sum(1 for s in stores if s.publicly_accessible)
    critical_f    = sum(1 for f in findings if f.severity == "Critical" and f.status == "open")

    return jsonify({
        "total_datastores":    len(stores),
        "total_findings":      len([f for f in findings if f.status == "open"]),
        "critical_findings":   critical_f,
        "unencrypted_stores":  unencrypted,
        "public_stores":       public_stores,
        "total_records":       total_records,
        "by_sensitivity":      by_sensitivity,
        "by_type":             by_type,
        "avg_risk":            round(sum(s.risk_score for s in stores) / max(len(stores),1), 1),
    })
