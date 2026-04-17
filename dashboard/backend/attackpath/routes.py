"""
AIPET X — Attack Path Modelling Routes

Endpoints:
  GET  /api/attackpath/analyses          — list analyses
  POST /api/attackpath/analyse           — run analysis
  GET  /api/attackpath/analyses/<id>     — analysis + paths
  DEL  /api/attackpath/analyses/<id>     — delete
  GET  /api/attackpath/stats             — metrics
"""
import json, random
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.attackpath.models import ApAnalysis, ApPath

attackpath_bp = Blueprint("attackpath", __name__)

# Attack techniques by network zone
TECHNIQUES = {
    "initial_access": [
        {"id":"T1190","name":"Exploit Public App",       "severity":"Critical"},
        {"id":"T1078","name":"Default Credentials",      "severity":"Critical"},
        {"id":"T1133","name":"External Remote Services", "severity":"High"},
        {"id":"T1566","name":"Phishing",                 "severity":"High"},
    ],
    "lateral_movement": [
        {"id":"T1021","name":"Remote Services",          "severity":"Critical"},
        {"id":"T1210","name":"Exploit Remote Services",  "severity":"Critical"},
        {"id":"T1550","name":"Use Alternate Auth",       "severity":"High"},
    ],
    "impact": [
        {"id":"T1499","name":"Denial of Service",        "severity":"Critical"},
        {"id":"T1565","name":"Data Manipulation",        "severity":"Critical"},
        {"id":"T1486","name":"Data Encrypted",           "severity":"Critical"},
        {"id":"T1489","name":"Service Stop",             "severity":"High"},
    ],
    "collection": [
        {"id":"T1040","name":"Network Sniffing",         "severity":"High"},
        {"id":"T1530","name":"Cloud Storage Access",     "severity":"High"},
    ],
}

# Network topology zones
ZONES = {
    "internet":    { "devices": ["External Attacker"],              "zone": "internet"    },
    "dmz":         { "devices": ["Web Server","VPN Gateway",
                                  "Email Server"],                    "zone": "dmz"         },
    "corporate":   { "devices": ["Corporate Firewall","DNS Server",
                                  "AD Controller"],                   "zone": "corporate"   },
    "iot":         { "devices": ["IP Camera","Smart Thermostat",
                                  "IoT Gateway","MQTT Broker"],       "zone": "iot"         },
    "operational": { "devices": ["SCADA Server","HMI Terminal",
                                  "Historian Server"],                 "zone": "operational" },
    "field":       { "devices": ["PLC Controller","RTU Device",
                                  "Water Treatment Controller",
                                  "Temperature Sensor"],              "zone": "field"       },
}

CRITICAL_TARGETS = ["PLC Controller","SCADA Server","Water Treatment Controller",
                    "RTU Device","Historian Server"]


def _generate_attack_paths(scope, findings_data):
    """
    Generate realistic attack paths based on network topology
    and current findings. Returns list of path dicts.
    """
    random.seed(42)
    paths = []

    # Entry points — internet-facing and weakly protected devices
    entry_points = [
        {"device": "IP Camera",       "technique": "T1190", "reason": "CVE in web interface"},
        {"device": "VPN Gateway",     "technique": "T1078", "reason": "Default credentials"},
        {"device": "IoT Gateway",     "technique": "T1133", "reason": "Exposed management port"},
        {"device": "Web Server",      "technique": "T1190", "reason": "SQL injection vulnerability"},
        {"device": "MQTT Broker",     "technique": "T1040", "reason": "Unencrypted traffic"},
    ]

    # Define attack chains
    attack_chains = [
        # Chain 1: Camera → Gateway → SCADA → PLC (most dangerous)
        {
            "entry": "IP Camera",
            "chain": [
                {"device":"IP Camera",    "action":"Initial compromise via CVE-2024-1234",
                 "technique":"T1190", "zone":"iot"},
                {"device":"IoT Gateway",  "action":"Lateral movement via default SSH credentials",
                 "technique":"T1021", "zone":"iot"},
                {"device":"SCADA Server", "action":"Pivot to OT network via unpatched Modbus service",
                 "technique":"T1210", "zone":"operational"},
                {"device":"PLC Controller","action":"Direct manipulation of control registers",
                 "technique":"T1565", "zone":"field"},
            ],
            "target": "PLC Controller",
            "impact": "Physical process manipulation — potential equipment damage or safety incident",
            "likelihood": 78,
            "severity": "Critical",
        },
        # Chain 2: VPN → AD → Historian
        {
            "entry": "VPN Gateway",
            "chain": [
                {"device":"VPN Gateway",   "action":"Credential stuffing attack succeeds",
                 "technique":"T1078", "zone":"dmz"},
                {"device":"AD Controller", "action":"Kerberoasting yields domain admin hash",
                 "technique":"T1558", "zone":"corporate"},
                {"device":"Historian Server","action":"Full access to all historical OT data",
                 "technique":"T1530", "zone":"operational"},
            ],
            "target": "Historian Server",
            "impact": "Full access to 5 years of operational data — regulatory breach, IP theft",
            "likelihood": 65,
            "severity": "Critical",
        },
        # Chain 3: MQTT → Water Treatment
        {
            "entry": "MQTT Broker",
            "chain": [
                {"device":"MQTT Broker",   "action":"Unencrypted MQTT traffic captured and injected",
                 "technique":"T1040", "zone":"iot"},
                {"device":"IoT Gateway",   "action":"MQTT broker compromise gives device control",
                 "technique":"T1565", "zone":"iot"},
                {"device":"Water Treatment Controller",
                 "action":"False sensor data injection alters treatment levels",
                 "technique":"T1565", "zone":"field"},
            ],
            "target": "Water Treatment Controller",
            "impact": "Public health risk — chemical dosing manipulation",
            "likelihood": 55,
            "severity": "Critical",
        },
        # Chain 4: IoT → SCADA (shorter)
        {
            "entry": "Smart Thermostat",
            "chain": [
                {"device":"Smart Thermostat", "action":"Firmware vulnerability exploited",
                 "technique":"T1203", "zone":"iot"},
                {"device":"SCADA Server",     "action":"Network pivot via shared segment",
                 "technique":"T1021", "zone":"operational"},
            ],
            "target": "SCADA Server",
            "impact": "SCADA compromise — full operational visibility to attacker",
            "likelihood": 45,
            "severity": "High",
        },
        # Chain 5: Email → AD → HMI
        {
            "entry": "Email Server",
            "chain": [
                {"device":"Email Server", "action":"Spear phishing email delivers malware",
                 "technique":"T1566", "zone":"dmz"},
                {"device":"AD Controller","action":"Credential theft via LSASS dump",
                 "technique":"T1003", "zone":"corporate"},
                {"device":"HMI Terminal", "action":"Remote desktop to HMI with stolen creds",
                 "technique":"T1021", "zone":"operational"},
            ],
            "target": "HMI Terminal",
            "impact": "Human-machine interface control — operator-level access to all OT systems",
            "likelihood": 40,
            "severity": "High",
        },
    ]

    for chain_def in attack_chains:
        path = ApPath(
            entry_point = chain_def["entry"],
            target      = chain_def["target"],
            severity    = chain_def["severity"],
            hops        = len(chain_def["chain"]),
            chain       = json.dumps(chain_def["chain"]),
            techniques  = json.dumps([s["technique"] for s in chain_def["chain"]]),
            likelihood  = chain_def["likelihood"],
            impact      = chain_def["impact"],
            blocked     = chain_def["likelihood"] < 40,
        )
        paths.append(path)

    return paths


@attackpath_bp.route("/api/attackpath/analyses", methods=["GET"])
@jwt_required()
def list_analyses():
    analyses = ApAnalysis.query.order_by(
        ApAnalysis.created_at.desc()).all()
    return jsonify({"analyses": [a.to_dict() for a in analyses]})


@attackpath_bp.route("/api/attackpath/analyse", methods=["POST"])
@jwt_required()
def run_analysis():
    from dashboard.backend.models import Finding
    data  = request.get_json(silent=True) or {}
    name  = data.get("name", f"Attack Path Analysis {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    scope = data.get("scope", "Full Network")

    findings = Finding.query.all()
    findings_data = [{"target": f.target, "severity": f.severity} for f in findings]

    analysis = ApAnalysis(
        name       = name,
        scope      = scope,
        created_by = int(get_jwt_identity()),
    )
    db.session.add(analysis)
    db.session.flush()

    paths = _generate_attack_paths(scope, findings_data)
    for p in paths:
        p.analysis_id = analysis.id
        db.session.add(p)

    analysis.total_paths   = len(paths)
    analysis.critical_paths= sum(1 for p in paths if p.severity=="Critical")
    analysis.max_depth     = max((p.hops for p in paths), default=0)
    db.session.commit()

    return jsonify({
        "success":  True,
        "analysis": analysis.to_dict(),
        "paths":    [p.to_dict() for p in paths],
    }), 201


@attackpath_bp.route("/api/attackpath/analyses/<int:aid>", methods=["GET"])
@jwt_required()
def get_analysis(aid):
    analysis = ApAnalysis.query.get_or_404(aid)
    paths    = ApPath.query.filter_by(analysis_id=aid).order_by(
        ApPath.likelihood.desc()).all()
    data     = analysis.to_dict()
    data["paths"] = [p.to_dict() for p in paths]
    return jsonify(data)


@attackpath_bp.route("/api/attackpath/analyses/<int:aid>",
                     methods=["DELETE"])
@jwt_required()
def delete_analysis(aid):
    analysis = ApAnalysis.query.get_or_404(aid)
    ApPath.query.filter_by(analysis_id=aid).delete()
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({"success": True})


@attackpath_bp.route("/api/attackpath/stats", methods=["GET"])
@jwt_required()
def attackpath_stats():
    analyses = ApAnalysis.query.all()
    all_paths = ApPath.query.all()
    return jsonify({
        "total_analyses":  len(analyses),
        "total_paths":     len(all_paths),
        "critical_paths":  sum(1 for p in all_paths if p.severity=="Critical"),
        "blocked_paths":   sum(1 for p in all_paths if p.blocked),
        "avg_hops":        round(sum(p.hops for p in all_paths)/max(len(all_paths),1), 1),
        "avg_likelihood":  round(sum(p.likelihood for p in all_paths)/max(len(all_paths),1), 1),
    })
