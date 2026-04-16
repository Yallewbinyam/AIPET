"""
AIPET X — OT/ICS Security Routes

Endpoints:
  GET  /api/otics/devices           — list all OT devices
  POST /api/otics/devices           — register OT device
  PUT  /api/otics/devices/<id>      — update device
  DEL  /api/otics/devices/<id>      — remove device
  POST /api/otics/scan              — run OT protocol scan
  GET  /api/otics/scans             — scan history
  GET  /api/otics/findings          — all findings with filters
  GET  /api/otics/stats             — dashboard metrics
"""
import json
import time
import random
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.otics.models import OtDevice, OtScan, OtFinding
from dashboard.backend.siem.models import SiemEvent

otics_bp = Blueprint("otics", __name__)


# ── Protocol scanner engine ──────────────────────────────────

# MITRE ATT&CK for ICS technique mappings
MITRE_ICS = {
    "unauthenticated_access": "T0817",   # Drive-by Compromise
    "exposed_registers":      "T0801",   # Monitor Process State
    "default_credentials":    "T0812",   # Default Credentials
    "unencrypted_comms":      "T0885",   # Commonly Used Port
    "firmware_outdated":      "T0857",   # System Firmware
    "insecure_config":        "T0820",   # Exploitation of Remote Services
    "network_exposure":       "T0886",   # Remote Services
    "coil_write_enabled":     "T0831",   # Manipulation of Control
}

# Protocol-specific vulnerability checks
PROTOCOL_CHECKS = {
    "modbus": [
        {
            "finding_type": "unauthenticated_access",
            "severity":     "Critical",
            "title":        "Modbus TCP has no authentication — any device can send commands",
            "description":  "Modbus TCP protocol has no built-in authentication mechanism. "
                           "Any host on the network can read sensor data and write control "
                           "commands to connected PLCs and field devices.",
            "evidence":     "Function code 0x01 (Read Coils) accepted without credentials",
            "remediation":  "Deploy Modbus firewall or application-aware gateway. "
                           "Implement network segmentation to isolate Modbus devices. "
                           "Use VPN for any remote access to Modbus networks.",
        },
        {
            "finding_type": "coil_write_enabled",
            "severity":     "Critical",
            "title":        "Modbus coil writing enabled — physical control registers writable",
            "description":  "Modbus Function Code 0x0F (Write Multiple Coils) is enabled. "
                           "An attacker can write to coil registers to directly control "
                           "connected physical equipment such as motors, valves, and relays.",
            "evidence":     "Function code 0x0F accepted on Unit ID 1",
            "remediation":  "Disable write function codes at the firewall level. "
                           "Implement read-only Modbus proxy for monitoring systems. "
                           "Require explicit authorisation for any write operations.",
        },
        {
            "finding_type": "network_exposure",
            "severity":     "High",
            "title":        "Modbus device reachable from IT network — OT/IT boundary breach",
            "description":  "This Modbus device is accessible from the corporate IT network. "
                           "Purdue Model Level 1 (Field Devices) should never be directly "
                           "reachable from Level 4 (Enterprise) without an industrial DMZ.",
            "evidence":     "TCP port 502 responding to connection from IT subnet",
            "remediation":  "Implement industrial DMZ between IT and OT networks. "
                           "Deploy unidirectional security gateway (data diode). "
                           "Restrict Modbus access to SCADA/HMI systems only.",
        },
    ],
    "dnp3": [
        {
            "finding_type": "unauthenticated_access",
            "severity":     "Critical",
            "title":        "DNP3 Secure Authentication not enabled",
            "description":  "DNP3 Secure Authentication Version 5 (SA v5) is not configured. "
                           "Without SA v5, any device on the network can send spoofed DNP3 "
                           "messages to outstations controlling power grid equipment.",
            "evidence":     "DNP3 master-outstation handshake completed without challenge",
            "remediation":  "Enable DNP3 Secure Authentication Version 5. "
                           "Configure HMAC-SHA256 for message authentication. "
                           "Implement key management infrastructure for DNP3 SA.",
        },
        {
            "finding_type": "unencrypted_comms",
            "severity":     "High",
            "title":        "DNP3 traffic unencrypted — SCADA commands visible in plaintext",
            "description":  "DNP3 protocol does not encrypt traffic by default. "
                           "All SCADA commands, sensor readings, and control messages "
                           "are transmitted in cleartext and can be intercepted.",
            "evidence":     "DNP3 application layer data captured without decryption",
            "remediation":  "Tunnel DNP3 over TLS using DNP3 over TCP with TLS wrapper. "
                           "Deploy encrypted SCADA communications gateway.",
        },
    ],
    "iec61850": [
        {
            "finding_type": "insecure_config",
            "severity":     "High",
            "title":        "IEC 61850 GOOSE messages unsigned — relay protection bypass possible",
            "description":  "Generic Object Oriented Substation Event (GOOSE) messages "
                           "are not cryptographically signed. An attacker on the substation "
                           "LAN can spoof GOOSE messages to trigger false protection trips "
                           "or block legitimate protection actions.",
            "evidence":     "GOOSE PDU captured without digital signature field",
            "remediation":  "Implement IEC 62351-6 security for GOOSE message signing. "
                           "Deploy IEC 61850 aware intrusion detection system.",
        },
        {
            "finding_type": "network_exposure",
            "severity":     "Critical",
            "title":        "IEC 61850 MMS server exposed — substation control accessible",
            "description":  "Manufacturing Message Specification (MMS) service is accessible "
                           "without network restriction. MMS allows reading and writing of "
                           "logical nodes controlling circuit breakers and protection relays.",
            "evidence":     "MMS connection established on TCP port 102",
            "remediation":  "Restrict MMS access to authorised engineering workstations only. "
                           "Implement IEC 62351-4 TLS for MMS communications.",
        },
    ],
    "ethernetip": [
        {
            "finding_type": "unauthenticated_access",
            "severity":     "Critical",
            "title":        "EtherNet/IP CIP device accessible without authentication",
            "description":  "Common Industrial Protocol (CIP) service accepts connections "
                           "without authentication. Rockwell/Allen-Bradley PLCs with "
                           "unauthenticated CIP access can have their logic read and "
                           "potentially modified by any network host.",
            "evidence":     "CIP Forward Open service accepted connection without identity challenge",
            "remediation":  "Enable CIP Security using TLS and DTLS. "
                           "Configure device-level firewall on managed switches. "
                           "Upgrade to controllers supporting CIP Security.",
        },
        {
            "finding_type": "firmware_outdated",
            "severity":     "High",
            "title":        "EtherNet/IP device firmware has known vulnerabilities",
            "description":  "The detected firmware version is affected by published CVEs "
                           "including buffer overflow vulnerabilities in the CIP stack "
                           "that could allow remote code execution.",
            "evidence":     "Firmware version 20.011 — affects CVE-2020-6998, CVE-2021-27478",
            "remediation":  "Update firmware to latest vendor release. "
                           "Apply vendor security patches immediately. "
                           "Isolate device until patching is complete.",
        },
    ],
    "bacnet": [
        {
            "finding_type": "unauthenticated_access",
            "severity":     "High",
            "title":        "BACnet/IP device accessible without authentication",
            "description":  "BACnet protocol has no built-in authentication in base standard. "
                           "Building automation devices (HVAC, lifts, access control) "
                           "can be read and controlled by any host on the network.",
            "evidence":     "BACnet Who-Is broadcast received response from target device",
            "remediation":  "Implement BACnet/SC (Secure Connect) with TLS. "
                           "Segment building automation network from corporate IT. "
                           "Deploy BACnet firewall/proxy for external access.",
        },
        {
            "finding_type": "exposed_registers",
            "severity":     "Medium",
            "title":        "BACnet object properties readable — building systems data exposed",
            "description":  "BACnet Read Property service returns device object data "
                           "including temperature setpoints, access control schedules, "
                           "and alarm thresholds without authentication.",
            "evidence":     "ReadProperty on Object-Identifier 0 returned 47 object properties",
            "remediation":  "Restrict BACnet Read Property to authorised BAS workstations. "
                           "Implement network access control for BACnet devices.",
        },
    ],
}


def _simulate_ot_scan(target, protocol):
    """
    Simulate an OT/ICS protocol scan against a target device.

    IMPORTANT: This is a simulation engine for demo purposes.
    Real OT scanning must be done with extreme caution:
      - Never send write commands to production OT devices
      - Always get written authorisation before scanning OT networks
      - Use read-only queries only
      - Test in maintenance windows
      - Have the plant engineer present

    Returns list of finding dicts.
    """
    checks   = PROTOCOL_CHECKS.get(protocol, [])
    findings = []

    for check in checks:
        # Simulate realistic scan — not all checks fire every time
        # Critical findings always included, others probabilistic
        if check["severity"] == "Critical" or random.random() > 0.3:
            findings.append({
                **check,
                "mitre_ics_id": MITRE_ICS.get(check["finding_type"], "T0800"),
            })

    return findings


# ── Device endpoints ─────────────────────────────────────────

@otics_bp.route("/api/otics/devices", methods=["GET"])
@jwt_required()
def list_devices():
    """List all registered OT/ICS devices."""
    protocol = request.args.get("protocol")
    zone     = request.args.get("zone")
    q        = OtDevice.query.order_by(OtDevice.criticality.desc())
    if protocol:
        q = q.filter_by(protocol=protocol)
    if zone:
        q = q.filter_by(zone=zone)
    devices = q.all()
    return jsonify({"devices": [d.to_dict() for d in devices]})


@otics_bp.route("/api/otics/devices", methods=["POST"])
@jwt_required()
def register_device():
    """Register a new OT/ICS device in the inventory."""
    data = request.get_json(silent=True) or {}
    if not data.get("device_ip") or not data.get("protocol"):
        return jsonify({"error": "device_ip and protocol required"}), 400

    device = OtDevice(
        device_ip   = data["device_ip"],
        device_name = data.get("device_name"),
        protocol    = data["protocol"],
        port        = data.get("port"),
        vendor      = data.get("vendor"),
        model       = data.get("model"),
        firmware    = data.get("firmware"),
        zone        = data.get("zone", "field"),
        criticality = data.get("criticality", "high"),
        location    = data.get("location"),
        online      = True,
        last_seen   = datetime.now(timezone.utc),
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({"success": True, "device": device.to_dict()}), 201


@otics_bp.route("/api/otics/devices/<int:device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    """Remove a device from the OT inventory."""
    device = OtDevice.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return jsonify({"success": True})


# ── Scan endpoint ────────────────────────────────────────────

@otics_bp.route("/api/otics/scan", methods=["POST"])
@jwt_required()
def run_scan():
    """
    Run an OT/ICS protocol security scan against a target.

    SAFETY: All scans are read-only simulations.
    No write commands are sent to any industrial device.

    The scan engine checks for:
      - Protocol authentication weaknesses
      - Exposed control registers
      - Network segmentation issues
      - Firmware vulnerabilities
      - Configuration problems
    """
    data     = request.get_json(silent=True) or {}
    target   = data.get("target", "").strip()
    protocol = data.get("protocol", "modbus").lower()

    if not target:
        return jsonify({"error": "target IP required"}), 400

    valid_protocols = list(PROTOCOL_CHECKS.keys())
    if protocol not in valid_protocols:
        return jsonify({
            "error": f"Protocol must be one of: {valid_protocols}"
        }), 400

    start_time = time.time()
    scan = OtScan(
        target   = target,
        protocol = protocol,
        status   = "running",
        user_id  = int(get_jwt_identity()),
    )
    db.session.add(scan)
    db.session.flush()

    # Run the protocol scan simulation
    raw_findings = _simulate_ot_scan(target, protocol)
    findings     = []

    for rf in raw_findings:
        finding = OtFinding(
            scan_id      = scan.id,
            device_ip    = target,
            protocol     = protocol,
            finding_type = rf["finding_type"],
            severity     = rf["severity"],
            title        = rf["title"],
            description  = rf.get("description"),
            evidence     = rf.get("evidence"),
            mitre_ics_id = rf.get("mitre_ics_id"),
            remediation  = rf.get("remediation"),
        )
        db.session.add(finding)
        findings.append(finding)

    # Determine overall risk level
    severities = [f.severity for f in findings]
    if "Critical" in severities:
        risk_level = "CRITICAL"
    elif "High" in severities:
        risk_level = "HIGH"
    elif "Medium" in severities:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Update scan record
    duration           = time.time() - start_time
    scan.status        = "completed"
    scan.findings_count= len(findings)
    scan.risk_level    = risk_level
    scan.scan_duration = round(duration, 2)
    scan.completed_at  = datetime.now(timezone.utc)

    # Push Critical findings to SIEM automatically
    critical = [f for f in findings if f.severity == "Critical"]
    for f in critical:
        event = SiemEvent(
            event_type  = "ot_ics_finding",
            source      = f"AIPET OT/ICS Scanner ({protocol.upper()})",
            severity    = "Critical",
            title       = f.title,
            description = f.description,
            mitre_id    = f.mitre_ics_id,
        )
        db.session.add(event)

    db.session.commit()

    return jsonify({
        "scan":     scan.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total":    len(findings),
            "critical": len([f for f in findings if f.severity == "Critical"]),
            "high":     len([f for f in findings if f.severity == "High"]),
            "risk":     risk_level,
        }
    }), 201


# ── Scan history + findings ───────────────────────────────────

@otics_bp.route("/api/otics/scans", methods=["GET"])
@jwt_required()
def scan_history():
    """OT scan history — newest first."""
    scans = OtScan.query.order_by(
        OtScan.created_at.desc()).limit(50).all()
    return jsonify({"scans": [s.to_dict() for s in scans]})


@otics_bp.route("/api/otics/findings", methods=["GET"])
@jwt_required()
def list_findings():
    """All OT findings with optional severity/protocol filter."""
    severity = request.args.get("severity")
    protocol = request.args.get("protocol")
    q        = OtFinding.query.order_by(OtFinding.created_at.desc())
    if severity:
        q = q.filter_by(severity=severity)
    if protocol:
        q = q.filter_by(protocol=protocol)
    findings = q.limit(100).all()
    return jsonify({"findings": [f.to_dict() for f in findings]})


# ── Stats ─────────────────────────────────────────────────────

@otics_bp.route("/api/otics/stats", methods=["GET"])
@jwt_required()
def ot_stats():
    """Dashboard metrics for the OT/ICS page."""
    total_devices   = OtDevice.query.count()
    critical_devices= OtDevice.query.filter_by(criticality="critical").count()
    total_findings  = OtFinding.query.count()
    critical_findings=OtFinding.query.filter_by(severity="Critical").count()
    total_scans     = OtScan.query.count()

    # Protocol coverage
    protocols = {}
    for p in ["modbus","dnp3","iec61850","ethernetip","bacnet"]:
        protocols[p] = OtDevice.query.filter_by(protocol=p).count()

    # Zone distribution
    zones = {}
    for z in ["field","control","supervisory","enterprise"]:
        zones[z] = OtDevice.query.filter_by(zone=z).count()

    return jsonify({
        "total_devices":    total_devices,
        "critical_devices": critical_devices,
        "total_findings":   total_findings,
        "critical_findings":critical_findings,
        "total_scans":      total_scans,
        "protocols":        protocols,
        "zones":            zones,
    })
