from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
import random

from ..models import db, User, ProtocolScan

protocols_bp = Blueprint('protocols', __name__, url_prefix='/api/protocols')

# =============================================================
# Protocol vulnerability definitions
# =============================================================

ZIGBEE_VULNS = [
    {"id": "ZB-001", "title": "Unencrypted network key",        "severity": "critical", "description": "Network key transmitted in plaintext during join procedure."},
    {"id": "ZB-002", "title": "Default trust centre key",       "severity": "high",     "description": "Device using default Zigbee trust centre link key."},
    {"id": "ZB-003", "title": "Rogue device detected",          "severity": "high",     "description": "Unauthorised device joined the Zigbee network."},
    {"id": "ZB-004", "title": "Replay attack vulnerability",    "severity": "medium",   "description": "No frame counter validation — replay attacks possible."},
    {"id": "ZB-005", "title": "Insecure OTA update",            "severity": "medium",   "description": "Over-the-air firmware update lacks signature verification."},
    {"id": "ZB-006", "title": "Weak network key rotation",      "severity": "low",      "description": "Network key has not been rotated in over 90 days."},
]

LORAWAN_VULNS = [
    {"id": "LW-001", "title": "Hardcoded AppKey detected",      "severity": "critical", "description": "Application key is hardcoded and matches known default values."},
    {"id": "LW-002", "title": "ABP activation vulnerability",   "severity": "high",     "description": "Device uses ABP activation — frame counter reset on reboot enables replay."},
    {"id": "LW-003", "title": "Weak DevEUI entropy",            "severity": "high",     "description": "Device EUI has insufficient entropy — predictable device identity."},
    {"id": "LW-004", "title": "Unconfirmed uplinks only",       "severity": "medium",   "description": "Device sends only unconfirmed uplinks — no delivery guarantee or tampering detection."},
    {"id": "LW-005", "title": "ADR manipulation risk",          "severity": "medium",   "description": "Adaptive Data Rate can be manipulated to drain device battery."},
    {"id": "LW-006", "title": "Missing MAC layer encryption",   "severity": "low",      "description": "MAC commands transmitted without encryption on some channels."},
]

MODBUS_VULNS = [
    {"id": "MB-001", "title": "No authentication required",     "severity": "critical", "description": "Modbus TCP endpoint accepts commands from any source without authentication."},
    {"id": "MB-002", "title": "Coil write access exposed",      "severity": "critical", "description": "Write access to output coils allows direct control of physical devices."},
    {"id": "MB-003", "title": "Holding register disclosure",    "severity": "high",     "description": "Holding registers expose sensitive process values without access control."},
    {"id": "MB-004", "title": "No TLS encryption",              "severity": "high",     "description": "Modbus TCP traffic transmitted in plaintext — susceptible to MITM."},
    {"id": "MB-005", "title": "Function code abuse",            "severity": "medium",   "description": "Unrestricted function codes allow device identification and enumeration."},
    {"id": "MB-006", "title": "No rate limiting",               "severity": "low",      "description": "No rate limiting on Modbus requests — DoS attacks possible."},
]

PROTOCOL_VULNS = {
    "zigbee":  ZIGBEE_VULNS,
    "lorawan": LORAWAN_VULNS,
    "modbus":  MODBUS_VULNS,
}

PROTOCOL_PORTS = {
    "zigbee":  None,
    "lorawan": 1700,
    "modbus":  502,
}

def simulate_scan(protocol, target):
    vulns = PROTOCOL_VULNS[protocol]
    num_vulns = random.randint(2, len(vulns))
    selected = random.sample(vulns, num_vulns)
    
    severities = [v["severity"] for v in selected]
    if "critical" in severities:
        risk = "critical"
    elif "high" in severities:
        risk = "high"
    elif "medium" in severities:
        risk = "medium"
    else:
        risk = "low"

    devices = []
    num_devices = random.randint(1, 8)
    for i in range(num_devices):
        devices.append({
            "id":       f"{protocol.upper()}-{random.randint(1000,9999)}",
            "address":  f"{target}.{random.randint(1,254)}" if protocol != "zigbee" else f"0x{random.randint(0,65535):04X}",
            "type":     random.choice(["sensor", "actuator", "gateway", "controller"]),
            "rssi":     random.randint(-90, -40) if protocol in ["zigbee", "lorawan"] else None,
        })

    return {
        "findings":     selected,
        "devices":      devices,
        "device_count": num_devices,
        "risk_level":   risk,
    }


# =============================================================
# Routes
# =============================================================

@protocols_bp.route('/scan', methods=['POST'])
@jwt_required()
def start_scan():
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.plan == 'free':
        return jsonify({'error': 'Protocol scanning requires Professional or Enterprise plan'}), 403

    data     = request.get_json()
    protocol = data.get('protocol', '').lower()
    target   = data.get('target', '').strip()

    if protocol not in PROTOCOL_VULNS:
        return jsonify({'error': 'Invalid protocol. Use: zigbee, lorawan, modbus'}), 400

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    result = simulate_scan(protocol, target)

    scan = ProtocolScan(
        user_id      = int(user_id),
        protocol     = protocol,
        target       = target,
        status       = "completed",
        findings     = result["findings"],
        device_count = result["device_count"],
        risk_level   = result["risk_level"],
        completed_at = datetime.now(timezone.utc),
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "id":           scan.id,
        "protocol":     protocol.upper(),
        "target":       target,
        "device_count": result["device_count"],
        "devices":      result["devices"],
        "risk_level":   result["risk_level"],
        "findings":     result["findings"],
        "created_at":   str(scan.created_at),
    }), 200


@protocols_bp.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    scans   = ProtocolScan.query.filter_by(
        user_id=int(user_id)
    ).order_by(ProtocolScan.created_at.desc()).limit(20).all()

    return jsonify([s.to_dict() for s in scans]), 200
