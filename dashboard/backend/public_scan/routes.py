from flask import Blueprint, jsonify, request
from datetime import datetime
import socket
import re

public_scan_bp = Blueprint('public_scan', __name__)
scan_cache = {}

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 1883, 5683, 502, 8080, 161]

PORT_VULNS = {
    21:   {"name": "FTP Exposed",        "severity": "high",     "mitre": "T1021.002", "fix": "Disable FTP, use SFTP instead"},
    22:   {"name": "SSH Exposed",         "severity": "medium",   "mitre": "T1021.004", "fix": "Restrict SSH with firewall rules"},
    23:   {"name": "Telnet Exposed",      "severity": "critical", "mitre": "T1021.004", "fix": "Disable Telnet immediately"},
    80:   {"name": "HTTP Exposed",        "severity": "medium",   "mitre": "T1190",     "fix": "Enable HTTPS, disable HTTP"},
    443:  {"name": "HTTPS Open",          "severity": "low",      "mitre": "T1190",     "fix": "Ensure TLS certificate is valid"},
    1883: {"name": "MQTT Unencrypted",    "severity": "critical", "mitre": "T1040",     "fix": "Enable MQTT TLS on port 8883"},
    5683: {"name": "CoAP Exposed",        "severity": "high",     "mitre": "T1046",     "fix": "Restrict CoAP to internal network"},
    502:  {"name": "Modbus TCP Exposed",  "severity": "critical", "mitre": "T1046",     "fix": "Isolate on separate VLAN"},
    8080: {"name": "HTTP Alt Exposed",    "severity": "medium",   "mitre": "T1190",     "fix": "Restrict with firewall rules"},
    161:  {"name": "SNMP Exposed",        "severity": "high",     "mitre": "T1046",     "fix": "Use SNMPv3 with authentication"},
}

def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports

def calculate_risk(findings):
    score = 0
    for f in findings:
        if f["severity"] == "critical": score += 30
        elif f["severity"] == "high": score += 20
        elif f["severity"] == "medium": score += 10
        else: score += 5
    return min(score, 100)

@public_scan_bp.route('/api/public/scan', methods=['POST'])
def public_scan():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target IP required'}), 400
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        return jsonify({'error': 'Invalid IP address'}), 400
    now = datetime.now().timestamp()
    if client_ip in scan_cache and now - scan_cache[client_ip] < 60:
        return jsonify({'error': 'Rate limit: 1 scan per minute. Sign up for unlimited scans.'}), 429
    scan_cache[client_ip] = now
    open_ports = scan_ports(target, COMMON_PORTS)
    findings = []
    for port in open_ports:
        if port in PORT_VULNS:
            findings.append({"port": port, **PORT_VULNS[port]})
    risk_score = calculate_risk(findings)
    if 502 in open_ports or 5683 in open_ports:
        device_type, device_icon = "Industrial/IoT Device", "⚙️"
    elif 1883 in open_ports:
        device_type, device_icon = "IoT Sensor/Broker", "📡"
    elif 80 in open_ports or 443 in open_ports:
        device_type, device_icon = "Web Server/Router", "🔀"
    else:
        device_type, device_icon = "Network Device", "🖥️"
    return jsonify({
        "target": target,
        "device_type": device_type,
        "device_icon": device_icon,
        "open_ports": open_ports,
        "findings": findings[:3],
        "total_findings": len(findings),
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW",
        "scanned_at": datetime.now().isoformat(),
        "limited": True,
    })
