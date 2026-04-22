# ============================================================
# AIPET X — Module #45: Cognitive Digital Twin v2
# Device Simulation | Anomaly Detection | Attack Simulation
# Phase 5C | v6.2.0
# ============================================================

import json, uuid, datetime, random
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

digital_twin_v2_bp = Blueprint("digital_twin_v2", __name__)

class DigitalTwinV2Environment(db.Model):
    __tablename__ = "digital_twin_v2_environments"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    name          = Column(String(256))
    env_type      = Column(String(64))
    device_count  = Column(Integer, default=0)
    risk_score    = Column(Float, default=0.0)
    health_score  = Column(Float, default=100.0)
    anomaly_count = Column(Integer, default=0)
    status        = Column(String(32), default="active")
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    devices       = relationship("DigitalTwinV2Device", backref="environment", lazy=True, cascade="all, delete-orphan")
    anomalies     = relationship("DigitalTwinV2Anomaly", backref="environment", lazy=True, cascade="all, delete-orphan")

class DigitalTwinV2Device(db.Model):
    __tablename__ = "digital_twin_v2_devices"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    env_id        = Column(String(64), ForeignKey("digital_twin_v2_environments.id"), nullable=False)
    device_name   = Column(String(256))
    device_type   = Column(String(64))
    ip_address    = Column(String(64))
    status        = Column(String(32), default="online")
    risk_level    = Column(String(16), default="LOW")
    cpu_usage     = Column(Float, default=0.0)
    memory_usage  = Column(Float, default=0.0)
    last_seen     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

class DigitalTwinV2Anomaly(db.Model):
    __tablename__ = "digital_twin_v2_anomalies"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    env_id        = Column(String(64), ForeignKey("digital_twin_v2_environments.id"), nullable=False)
    device_name   = Column(String(256))
    anomaly_type  = Column(String(64))
    severity      = Column(String(16))
    description   = Column(Text)
    recommendation= Column(Text)
    mitre_tactic  = Column(String(128), nullable=True)
    detected_at   = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")

DEVICE_TYPES = {
    "plc": {"label":"PLC / Controller","risk_base":40,"anomalies":["Unexpected firmware change","Unauthorised command injection","Abnormal register writes","Communication protocol anomaly"]},
    "hmi": {"label":"HMI Terminal","risk_base":35,"anomalies":["Unauthorised access attempt","Remote desktop session detected","Configuration change outside maintenance window"]},
    "sensor": {"label":"IoT Sensor","risk_base":20,"anomalies":["Data spike anomaly","Offline beyond threshold","Telemetry flooding detected"]},
    "camera": {"label":"IP Camera","risk_base":30,"anomalies":["Firmware version outdated","Default credentials detected","Unusual outbound connection"]},
    "gateway": {"label":"IoT Gateway","risk_base":35,"anomalies":["New device joined network","Traffic volume anomaly","Unexpected protocol detected"]},
    "server": {"label":"OT Server","risk_base":40,"anomalies":["Unusual process execution","Port scan detected","Lateral movement attempt"]},
    "switch": {"label":"Network Switch","risk_base":25,"anomalies":["MAC flooding detected","VLAN hopping attempt","ARP spoofing detected"]},
    "robot": {"label":"Industrial Robot","risk_base":45,"anomalies":["Movement outside safe zone","Emergency stop triggered","Control system anomaly"]},
}

ANOMALY_MITRE = {
    "Unexpected firmware change": "T1542 — Pre-OS Boot",
    "Unauthorised command injection": "T1059 — Command and Scripting Interpreter",
    "Abnormal register writes": "T1565 — Data Manipulation",
    "Unauthorised access attempt": "T1078 — Valid Accounts",
    "Remote desktop session detected": "T1021.001 — Remote Desktop Protocol",
    "Data spike anomaly": "T1499 — Endpoint Denial of Service",
    "Telemetry flooding detected": "T1498 — Network Denial of Service",
    "Default credentials detected": "T1078.001 — Default Accounts",
    "Unusual outbound connection": "T1041 — Exfiltration Over C2 Channel",
    "New device joined network": "T1200 — Hardware Additions",
    "Traffic volume anomaly": "T1498 — Network Denial of Service",
    "Port scan detected": "T1046 — Network Service Discovery",
    "Lateral movement attempt": "T1021 — Remote Services",
    "MAC flooding detected": "T1557 — Adversary-in-the-Middle",
    "ARP spoofing detected": "T1557.002 — ARP Cache Poisoning",
    "Movement outside safe zone": "T1565 — Data Manipulation",
    "Unusual process execution": "T1055 — Process Injection",
    "Configuration change outside maintenance window": "T1562 — Impair Defenses",
}

ANOMALY_SEV = {
    "Unexpected firmware change": "CRITICAL",
    "Unauthorised command injection": "CRITICAL",
    "Lateral movement attempt": "CRITICAL",
    "ARP spoofing detected": "HIGH",
    "MAC flooding detected": "HIGH",
    "Remote desktop session detected": "HIGH",
    "Unauthorised access attempt": "HIGH",
    "Port scan detected": "HIGH",
    "Default credentials detected": "CRITICAL",
    "Unusual outbound connection": "HIGH",
    "Movement outside safe zone": "CRITICAL",
    "Unusual process execution": "HIGH",
    "Configuration change outside maintenance window": "MEDIUM",
    "New device joined network": "MEDIUM",
    "Traffic volume anomaly": "MEDIUM",
    "Data spike anomaly": "LOW",
    "Telemetry flooding detected": "MEDIUM",
    "Offline beyond threshold": "LOW",
    "Firmware version outdated": "MEDIUM",
    "Abnormal register writes": "HIGH",
    "Communication protocol anomaly": "MEDIUM",
    "Emergency stop triggered": "HIGH",
    "Control system anomaly": "CRITICAL",
    "VLAN hopping attempt": "HIGH",
}

ANOMALY_REC = {
    "Unexpected firmware change": "Isolate device immediately. Verify firmware integrity. Roll back to known-good version.",
    "Unauthorised command injection": "Block source. Audit all recent commands. Enable command allowlisting on PLC.",
    "Lateral movement attempt": "Segment network. Block lateral traffic. Investigate compromised source device.",
    "ARP spoofing detected": "Enable Dynamic ARP Inspection on switches. Investigate source MAC address.",
    "Default credentials detected": "Change credentials immediately. Audit all devices for default credentials.",
    "Remote desktop session detected": "Verify session legitimacy. Disable RDP if not required. Enable NLA.",
    "Port scan detected": "Block scanning source. Investigate for reconnaissance activity.",
    "Unusual outbound connection": "Block connection. Investigate for C2 communication or data exfiltration.",
    "Movement outside safe zone": "Emergency stop robot. Verify safety systems. Investigate control system integrity.",
    "Configuration change outside maintenance window": "Revert change. Investigate source. Enforce change management controls.",
    "Traffic volume anomaly": "Apply rate limiting. Investigate source. Check for DDoS or device malfunction.",
    "New device joined network": "Verify device identity. Apply NAC policy. Block if unrecognised.",
    "Firmware version outdated": "Schedule firmware update. Apply vendor security patches immediately.",
    "MAC flooding detected": "Enable port security on switch. Limit MAC addresses per port.",
    "Unusual process execution": "Terminate process. Isolate device. Investigate for malware.",
    "Data spike anomaly": "Verify sensor calibration. Check for tampering or malfunction.",
    "Telemetry flooding detected": "Rate limit device telemetry. Check for device compromise or misconfiguration.",
    "Offline beyond threshold": "Investigate device connectivity. Check for physical tampering.",
    "Abnormal register writes": "Audit register values. Revert to safe state. Investigate source of writes.",
    "Communication protocol anomaly": "Inspect traffic. Block anomalous protocol usage. Update allowlists.",
    "Emergency stop triggered": "Investigate cause. Verify safety system integrity before restart.",
    "Control system anomaly": "Isolate control system. Verify integrity. Engage OT security team.",
    "VLAN hopping attempt": "Disable DTP on all ports. Use dedicated native VLAN. Audit switch config.",
}

def parse_devices(description):
    desc_lower = description.lower()
    devices = []
    ip_counter = 1
    for dtype, dinfo in DEVICE_TYPES.items():
        keywords = [dtype, dinfo["label"].lower().split("/")[0].strip()]
        count = 1
        for kw in keywords:
            if kw in desc_lower:
                import re
                nums = re.findall(rf"(\d+)\s*{kw}", desc_lower)
                if nums:
                    count = min(int(nums[0]), 10)
                for i in range(count):
                    cpu = round(random.uniform(10,85), 1)
                    mem = round(random.uniform(20,90), 1)
                    risk = "LOW"
                    if cpu > 80 or mem > 85: risk = "HIGH"
                    elif cpu > 60 or mem > 70: risk = "MEDIUM"
                    devices.append({
                        "device_name": f"{dinfo['label']} {i+1:02d}",
                        "device_type": dtype,
                        "ip_address":  f"192.168.{ip_counter}.{10+i}",
                        "status":      "online" if random.random() > 0.1 else "offline",
                        "risk_level":  risk,
                        "cpu_usage":   cpu,
                        "memory_usage":mem,
                    })
                ip_counter += 1
                break
    if not devices:
        for i in range(5):
            devices.append({"device_name":f"Device {i+1:02d}","device_type":"sensor","ip_address":f"192.168.1.{10+i}","status":"online","risk_level":"LOW","cpu_usage":round(random.uniform(10,50),1),"memory_usage":round(random.uniform(20,60),1)})
    return devices

def detect_anomalies(devices, description):
    desc_lower = description.lower()
    anomalies = []
    risk_keywords = {
        "firmware": "Unexpected firmware change",
        "injection": "Unauthorised command injection",
        "lateral": "Lateral movement attempt",
        "arp": "ARP spoofing detected",
        "default password": "Default credentials detected",
        "rdp": "Remote desktop session detected",
        "port scan": "Port scan detected",
        "exfiltrat": "Unusual outbound connection",
        "safe zone": "Movement outside safe zone",
        "config change": "Configuration change outside maintenance window",
        "flooding": "Traffic volume anomaly",
        "new device": "New device joined network",
        "outdated": "Firmware version outdated",
        "mac flood": "MAC flooding detected",
        "vlan hop": "VLAN hopping attempt",
        "anomaly": "Data spike anomaly",
    }
    for kw, anomaly_type in risk_keywords.items():
        if kw in desc_lower:
            target = devices[0] if devices else {"device_name":"Unknown Device"}
            sev = ANOMALY_SEV.get(anomaly_type,"MEDIUM")
            anomalies.append({
                "device_name":   target["device_name"],
                "anomaly_type":  anomaly_type,
                "severity":      sev,
                "description":   f"Cognitive Twin detected: {anomaly_type} on {target['device_name']}. Automated analysis triggered.",
                "recommendation":ANOMALY_REC.get(anomaly_type,"Investigate and remediate immediately."),
                "mitre_tactic":  ANOMALY_MITRE.get(anomaly_type),
            })
    for device in devices:
        if device["cpu_usage"] > 80:
            anomalies.append({"device_name":device["device_name"],"anomaly_type":"Traffic volume anomaly","severity":"MEDIUM","description":f"High CPU usage ({device['cpu_usage']}%) detected on {device['device_name']}.","recommendation":"Investigate high load. Check for malicious processes or resource exhaustion attack.","mitre_tactic":"T1499 — Endpoint Denial of Service"})
        if device["status"] == "offline":
            anomalies.append({"device_name":device["device_name"],"anomaly_type":"Offline beyond threshold","severity":"LOW","description":f"{device['device_name']} is offline. Last seen recently.","recommendation":"Check device connectivity and physical integrity.","mitre_tactic":None})
    return anomalies

def calc_scores(devices, anomalies):
    sev_w = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}
    risk = min(sum(sev_w.get(a["severity"],0) for a in anomalies)*2, 100.0)
    offline = sum(1 for d in devices if d["status"]=="offline")
    health = max(100 - (offline/max(len(devices),1)*20) - (risk*0.3), 0)
    return round(risk,1), round(health,1)

@digital_twin_v2_bp.route("/api/digital-twin-v2/create", methods=["POST"])
@jwt_required()
def create():
    data    = request.get_json(silent=True) or {}
    name    = data.get("name","My Digital Twin")
    env_type= data.get("env_type","industrial")
    desc    = data.get("description","")
    if not desc.strip(): return jsonify({"error":"No description provided"}),400
    devices   = parse_devices(desc)
    anomalies = detect_anomalies(devices, desc)
    risk, health = calc_scores(devices, anomalies)
    sev = "CRITICAL" if risk>=70 else "HIGH" if risk>=45 else "MEDIUM" if risk>=20 else "LOW"
    summary = (f"Digital Twin created with {len(devices)} device(s) across {env_type} environment. "
               f"Health score: {health}/100. Risk score: {risk}/100. {len(anomalies)} anomaly(s) detected.")
    env = DigitalTwinV2Environment(user_id=get_jwt_identity(),name=name,env_type=env_type,device_count=len(devices),risk_score=risk,health_score=health,anomaly_count=len(anomalies),status="active",summary=summary,node_meta="{}")
    db.session.add(env); db.session.flush()
    for d in devices:
        db.session.add(DigitalTwinV2Device(env_id=env.id,device_name=d["device_name"],device_type=d["device_type"],ip_address=d["ip_address"],status=d["status"],risk_level=d["risk_level"],cpu_usage=d["cpu_usage"],memory_usage=d["memory_usage"],node_meta="{}"))
    for a in anomalies:
        db.session.add(DigitalTwinV2Anomaly(env_id=env.id,device_name=a["device_name"],anomaly_type=a["anomaly_type"],severity=a["severity"],description=a["description"],recommendation=a["recommendation"],mitre_tactic=a.get("mitre_tactic"),node_meta="{}"))
    db.session.commit()
    return jsonify({"env_id":env.id,"name":name,"device_count":len(devices),"anomaly_count":len(anomalies),"risk_score":risk,"health_score":health,"severity":sev,"summary":summary}),200

@digital_twin_v2_bp.route("/api/digital-twin-v2/environments/<env_id>", methods=["GET"])
@jwt_required()
def get_env(env_id):
    env = DigitalTwinV2Environment.query.filter_by(id=env_id,user_id=get_jwt_identity()).first()
    if not env: return jsonify({"error":"Not found"}),404
    devices   = DigitalTwinV2Device.query.filter_by(env_id=env_id).all()
    anomalies = DigitalTwinV2Anomaly.query.filter_by(env_id=env_id).all()
    return jsonify({"env_id":env.id,"name":env.name,"env_type":env.env_type,"device_count":env.device_count,"risk_score":env.risk_score,"health_score":env.health_score,"anomaly_count":env.anomaly_count,"status":env.status,"summary":env.summary,"created_at":env.created_at.isoformat(),"devices":[{"device_name":d.device_name,"device_type":d.device_type,"ip_address":d.ip_address,"status":d.status,"risk_level":d.risk_level,"cpu_usage":d.cpu_usage,"memory_usage":d.memory_usage} for d in devices],"anomalies":[{"device_name":a.device_name,"anomaly_type":a.anomaly_type,"severity":a.severity,"description":a.description,"recommendation":a.recommendation,"mitre_tactic":a.mitre_tactic} for a in anomalies],"by_status":{"online":sum(1 for d in devices if d.status=="online"),"offline":sum(1 for d in devices if d.status=="offline")},"by_risk":{"CRITICAL":sum(1 for d in devices if d.risk_level=="CRITICAL"),"HIGH":sum(1 for d in devices if d.risk_level=="HIGH"),"MEDIUM":sum(1 for d in devices if d.risk_level=="MEDIUM"),"LOW":sum(1 for d in devices if d.risk_level=="LOW")}}),200

@digital_twin_v2_bp.route("/api/digital-twin-v2/history", methods=["GET"])
@jwt_required()
def history():
    envs = DigitalTwinV2Environment.query.filter_by(user_id=get_jwt_identity()).order_by(DigitalTwinV2Environment.created_at.desc()).limit(50).all()
    return jsonify({"environments":[{"env_id":e.id,"name":e.name,"env_type":e.env_type,"device_count":e.device_count,"risk_score":e.risk_score,"health_score":e.health_score,"anomaly_count":e.anomaly_count,"created_at":e.created_at.isoformat()} for e in envs]}),200

@digital_twin_v2_bp.route("/api/digital-twin-v2/health", methods=["GET"])
def health():
    return jsonify({"module":"Cognitive Digital Twin v2","version":"2.0.0","status":"operational"}),200
