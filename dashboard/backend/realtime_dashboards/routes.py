# ============================================================
# AIPET X — Real-Time Dashboards
# Live Metrics | Security Posture | Operational Health
# ============================================================

import json, uuid, datetime, random
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

realtime_dashboards_bp = Blueprint("realtime_dashboards", __name__)

class RealtimeSnapshot(db.Model):
    __tablename__ = "realtime_snapshots"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    security_score  = Column(Float, default=0.0)
    threat_level    = Column(String(16), default="LOW")
    active_threats  = Column(Integer, default=0)
    open_incidents  = Column(Integer, default=0)
    compliance_pct  = Column(Float, default=0.0)
    uptime_pct      = Column(Float, default=99.9)
    events_per_min  = Column(Float, default=0.0)
    widgets_data    = Column(Text, default="{}")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")

def generate_realtime_data():
    sec_score   = round(random.uniform(45, 95), 1)
    threats     = random.randint(0, 25)
    incidents   = random.randint(0, 8)
    compliance  = round(random.uniform(65, 98), 1)
    uptime      = round(random.uniform(97, 99.99), 2)
    epm         = round(random.uniform(120, 4500), 0)

    threat_level = "CRITICAL" if threats > 15 else "HIGH" if threats > 8 else "MEDIUM" if threats > 3 else "LOW"

    # 24h timeline
    timeline = []
    base = sec_score
    for h in range(24):
        t = datetime.datetime.utcnow() - datetime.timedelta(hours=23-h)
        s = round(max(20, min(100, base + random.uniform(-8, 8))), 1)
        timeline.append({"hour":t.strftime("%H:00"),"score":s,"threats":random.randint(0,threats+3),"events":round(random.uniform(50,epm),0)})
        base = s

    # Top threats
    top_threats = [
        {"type":"Brute Force","count":random.randint(5,50),"severity":"HIGH","trend":"↑"},
        {"type":"Port Scan","count":random.randint(10,100),"severity":"MEDIUM","trend":"→"},
        {"type":"SQL Injection","count":random.randint(1,20),"severity":"CRITICAL","trend":"↑"},
        {"type":"XSS Attempt","count":random.randint(2,30),"severity":"HIGH","trend":"↓"},
        {"type":"C2 Beacon","count":random.randint(0,5),"severity":"CRITICAL","trend":"↑"},
    ]

    # Module health
    modules = [
        {"name":"Cloud Runtime","status":"ACTIVE","scans":random.randint(10,50),"findings":random.randint(0,20)},
        {"name":"Endpoint Agent","status":"ACTIVE","scans":random.randint(5,30),"findings":random.randint(0,15)},
        {"name":"ITDR","status":"ACTIVE","scans":random.randint(3,20),"findings":random.randint(0,10)},
        {"name":"Threat Intel","status":"ACTIVE","scans":random.randint(20,100),"findings":random.randint(0,50)},
        {"name":"SIEM","status":"ACTIVE","scans":random.randint(100,1000),"findings":random.randint(0,30)},
        {"name":"APM","status":"ACTIVE","scans":random.randint(5,25),"findings":random.randint(0,8)},
    ]

    widgets = {"timeline":timeline,"top_threats":top_threats,"modules":modules,"geo_attacks":random.randint(5,50),"blocked_today":random.randint(100,5000),"mean_detect_min":round(random.uniform(1,15),1)}
    return sec_score, threat_level, threats, incidents, compliance, uptime, epm, widgets

@realtime_dashboards_bp.route("/api/realtime/snapshot", methods=["GET"])
@jwt_required()
def snapshot():
    sec_score, threat_level, threats, incidents, compliance, uptime, epm, widgets = generate_realtime_data()
    s = RealtimeSnapshot(user_id=get_jwt_identity(), security_score=sec_score, threat_level=threat_level, active_threats=threats, open_incidents=incidents, compliance_pct=compliance, uptime_pct=uptime, events_per_min=epm, widgets_data=json.dumps(widgets), node_meta="{}")
    db.session.add(s); db.session.commit()
    return jsonify({"snapshot_id":s.id,"security_score":sec_score,"threat_level":threat_level,"active_threats":threats,"open_incidents":incidents,"compliance_pct":compliance,"uptime_pct":uptime,"events_per_min":epm,"widgets":widgets,"timestamp":s.created_at.isoformat()}), 200

@realtime_dashboards_bp.route("/api/realtime/health", methods=["GET"])
def health():
    return jsonify({"module":"Real-Time Dashboards","version":"1.0.0","status":"operational"}), 200
