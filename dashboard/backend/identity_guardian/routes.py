# ============================================================
# AIPET X — Module #38: AI Identity Guardian
# Privilege Analysis | Behaviour Anomaly | Credential Risk
# Phase 5C | v6.2.0
# ============================================================

import re, json, uuid, datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

identity_guardian_bp = Blueprint("identity_guardian", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class IdentityGuardianAlert(db.Model):
    __tablename__ = "identity_guardian_alerts"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    subject       = Column(String(256))
    risk_score    = Column(Float, default=0.0)
    severity      = Column(String(16), default="LOW")
    status        = Column(String(32), default="open")
    summary       = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    signals       = relationship("IdentityGuardianSignal", backref="alert", lazy=True, cascade="all, delete-orphan")

class IdentityGuardianSignal(db.Model):
    __tablename__ = "identity_guardian_signals"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id      = Column(String(64), ForeignKey("identity_guardian_alerts.id"), nullable=False)
    signal_type   = Column(String(64))
    title         = Column(String(256))
    description   = Column(Text)
    severity      = Column(String(16))
    recommendation= Column(Text, nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# PRIVILEGE ANALYSER ENGINE
# ============================================================

PRIVILEGE_RULES = [
    {"title":"Admin Account Sprawl","keywords":["multiple admin","admin account","domain admin","local admin","administrator","root access","sudo all"],"severity":"CRITICAL","signal_type":"PRIVILEGE","recommendation":"Reduce admin accounts to minimum. Use just-in-time privileged access management."},
    {"title":"Stale/Dormant Account Detected","keywords":["inactive","dormant","stale","unused","old account","no login","last login","disabled"],"severity":"HIGH","signal_type":"PRIVILEGE","recommendation":"Disable or remove accounts inactive for more than 90 days. Implement automated deprovisioning."},
    {"title":"Over-Privileged Service Account","keywords":["service account","api key","token","over-privileged","excessive permission","broad access","wildcard"],"severity":"HIGH","signal_type":"PRIVILEGE","recommendation":"Apply least-privilege to all service accounts. Rotate credentials every 90 days."},
    {"title":"Shared Account Usage","keywords":["shared account","generic account","shared credential","shared login","shared password","common account"],"severity":"CRITICAL","signal_type":"PRIVILEGE","recommendation":"Eliminate shared accounts. Assign individual accounts for full audit trail."},
    {"title":"Privileged Access Without Approval","keywords":["unapproved","unauthorized","no approval","bypass","escalated without","self-approved"],"severity":"CRITICAL","signal_type":"PRIVILEGE","recommendation":"Enforce approval workflows for all privileged access requests via PAM solution."},
    {"title":"Excessive Cloud IAM Permissions","keywords":["iam","s3:*","ec2:*","*:*","admin policy","full access","all permissions","cloud admin"],"severity":"HIGH","signal_type":"PRIVILEGE","recommendation":"Replace wildcard IAM policies with granular least-privilege policies."},
]

# ============================================================
# BEHAVIOUR ANOMALY DETECTOR
# ============================================================

BEHAVIOUR_RULES = [
    {"title":"Impossible Travel Detected","keywords":["impossible travel","different country","multiple location","geographic","two country","rapid location"],"severity":"CRITICAL","signal_type":"BEHAVIOUR","recommendation":"Block session and require re-authentication. Investigate with user and manager immediately."},
    {"title":"Unusual Login Time","keywords":["unusual time","odd hour","3am","midnight","weekend login","outside business","after hours","night login"],"severity":"HIGH","signal_type":"BEHAVIOUR","recommendation":"Enforce time-based access policies. Alert security team for off-hours privileged access."},
    {"title":"Brute Force / Password Spray","keywords":["brute force","password spray","multiple fail","login attempt","failed login","lockout","credential stuff"],"severity":"CRITICAL","signal_type":"BEHAVIOUR","recommendation":"Lock account after 5 failed attempts. Implement CAPTCHA and IP-based rate limiting."},
    {"title":"Mass Data Access / Exfiltration","keywords":["mass download","bulk access","large transfer","exfiltrat","unusual volume","download spike","data theft"],"severity":"CRITICAL","signal_type":"BEHAVIOUR","recommendation":"Implement DLP controls and alert on abnormal data access patterns immediately."},
    {"title":"Lateral Movement Behaviour","keywords":["lateral","moving","pivot","multiple system","cross system","rdp","psexec","wmi","smb"],"severity":"HIGH","signal_type":"BEHAVIOUR","recommendation":"Segment network and enforce Zero Trust to prevent lateral movement between systems."},
    {"title":"New Device / Unknown Endpoint","keywords":["new device","unknown device","unmanaged","unfamiliar","new endpoint","unregistered","byod"],"severity":"MEDIUM","signal_type":"BEHAVIOUR","recommendation":"Enforce device compliance checks via MDM before granting access."},
]

# ============================================================
# CREDENTIAL RISK ENGINE
# ============================================================

CREDENTIAL_RULES = [
    {"title":"No MFA Enforced","keywords":["no mfa","without mfa","mfa disabled","single factor","no two factor","no 2fa","mfa not"],"severity":"CRITICAL","signal_type":"CREDENTIAL","recommendation":"Enforce MFA immediately for all accounts, especially privileged users."},
    {"title":"Weak Password Policy","keywords":["weak password","simple password","short password","no complexity","password123","default password","no expiry"],"severity":"HIGH","signal_type":"CREDENTIAL","recommendation":"Enforce minimum 16-character passwords with complexity. Use a password manager."},
    {"title":"Hardcoded Credentials Detected","keywords":["hardcoded","plaintext password","password in code","credential in script","secret in repo","api key in code"],"severity":"CRITICAL","signal_type":"CREDENTIAL","recommendation":"Remove hardcoded credentials immediately. Rotate all exposed secrets and use a vault."},
    {"title":"Credential Exposure in Logs","keywords":["password in log","credential in log","token in log","secret in log","key in log"],"severity":"CRITICAL","signal_type":"CREDENTIAL","recommendation":"Scrub credentials from all logs immediately. Implement log filtering and secret scanning."},
    {"title":"Long-lived Access Tokens","keywords":["never expire","no expiry","long lived","permanent token","no rotation","token rotation","api key rotation"],"severity":"HIGH","signal_type":"CREDENTIAL","recommendation":"Rotate all access tokens every 90 days. Use short-lived tokens via OIDC where possible."},
    {"title":"Password Reuse Detected","keywords":["reuse","same password","reused","duplicate password","password reuse","recycled"],"severity":"HIGH","signal_type":"CREDENTIAL","recommendation":"Enforce password history policy. Implement a password manager across the organisation."},
]

# ============================================================
# SCORING & ANALYSIS
# ============================================================

SEV_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}

def run_analysis(text):
    signals = []
    text_lower = text.lower()
    for rule in PRIVILEGE_RULES + BEHAVIOUR_RULES + CREDENTIAL_RULES:
        if any(kw in text_lower for kw in rule["keywords"]):
            signals.append({
                "signal_type":    rule["signal_type"],
                "title":          rule["title"],
                "severity":       rule["severity"],
                "description":    f"Risk signal detected based on submitted identity profile. Matched pattern: {rule['title']}.",
                "recommendation": rule["recommendation"]
            })
    return signals

def calculate_risk(signals):
    if not signals:
        return 0.0
    raw = sum(SEV_WEIGHTS.get(s["severity"], 0) for s in signals)
    return round(min(raw * 1.5, 100.0), 1)

def overall_severity(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

# ============================================================
# API ROUTES
# ============================================================

@identity_guardian_bp.route("/api/identity-guardian/analyse", methods=["POST"])
@jwt_required()
def analyse():
    data    = request.get_json(silent=True) or {}
    subject = data.get("subject", "Unknown Identity")
    profile = data.get("profile", "")

    if not profile.strip():
        return jsonify({"error": "No identity profile provided"}), 400

    signals  = run_analysis(profile)
    score    = calculate_risk(signals)
    sev      = overall_severity(score)

    critical = sum(1 for s in signals if s["severity"] == "CRITICAL")
    high     = sum(1 for s in signals if s["severity"] == "HIGH")
    medium   = sum(1 for s in signals if s["severity"] == "MEDIUM")

    summary = f"Identity risk analysis for {subject} complete. Risk score: {score}/100. Severity: {sev}. {len(signals)} signal(s) detected ({critical} critical, {high} high, {medium} medium)."

    alert = IdentityGuardianAlert(
        user_id    = get_jwt_identity(),
        subject    = subject,
        risk_score = score,
        severity   = sev,
        status     = "open" if score >= 45 else "resolved",
        summary    = summary,
        node_meta  = "{}"
    )
    db.session.add(alert)
    db.session.flush()

    for s in signals:
        db.session.add(IdentityGuardianSignal(
            alert_id      = alert.id,
            signal_type   = s["signal_type"],
            title         = s["title"],
            description   = s["description"],
            severity      = s["severity"],
            recommendation= s["recommendation"],
            node_meta     = "{}"
        ))

    db.session.commit()

    try:
        from dashboard.backend.central_events.adapter import emit_event
        emit_event(
            source_module = "identity_guardian",
            source_table  = "identity_guardian_alerts",
            source_row_id = alert.id,
            event_type    = "identity_guardian_alert",
            severity      = alert.severity.lower(),
            user_id       = alert.user_id,
            entity        = alert.subject,
            entity_type   = "user",
            title         = alert.summary[:200] if alert.summary else f"Identity risk analysis for {alert.subject}",
            risk_score    = alert.risk_score,
            payload       = {
                "signal_count": len(signals),
                "status":       alert.status,
            },
        )
    except Exception:
        current_app.logger.exception("emit_event call site error in identity_guardian")

    return jsonify({
        "alert_id":     alert.id,
        "subject":      subject,
        "risk_score":   score,
        "severity":     sev,
        "signal_count": len(signals),
        "summary":      summary
    }), 200

@identity_guardian_bp.route("/api/identity-guardian/alerts/<alert_id>", methods=["GET"])
@jwt_required()
def get_alert(alert_id):
    alert = IdentityGuardianAlert.query.filter_by(id=alert_id, user_id=get_jwt_identity()).first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    signals = IdentityGuardianSignal.query.filter_by(alert_id=alert_id).all()
    return jsonify({
        "alert_id":   alert.id,
        "subject":    alert.subject,
        "risk_score": alert.risk_score,
        "severity":   alert.severity,
        "status":     alert.status,
        "summary":    alert.summary,
        "created_at": alert.created_at.isoformat(),
        "signals": [{"signal_type": s.signal_type, "title": s.title, "severity": s.severity, "description": s.description, "recommendation": s.recommendation} for s in signals],
        "summary_by_type": {
            "PRIVILEGE":  sum(1 for s in signals if s.signal_type == "PRIVILEGE"),
            "BEHAVIOUR":  sum(1 for s in signals if s.signal_type == "BEHAVIOUR"),
            "CREDENTIAL": sum(1 for s in signals if s.signal_type == "CREDENTIAL"),
        }
    }), 200

@identity_guardian_bp.route("/api/identity-guardian/history", methods=["GET"])
@jwt_required()
def history():
    alerts = IdentityGuardianAlert.query.filter_by(user_id=get_jwt_identity()).order_by(IdentityGuardianAlert.created_at.desc()).limit(50).all()
    return jsonify({"alerts": [{"alert_id": a.id, "subject": a.subject, "risk_score": a.risk_score, "severity": a.severity, "status": a.status, "created_at": a.created_at.isoformat()} for a in alerts]}), 200

@identity_guardian_bp.route("/api/identity-guardian/health", methods=["GET"])
def health():
    return jsonify({"module": "AI Identity Guardian", "version": "1.0.0", "engines": ["PRIVILEGE", "BEHAVIOUR", "CREDENTIAL"], "status": "operational"}), 200
