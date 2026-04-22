# ============================================================
# AIPET X — Module #40: AI Policy Brain
# Policy Generation | Framework Mapping | Compliance Coverage
# Phase 5C | v6.2.0
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

policy_brain_bp = Blueprint("policy_brain", __name__)

# ============================================================
# DATABASE MODELS
# ============================================================

class PolicyBrainPolicy(db.Model):
    __tablename__ = "policy_brain_policies"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    title         = Column(String(256))
    policy_type   = Column(String(64))
    framework_map = Column(Text, default="[]")
    coverage_score= Column(Float, default=0.0)
    word_count    = Column(Integer, default=0)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")
    sections      = relationship("PolicyBrainSection", backref="policy", lazy=True, cascade="all, delete-orphan")

class PolicyBrainSection(db.Model):
    __tablename__ = "policy_brain_sections"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    policy_id     = Column(String(64), ForeignKey("policy_brain_policies.id"), nullable=False)
    section_number= Column(Integer)
    section_title = Column(String(256))
    content       = Column(Text)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

# ============================================================
# POLICY TEMPLATES
# ============================================================

POLICY_TYPES = {
    "information_security": {
        "title": "Information Security Policy",
        "frameworks": ["ISO 27001 A.5", "NIS2 Article 21", "NIST CSF GV.PO", "SOC2 CC1"],
        "sections": [
            {"title": "1. Purpose and Scope", "content": "This Information Security Policy establishes the framework for protecting {org_name} information assets. It applies to all employees, contractors, third-party suppliers, and any individual who accesses {org_name} systems or data."},
            {"title": "2. Information Security Objectives", "content": "The organisation is committed to: (a) Maintaining confidentiality of all sensitive information. (b) Ensuring integrity of data and systems. (c) Maintaining availability of critical business services. (d) Complying with all applicable laws and regulations including GDPR, NIS2 and ISO 27001."},
            {"title": "3. Roles and Responsibilities", "content": "Chief Information Security Officer (CISO): Overall accountability for information security strategy and policy. IT Security Team: Day-to-day implementation and monitoring of security controls. All Staff: Compliance with this policy and reporting of security incidents. Third Parties: Must comply with {org_name} security requirements as defined in supplier agreements."},
            {"title": "4. Asset Management", "content": "All information assets must be inventoried, classified and assigned an owner. Assets must be classified as: Public, Internal, Confidential, or Restricted. Asset owners are responsible for ensuring appropriate controls are applied based on classification."},
            {"title": "5. Access Control", "content": "Access to information systems must be granted on a least-privilege, need-to-know basis. Multi-factor authentication (MFA) is mandatory for all privileged access and remote access. Access rights must be reviewed quarterly and revoked immediately upon termination."},
            {"title": "6. Cryptography", "content": "All sensitive data must be encrypted at rest using AES-256 and in transit using TLS 1.2 or higher. Cryptographic keys must be managed using an approved key management system. The use of deprecated algorithms (MD5, SHA-1, DES) is strictly prohibited."},
            {"title": "7. Physical and Environmental Security", "content": "Access to data centres and server rooms is restricted to authorised personnel only. Environmental controls including fire suppression, cooling and power redundancy must be maintained. Visitors must be escorted at all times in secure areas."},
            {"title": "8. Incident Management", "content": "All security incidents must be reported to the Security Operations Centre (SOC) immediately. A formal incident response plan must be maintained and tested annually. Personal data breaches must be reported to the supervisory authority within 72 hours per GDPR Article 33."},
            {"title": "9. Business Continuity", "content": "Business continuity plans must be maintained for all critical systems with defined RTO and RPO targets. Backups must be performed daily and tested monthly. Disaster recovery exercises must be conducted at least annually."},
            {"title": "10. Compliance and Review", "content": "This policy must be reviewed annually or following a significant security incident. Non-compliance may result in disciplinary action up to and including termination. All staff must acknowledge this policy annually."},
        ]
    },
    "acceptable_use": {
        "title": "Acceptable Use Policy",
        "frameworks": ["ISO 27001 A.8", "SOC2 CC6", "NIST CSF PR.AT"],
        "sections": [
            {"title": "1. Purpose", "content": "This Acceptable Use Policy (AUP) defines the acceptable use of {org_name} information technology resources including computers, networks, email, internet, and cloud services."},
            {"title": "2. Scope", "content": "This policy applies to all employees, contractors, consultants, temporary staff, and any other individuals who use {org_name} IT resources, whether on-site or remotely."},
            {"title": "3. Acceptable Use", "content": "IT resources must be used primarily for legitimate business purposes. Incidental personal use is permitted provided it does not interfere with work duties, consume excessive resources, or violate this policy. All use is subject to monitoring and logging."},
            {"title": "4. Prohibited Activities", "content": "The following are strictly prohibited: (a) Accessing, downloading or distributing illegal, offensive or inappropriate content. (b) Attempting to bypass security controls or access unauthorised systems. (c) Installing unauthorised software or hardware. (d) Sharing credentials or allowing others to use your account. (e) Using {org_name} resources for commercial activities without authorisation."},
            {"title": "5. Email and Communications", "content": "Email must be used professionally and responsibly. Phishing and social engineering attacks must be reported immediately to the IT Security team. Sensitive data must not be transmitted via unencrypted email. Business communications must be retained per the data retention policy."},
            {"title": "6. Remote Working", "content": "Remote access must use the approved VPN solution. Public Wi-Fi must not be used without a VPN connection. Screens must be locked when unattended. Physical documents containing sensitive information must be securely stored and disposed of."},
            {"title": "7. Monitoring", "content": "Users have no expectation of privacy when using {org_name} IT resources. All activity may be monitored, logged and reviewed for security and compliance purposes. Monitoring is conducted in accordance with applicable employment law."},
            {"title": "8. Violations", "content": "Violations of this policy will be investigated and may result in disciplinary action, suspension of access, or termination. In serious cases, legal action may be pursued. Report violations to it.security@{org_name}.com."},
        ]
    },
    "password": {
        "title": "Password and Authentication Policy",
        "frameworks": ["ISO 27001 A.9", "NIS2 Article 21", "PCI DSS Requirement 8", "SOC2 CC6"],
        "sections": [
            {"title": "1. Purpose", "content": "This policy establishes requirements for password creation, management, and authentication to protect {org_name} systems and data from unauthorised access."},
            {"title": "2. Password Requirements", "content": "All passwords must meet the following minimum requirements: Minimum length of 16 characters. Must contain uppercase, lowercase, numbers and special characters. Must not contain the username or common dictionary words. Must not be reused from the last 12 passwords. Must not be shared with anyone under any circumstances."},
            {"title": "3. Multi-Factor Authentication", "content": "MFA is mandatory for: All privileged and administrative accounts. All remote access including VPN. All cloud service access. All access to systems containing sensitive or personal data. Approved MFA methods: authenticator apps (TOTP), hardware security keys (FIDO2). SMS-based MFA is discouraged due to SIM-swapping risks."},
            {"title": "4. Password Management", "content": "All staff must use the organisation-approved password manager. Passwords must never be stored in plaintext, spreadsheets or documents. Default passwords on all systems and devices must be changed immediately upon deployment. Vendor and service account passwords must be rotated every 90 days."},
            {"title": "5. Account Lockout", "content": "Accounts will be locked after 5 consecutive failed login attempts. Locked accounts must be unlocked by the IT helpdesk after identity verification. Repeated lockouts will trigger a security review."},
            {"title": "6. Privileged Accounts", "content": "Privileged accounts must be used only for administrative tasks. Day-to-day work must use standard user accounts. Privileged access must be logged and reviewed monthly. Just-in-time (JIT) access is the preferred model for privileged operations."},
            {"title": "7. Incident Response", "content": "Immediately report suspected password compromise to the IT Security team. Compromised passwords must be changed immediately across all affected systems. If credentials are exposed in a data breach, a full audit of affected systems must be conducted."},
        ]
    },
    "incident_response": {
        "title": "Incident Response Policy",
        "frameworks": ["ISO 27001 A.16", "NIS2 Article 23", "NIST CSF RS", "SOC2 CC7"],
        "sections": [
            {"title": "1. Purpose and Scope", "content": "This policy defines {org_name} approach to identifying, managing, and recovering from information security incidents to minimise business impact and ensure regulatory compliance."},
            {"title": "2. Incident Classification", "content": "Incidents are classified by severity: P1 Critical: Ransomware, data breach, system-wide outage. P2 High: Malware infection, unauthorised access, significant service degradation. P3 Medium: Policy violation, phishing attempt, minor service disruption. P4 Low: Spam, minor policy violations, informational alerts."},
            {"title": "3. Incident Response Team", "content": "Incident Commander: Coordinates overall response. SOC Lead: Technical investigation and containment. Legal Counsel: Regulatory and legal obligations. Communications Lead: Internal and external communications. CISO: Executive escalation and decision authority."},
            {"title": "4. Detection and Reporting", "content": "All staff must report suspected incidents immediately to the SOC via: Phone: [SOC Hotline], Email: soc@{org_name}.com, Ticketing system: [ITSM Portal]. The SOC must acknowledge all reports within 15 minutes and classify within 1 hour."},
            {"title": "5. Response Phases", "content": "Phase 1 — Identification: Confirm and classify the incident. Phase 2 — Containment: Limit the scope and impact. Phase 3 — Eradication: Remove the threat. Phase 4 — Recovery: Restore systems and services. Phase 5 — Post-Incident: Lessons learned and policy updates."},
            {"title": "6. Regulatory Notification", "content": "Personal data breaches must be reported to the supervisory authority within 72 hours (GDPR Article 33). Affected individuals must be notified without undue delay if high risk (GDPR Article 34). NIS2 significant incidents must be reported within 24 hours (early warning) and 72 hours (full notification)."},
            {"title": "7. Evidence Preservation", "content": "All evidence must be preserved in a forensically sound manner. Chain of custody must be maintained for all evidence. Logs must not be altered or deleted during an investigation. Legal hold may be applied to relevant systems and data."},
            {"title": "8. Testing and Review", "content": "The incident response plan must be tested via tabletop exercises at least annually. Results must be documented and improvements implemented within 30 days. This policy must be reviewed after every major incident and at least annually."},
        ]
    },
    "data_protection": {
        "title": "Data Protection and Privacy Policy",
        "frameworks": ["GDPR", "ISO 27001 A.18", "NIS2 Article 21", "SOC2 C1"],
        "sections": [
            {"title": "1. Purpose", "content": "This policy establishes {org_name} commitment to protecting personal data and complying with applicable data protection legislation including the UK GDPR, EU GDPR, and Data Protection Act 2018."},
            {"title": "2. Data Protection Principles", "content": "All personal data must be: Processed lawfully, fairly and transparently. Collected for specified, explicit and legitimate purposes. Adequate, relevant and limited to what is necessary. Accurate and kept up to date. Retained only as long as necessary. Processed securely with appropriate technical and organisational measures."},
            {"title": "3. Lawful Basis for Processing", "content": "Before processing personal data, a lawful basis must be identified and documented: Consent, Contract, Legal obligation, Vital interests, Public task, or Legitimate interests. A Records of Processing Activities (RoPA) must be maintained and kept up to date."},
            {"title": "4. Data Subject Rights", "content": "Individuals have the right to: Access their personal data (Subject Access Request — 30 days). Rectification of inaccurate data. Erasure (right to be forgotten). Restriction of processing. Data portability. Object to processing. All requests must be logged and fulfilled within statutory timeframes."},
            {"title": "5. Data Security", "content": "Personal data must be encrypted at rest (AES-256) and in transit (TLS 1.2+). Access must be restricted to authorised personnel on a need-to-know basis. Personal data must not be stored on personal devices without encryption. Data breaches must be reported to the DPO immediately."},
            {"title": "6. International Transfers", "content": "Personal data must not be transferred outside the UK/EEA without appropriate safeguards: Adequacy decision, Standard Contractual Clauses (SCCs), Binding Corporate Rules, or other approved mechanisms. All international transfers must be documented in the RoPA."},
            {"title": "7. Data Retention", "content": "Personal data must not be retained longer than necessary for its purpose. A data retention schedule must be maintained and applied consistently. Data must be securely deleted or anonymised when no longer required. Backups containing personal data must be subject to the same retention rules."},
            {"title": "8. Data Protection Officer", "content": "The Data Protection Officer (DPO) is responsible for overseeing compliance with this policy. Contact: dpo@{org_name}.com. The DPO must be consulted on all new processing activities and data breaches. DPIAs must be conducted for high-risk processing activities."},
        ]
    },
    "remote_working": {
        "title": "Remote Working Security Policy",
        "frameworks": ["ISO 27001 A.6.7", "NIST CSF PR.AC", "SOC2 CC6", "NIS2 Article 21"],
        "sections": [
            {"title": "1. Purpose", "content": "This policy establishes security requirements for employees working remotely to ensure {org_name} data and systems remain protected outside the office environment."},
            {"title": "2. Approved Devices", "content": "Only {org_name}-approved and managed devices may be used to access company systems and data. Personal devices (BYOD) require MDM enrollment and compliance certification before access is granted. All devices must have approved endpoint protection, encryption and remote-wipe capability enabled."},
            {"title": "3. Network Security", "content": "The approved corporate VPN must be used for all access to internal systems. Public Wi-Fi (cafes, hotels, airports) must never be used without an active VPN connection. Home routers must use WPA3 encryption and have default passwords changed. Guest Wi-Fi must be used to segregate work devices from personal devices."},
            {"title": "4. Physical Security", "content": "Screens must be locked when unattended (maximum 5-minute timeout). Screen privacy filters are required in public locations. Sensitive conversations must not take place in public areas. Physical documents containing sensitive information must be stored securely and shredded when no longer required."},
            {"title": "5. Cloud and SaaS Access", "content": "Only approved cloud services may be used for business data. Data must not be stored in personal cloud accounts (personal Dropbox, Google Drive etc.). MFA must be enabled on all cloud service accounts. Sharing settings must be reviewed to prevent unintended public access."},
            {"title": "6. Incident Reporting", "content": "Lost or stolen devices must be reported to IT Security immediately for remote wipe. Suspected security incidents must be reported to the SOC without delay. Data breaches involving remote working must follow the Incident Response Policy."},
            {"title": "7. Compliance", "content": "Remote workers are subject to the same security policies as office-based staff. Compliance will be monitored through endpoint management and security tooling. Non-compliance will be escalated per the disciplinary process."},
        ]
    }
}

KEYWORD_MAP = [
    {"type":"incident_response","keywords":["incident","response","breach","emergency","forensic","playbook","containment"]},
    {"type":"password","keywords":["password","authentication","mfa","credential","login","account","passphrase"]},
    {"type":"data_protection","keywords":["data protection","privacy","gdpr","personal data","dpo","ropa","data subject","erasure"]},
    {"type":"acceptable_use","keywords":["acceptable use","aup","internet","email","social media","bring your own","byod","personal use"]},
    {"type":"remote_working","keywords":["remote","work from home","wfh","vpn","telework","home office","mobile working"]},
    {"type":"information_security","keywords":["information security","infosec","isms","security policy","cyber","general security"]},
]

def classify_policy_type(description):
    desc_lower = description.lower()
    for item in KEYWORD_MAP:
        if any(kw in desc_lower for kw in item["keywords"]):
            return item["type"]
    return "information_security"

def generate_policy(policy_type, org_name, description):
    template = POLICY_TYPES.get(policy_type, POLICY_TYPES["information_security"])
    sections = []
    for s in template["sections"]:
        sections.append({
            "title":   s["title"],
            "content": s["content"].replace("{org_name}", org_name)
        })
    return template, sections

def coverage_score(policy_type):
    scores = {"information_security":92,"acceptable_use":88,"password":90,"incident_response":94,"data_protection":91,"remote_working":87}
    return scores.get(policy_type, 85)

# ============================================================
# API ROUTES
# ============================================================

@policy_brain_bp.route("/api/policy-brain/generate", methods=["POST"])
@jwt_required()
def generate():
    data        = request.get_json(silent=True) or {}
    org_name    = data.get("org_name", "Your Organisation")
    description = data.get("description", "")
    policy_type = data.get("policy_type", None)

    if not description.strip():
        return jsonify({"error": "No description provided"}), 400

    if not policy_type:
        policy_type = classify_policy_type(description)

    template, sections = generate_policy(policy_type, org_name, description)
    score = coverage_score(policy_type)
    word_count = sum(len(s["content"].split()) for s in sections)

    policy = PolicyBrainPolicy(
        user_id       = get_jwt_identity(),
        title         = template["title"].replace("{org_name}", org_name),
        policy_type   = policy_type,
        framework_map = json.dumps(template["frameworks"]),
        coverage_score= score,
        word_count    = word_count,
        node_meta     = json.dumps({"org_name": org_name})
    )
    db.session.add(policy)
    db.session.flush()

    for i, s in enumerate(sections):
        db.session.add(PolicyBrainSection(
            policy_id      = policy.id,
            section_number = i + 1,
            section_title  = s["title"],
            content        = s["content"],
            node_meta      = "{}"
        ))

    db.session.commit()

    return jsonify({
        "policy_id":    policy.id,
        "title":        policy.title,
        "policy_type":  policy_type,
        "frameworks":   template["frameworks"],
        "coverage_score": score,
        "word_count":   word_count,
        "section_count":len(sections)
    }), 200

@policy_brain_bp.route("/api/policy-brain/policies/<policy_id>", methods=["GET"])
@jwt_required()
def get_policy(policy_id):
    policy = PolicyBrainPolicy.query.filter_by(id=policy_id, user_id=get_jwt_identity()).first()
    if not policy:
        return jsonify({"error": "Policy not found"}), 404
    sections = PolicyBrainSection.query.filter_by(policy_id=policy_id).order_by(PolicyBrainSection.section_number).all()
    return jsonify({
        "policy_id":     policy.id,
        "title":         policy.title,
        "policy_type":   policy.policy_type,
        "frameworks":    json.loads(policy.framework_map),
        "coverage_score":policy.coverage_score,
        "word_count":    policy.word_count,
        "created_at":    policy.created_at.isoformat(),
        "sections": [{"number": s.section_number, "title": s.section_title, "content": s.content} for s in sections]
    }), 200

@policy_brain_bp.route("/api/policy-brain/history", methods=["GET"])
@jwt_required()
def history():
    policies = PolicyBrainPolicy.query.filter_by(user_id=get_jwt_identity()).order_by(PolicyBrainPolicy.created_at.desc()).limit(50).all()
    return jsonify({"policies": [{"policy_id": p.id, "title": p.title, "policy_type": p.policy_type, "coverage_score": p.coverage_score, "word_count": p.word_count, "created_at": p.created_at.isoformat()} for p in policies]}), 200

@policy_brain_bp.route("/api/policy-brain/health", methods=["GET"])
def health():
    return jsonify({"module": "AI Policy Brain", "version": "1.0.0", "policy_types": list(POLICY_TYPES.keys()), "status": "operational"}), 200
