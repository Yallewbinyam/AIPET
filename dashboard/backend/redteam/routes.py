"""
AIPET X — AI Red Team Routes

Endpoints:
  GET    /api/redteam/campaigns           — list campaigns
  POST   /api/redteam/campaigns           — create campaign
  DELETE /api/redteam/campaigns/<id>      — delete campaign
  POST   /api/redteam/campaigns/<id>/run  — run campaign
  GET    /api/redteam/campaigns/<id>/attacks — attacks in campaign
  POST   /api/redteam/report/<id>         — generate AI pentest report
  GET    /api/redteam/stats               — dashboard metrics
  GET    /api/redteam/techniques          — available attack techniques
"""
import json
import time
import random
import os
import urllib.request
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.redteam.models import RtCampaign, RtAttack
from dashboard.backend.siem.models import SiemEvent

redteam_bp = Blueprint("redteam", __name__)


# ── MITRE ATT&CK technique library ──────────────────────────
# IoT-relevant techniques with realistic simulation outcomes

ATTACK_TECHNIQUES = [
    # Initial Access
    {
        "mitre_id":  "T1190",
        "tactic":    "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "severity":  "Critical",
        "description": "Attempt to exploit vulnerabilities in internet-facing IoT management interfaces",
        "indicators": ["CVE exploitation", "SQL injection", "RCE attempts"],
    },
    {
        "mitre_id":  "T1078",
        "tactic":    "Initial Access",
        "technique": "Valid Accounts — Default Credentials",
        "severity":  "Critical",
        "description": "Test for default vendor credentials on IoT devices",
        "indicators": ["admin:admin", "admin:password", "root:root", "user:user"],
    },
    # Execution
    {
        "mitre_id":  "T1059",
        "tactic":    "Execution",
        "technique": "Command and Scripting Interpreter",
        "severity":  "High",
        "description": "Attempt to execute commands via exposed management interfaces",
        "indicators": ["Shell access", "Telnet commands", "SSH execution"],
    },
    {
        "mitre_id":  "T1203",
        "tactic":    "Execution",
        "technique": "Exploitation for Client Execution",
        "severity":  "High",
        "description": "Exploit firmware vulnerabilities for code execution",
        "indicators": ["Buffer overflow", "Format string", "ROP chains"],
    },
    # Persistence
    {
        "mitre_id":  "T1505",
        "tactic":    "Persistence",
        "technique": "Server Software Component",
        "severity":  "High",
        "description": "Attempt to install persistent backdoors in IoT firmware",
        "indicators": ["Backdoor installation", "Cron job injection", "Init script modification"],
    },
    {
        "mitre_id":  "T1136",
        "tactic":    "Persistence",
        "technique": "Create Account",
        "severity":  "Medium",
        "description": "Create hidden admin accounts on compromised devices",
        "indicators": ["Hidden user creation", "SSH key injection"],
    },
    # Lateral Movement
    {
        "mitre_id":  "T1021",
        "tactic":    "Lateral Movement",
        "technique": "Remote Services",
        "severity":  "Critical",
        "description": "Move laterally through IoT network using compromised credentials",
        "indicators": ["SSH pivoting", "RDP hopping", "WMI execution"],
    },
    {
        "mitre_id":  "T1210",
        "tactic":    "Lateral Movement",
        "technique": "Exploitation of Remote Services",
        "severity":  "Critical",
        "description": "Exploit unpatched services to move between network segments",
        "indicators": ["EternalBlue", "PrintNightmare", "Log4Shell"],
    },
    # Collection
    {
        "mitre_id":  "T1040",
        "tactic":    "Collection",
        "technique": "Network Sniffing",
        "severity":  "High",
        "description": "Capture unencrypted IoT protocol traffic (MQTT, Modbus, DNP3)",
        "indicators": ["Plaintext MQTT capture", "Modbus register reads", "DNP3 interception"],
    },
    {
        "mitre_id":  "T1530",
        "tactic":    "Collection",
        "technique": "Data from Cloud Storage",
        "severity":  "High",
        "description": "Access misconfigured cloud storage containing IoT data",
        "indicators": ["S3 bucket enumeration", "Blob storage access", "GCS object listing"],
    },
    # Command and Control
    {
        "mitre_id":  "T1071",
        "tactic":    "Command and Control",
        "technique": "Application Layer Protocol",
        "severity":  "High",
        "description": "Establish C2 channel using legitimate IoT protocols (MQTT, CoAP)",
        "indicators": ["MQTT C2 channel", "CoAP beaconing", "DNS tunneling"],
    },
    # Impact
    {
        "mitre_id":  "T1499",
        "tactic":    "Impact",
        "technique": "Endpoint Denial of Service",
        "severity":  "Critical",
        "description": "Attempt to disrupt IoT device availability",
        "indicators": ["Device flood", "Firmware corruption", "Config wipe"],
    },
    {
        "mitre_id":  "T1565",
        "tactic":    "Impact",
        "technique": "Data Manipulation",
        "severity":  "Critical",
        "description": "Manipulate sensor readings or control system data",
        "indicators": ["False sensor data injection", "Register manipulation", "Replay attacks"],
    },
    # Discovery
    {
        "mitre_id":  "T1046",
        "tactic":    "Discovery",
        "technique": "Network Service Discovery",
        "severity":  "Medium",
        "description": "Map the IoT network to identify attack targets",
        "indicators": ["Port scanning", "Service enumeration", "Device fingerprinting"],
    },
    {
        "mitre_id":  "T1083",
        "tactic":    "Discovery",
        "technique": "File and Directory Discovery",
        "severity":  "Medium",
        "description": "Discover sensitive files on compromised IoT devices",
        "indicators": ["Config file access", "Certificate discovery", "Credential file enumeration"],
    },
]

# Defence mechanisms that can block attacks
DEFENCES = [
    "Zero-Trust Policy (AIPET X)",
    "Network Segmentation",
    "SIEM Detection Rule",
    "Autonomous Defense Playbook",
    "Firewall Rule",
    "Multi-Factor Authentication",
    "Patch Management",
    "Encryption",
]

def _simulate_attack(technique, target, has_findings):
    """
    Simulate a single attack technique against a target.

    Result logic:
      - If target has critical findings matching technique: success (attacker wins)
      - If target has partial coverage: partial success
      - If defences are strong: blocked

    Returns (result, impact, evidence, blocked_by)
    """
    random.seed(hash(technique["mitre_id"] + str(target)) % 10000)

    # Weight outcomes based on whether target has related findings
    if has_findings and technique["severity"] == "Critical":
        # Likely to succeed against vulnerable target
        weights = [0.55, 0.25, 0.20]  # success, partial, blocked
    elif has_findings:
        weights = [0.35, 0.35, 0.30]
    else:
        weights = [0.15, 0.25, 0.60]  # mostly blocked for clean targets

    outcome = random.choices(
        ["success", "partial", "blocked"],
        weights=weights
    )[0]

    impacts = {
        "success": [
            f"Full access gained to {target}",
            f"Credentials extracted from {target}",
            f"Persistent backdoor installed on {target}",
            f"Sensitive data exfiltrated from {target}",
            f"Control registers read/written on {target}",
        ],
        "partial": [
            f"Limited access obtained — privilege escalation needed",
            f"Partial data access — encryption prevented full exfil",
            f"Foothold established but detected by monitoring",
            f"Some credentials found — MFA prevented full compromise",
        ],
        "blocked": [
            f"Attack blocked by network segmentation",
            f"SIEM detection rule triggered — connection terminated",
            f"Zero-Trust policy denied access",
            f"Strong authentication prevented credential attack",
            f"Encryption defeated traffic interception attempt",
        ],
    }

    evidence_map = {
        "success": f"Successful {technique['technique']} — {random.choice(technique['indicators'])}",
        "partial": f"Partial {technique['technique']} — {random.choice(technique['indicators'])} (partially mitigated)",
        "blocked": f"Blocked attempt: {random.choice(technique['indicators'])} detected and terminated",
    }

    blocked_by = random.choice(DEFENCES) if outcome in ("blocked", "partial") else None

    return (
        outcome,
        random.choice(impacts[outcome]),
        evidence_map[outcome],
        blocked_by,
    )


# ── Campaign endpoints ───────────────────────────────────────

@redteam_bp.route("/api/redteam/campaigns", methods=["GET"])
@jwt_required()
def list_campaigns():
    campaigns = RtCampaign.query.order_by(
        RtCampaign.created_at.desc()).all()
    return jsonify({"campaigns": [c.to_dict() for c in campaigns]})


@redteam_bp.route("/api/redteam/campaigns", methods=["POST"])
@jwt_required()
def create_campaign():
    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return jsonify({"error": "name required"}), 400

    campaign = RtCampaign(
        name        = data["name"],
        description = data.get("description"),
        scope       = data.get("scope", "192.168.1.0/24"),
        objectives  = data.get("objectives",
            "Test IoT network defences against MITRE ATT&CK techniques"),
        status      = "draft",
        created_by  = int(get_jwt_identity()),
    )
    db.session.add(campaign)
    db.session.commit()
    return jsonify({"success": True,
                    "campaign": campaign.to_dict()}), 201


@redteam_bp.route("/api/redteam/campaigns/<int:cid>", methods=["DELETE"])
@jwt_required()
def delete_campaign(cid):
    campaign = RtCampaign.query.get_or_404(cid)
    RtAttack.query.filter_by(campaign_id=cid).delete()
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({"success": True})


@redteam_bp.route("/api/redteam/campaigns/<int:cid>/run", methods=["POST"])
@jwt_required()
def run_campaign(cid):
    """
    Execute a red team campaign — run all selected attack
    techniques against the defined scope.

    For each technique:
      1. Identify relevant targets from AIPET scan data
      2. Simulate the attack with realistic outcome weighting
      3. Log result, evidence, and blocking mechanism
      4. Push high-impact successes to SIEM

    Returns campaign summary with defence score.
    """
    from dashboard.backend.models import Finding
    from sqlalchemy import distinct

    campaign = RtCampaign.query.get_or_404(cid)
    if campaign.status == "running":
        return jsonify({"error": "Campaign already running"}), 400

    data       = request.get_json(silent=True) or {}
    techniques = data.get("techniques", ATTACK_TECHNIQUES)
    if isinstance(techniques, list) and techniques and isinstance(techniques[0], str):
        techniques = [t for t in ATTACK_TECHNIQUES
                      if t["mitre_id"] in techniques]
    if not techniques:
        techniques = ATTACK_TECHNIQUES

    campaign.status = "running"
    db.session.commit()

    # Get targets from scan data
    targets = [row[0] for row in db.session.query(
        distinct(Finding.target)).filter(
        Finding.target.isnot(None)).all()]
    if not targets:
        targets = ["192.168.1.1", "192.168.1.2",
                   "192.168.1.3", "192.168.1.4"]

    # Clear previous attacks for this campaign
    RtAttack.query.filter_by(campaign_id=cid).delete()
    db.session.flush()

    start_time    = time.time()
    executed      = []
    success_count = 0
    blocked_count = 0
    now           = datetime.now(timezone.utc)
    attack_siem_events = []

    for tech in techniques:
        # Pick a target for this technique
        target = random.choice(targets)

        # Check if target has findings relevant to this technique
        findings = Finding.query.filter_by(target=target).all()
        has_findings = len(findings) > 0

        result, impact, evidence, blocked_by = _simulate_attack(
            tech, target, has_findings)

        attack = RtAttack(
            campaign_id = cid,
            mitre_id    = tech["mitre_id"],
            tactic      = tech["tactic"],
            technique   = tech["technique"],
            target      = target,
            result      = result,
            impact      = impact,
            evidence    = evidence,
            blocked_by  = blocked_by,
            severity    = tech["severity"],
            executed_at = now,
        )
        db.session.add(attack)

        if result == "success":
            success_count += 1
            # Push successful attacks to SIEM
            event = SiemEvent(
                event_type  = "redteam_finding",
                source      = "AIPET AI Red Team",
                severity    = tech["severity"],
                title       = f"[RED TEAM] {tech['technique']} succeeded on {target}",
                description = impact,
                mitre_id    = tech["mitre_id"],
            )
            db.session.add(event)
            attack_siem_events.append((event, target))
        elif result == "blocked":
            blocked_count += 1

        executed.append({
            "technique": tech["technique"],
            "mitre_id":  tech["mitre_id"],
            "result":    result,
            "target":    target,
        })

    # Calculate defence score
    # 100 = all blocked, 0 = all succeeded
    total         = len(executed)
    partial_count = total - success_count - blocked_count
    defence_score = int(
        (blocked_count * 100 + partial_count * 50) / max(total, 1)
    )

    campaign.status        = "completed"
    campaign.attack_count  = total
    campaign.success_count = success_count
    campaign.blocked_count = blocked_count
    campaign.overall_score = defence_score
    campaign.duration_sec  = int(time.time() - start_time)
    campaign.completed_at  = datetime.now(timezone.utc)

    db.session.commit()

    for sev_event, ev_target in attack_siem_events:
        try:
            from dashboard.backend.central_events.adapter import emit_event
            emit_event(
                source_module    = "redteam",
                source_table     = "siem_events",
                source_row_id    = sev_event.id,
                event_type       = sev_event.event_type,
                severity         = sev_event.severity.lower(),
                user_id          = sev_event.user_id,
                entity           = ev_target,
                entity_type      = "device",
                title            = sev_event.title,
                mitre_techniques = [{"technique_id": sev_event.mitre_id, "confidence": 1.0}] if sev_event.mitre_id else None,
                payload          = {"original_siem_event_id": sev_event.id},
            )
        except Exception:
            current_app.logger.exception("emit_event call site error in redteam")

    return jsonify({
        "campaign":      campaign.to_dict(),
        "total":         total,
        "success":       success_count,
        "blocked":       blocked_count,
        "partial":       partial_count,
        "defence_score": defence_score,
        "attacks":       executed,
    })


@redteam_bp.route("/api/redteam/campaigns/<int:cid>/attacks",
                  methods=["GET"])
@jwt_required()
def campaign_attacks(cid):
    """All attacks in a campaign."""
    attacks = RtAttack.query.filter_by(campaign_id=cid).order_by(
        RtAttack.created_at.asc()).all()
    return jsonify({"attacks": [a.to_dict() for a in attacks]})


# ── AI Report generation ─────────────────────────────────────

@redteam_bp.route("/api/redteam/report/<int:cid>", methods=["POST"])
@jwt_required()
def generate_report(cid):
    """
    Generate a professional AI-written penetration test report
    for a completed campaign using Claude.

    The report follows industry-standard pentest report structure:
    executive summary, methodology, findings, risk ratings,
    and remediation recommendations.
    """
    campaign = RtCampaign.query.get_or_404(cid)
    if campaign.status != "completed":
        return jsonify({"error": "Campaign must be completed first"}), 400

    attacks = RtAttack.query.filter_by(campaign_id=cid).all()

    # Build campaign summary for Claude
    successful = [a for a in attacks if a.result == "success"]
    partial    = [a for a in attacks if a.result == "partial"]
    blocked    = [a for a in attacks if a.result == "blocked"]

    summary = f"""Campaign: {campaign.name}
Scope: {campaign.scope}
Duration: {campaign.duration_sec} seconds
Total techniques tested: {campaign.attack_count}
Successful attacks: {campaign.success_count}
Partially successful: {len(partial)}
Blocked: {campaign.blocked_count}
Defence score: {campaign.overall_score}/100

SUCCESSFUL ATTACKS:
{chr(10).join(f"- [{a.mitre_id}] {a.technique} on {a.target}: {a.impact}" for a in successful[:8])}

BLOCKED ATTACKS:
{chr(10).join(f"- [{a.mitre_id}] {a.technique} — {a.blocked_by}" for a in blocked[:5])}

PARTIAL SUCCESSES:
{chr(10).join(f"- [{a.mitre_id}] {a.technique} on {a.target}" for a in partial[:5])}
"""

    prompt = f"""You are a senior penetration tester writing a professional
red team assessment report. Based on the following campaign results,
write a structured penetration test report.

{summary}

Structure the report as:

1. EXECUTIVE SUMMARY
   Risk rating, key findings, business impact — 1 paragraph

2. METHODOLOGY
   Brief description of techniques used and testing approach

3. CRITICAL FINDINGS
   Top 3 most dangerous successful attacks with MITRE IDs,
   what was achieved, and business risk

4. DEFENCE EFFECTIVENESS
   What worked well, which controls blocked attacks,
   defence score analysis

5. RECOMMENDATIONS
   Top 5 specific remediation actions, prioritised by risk

6. RISK RATING SUMMARY
   Table format: Technique | Result | Risk | Priority

Keep it professional, specific, and actionable.
Reference actual MITRE ATT&CK IDs from the results."""

    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return jsonify({"error": "ANTHROPIC_API_KEY not set"}), 500

        payload = json.dumps({
            "model":      "claude-opus-4-5",
            "max_tokens": 2000,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data    = payload,
            headers = {
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            method = "POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data        = json.loads(resp.read().decode("utf-8"))
            content     = data["content"][0]["text"]
            tokens_used = data.get("usage", {}).get("output_tokens", 0)

        return jsonify({
            "campaign":    campaign.to_dict(),
            "report":      content,
            "tokens_used": tokens_used,
            "success":     True,
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


# ── Stats + techniques ───────────────────────────────────────

@redteam_bp.route("/api/redteam/stats", methods=["GET"])
@jwt_required()
def redteam_stats():
    campaigns      = RtCampaign.query.all()
    total_c        = len(campaigns)
    completed_c    = sum(1 for c in campaigns if c.status == "completed")
    total_attacks  = RtAttack.query.count()
    success_attacks= RtAttack.query.filter_by(result="success").count()
    blocked_attacks= RtAttack.query.filter_by(result="blocked").count()
    avg_score      = sum(c.overall_score for c in campaigns
                         if c.status == "completed") / max(completed_c, 1)

    # Tactic breakdown
    tactics = {}
    for attack in RtAttack.query.all():
        t = attack.tactic
        if t not in tactics:
            tactics[t] = {"success": 0, "blocked": 0, "partial": 0}
        tactics[t][attack.result] = tactics[t].get(attack.result, 0) + 1

    return jsonify({
        "total_campaigns":   total_c,
        "completed":         completed_c,
        "total_attacks":     total_attacks,
        "success_attacks":   success_attacks,
        "blocked_attacks":   blocked_attacks,
        "avg_defence_score": round(avg_score, 1),
        "tactics":           tactics,
    })


@redteam_bp.route("/api/redteam/techniques", methods=["GET"])
@jwt_required()
def list_techniques():
    """All available attack techniques."""
    return jsonify({"techniques": ATTACK_TECHNIQUES})
