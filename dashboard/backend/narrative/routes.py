"""
AIPET X — AI Risk Narrative Routes

Endpoints:
  POST /api/narrative/generate     — generate narrative
  GET  /api/narrative/history      — past narratives
  GET  /api/narrative/history/<id> — specific narrative
  DEL  /api/narrative/history/<id> — delete narrative
"""
import json, os, urllib.request
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.narrative.models import RiskNarrative

narrative_bp = Blueprint("narrative", __name__)

AUDIENCE_PROMPTS = {
    "executive": """You are a Chief Information Security Officer briefing the CEO.
Write a 3-paragraph executive risk narrative. Use plain English.
No technical jargon. Focus on business risk and financial impact.
Include: what the risk is, what could happen if unaddressed, what action is needed.
End with 3 prioritised action items.""",

    "board": """You are presenting to a board of directors who are not technical.
Write a 1-page board risk summary. Use analogies to make risks relatable.
Include: overall security posture (traffic light), top 3 risks in plain English,
regulatory implications, recommended investment. Keep it concise and decisive.""",

    "technical": """You are a senior security engineer briefing the SOC team.
Write a detailed technical risk briefing. Include: affected systems with IPs,
CVE IDs, CVSS scores, attack vectors, MITRE ATT&CK mappings, exploitation likelihood,
and specific technical remediation steps. Be precise and actionable.""",

    "compliance": """You are a compliance officer preparing a regulatory briefing.
Write a compliance-focused risk narrative. Map findings to NIS2, ISO 27001,
and OWASP IoT Top 10 controls. Identify compliance gaps, regulatory risk,
and required remediation timeline. Include audit trail recommendations.""",
}


@narrative_bp.route("/api/narrative/generate", methods=["POST"])
@jwt_required()
def generate_narrative():
    """
    Generate an AI risk narrative using Claude.
    Pulls real data from findings, scans, and devices.
    """
    from dashboard.backend.models import Finding, Scan, Device
    from sqlalchemy import func

    data     = request.get_json(silent=True) or {}
    audience = data.get("audience", "executive")
    if audience not in AUDIENCE_PROMPTS:
        return jsonify({"error": "Invalid audience"}), 400

    # Gather security context
    findings = Finding.query.order_by(
        Finding.cvss_score.desc()).limit(20).all()
    scans    = Scan.query.order_by(
        Scan.created_at.desc()).limit(5).all()
    devices  = Device.query.limit(20).all() if hasattr(Finding, "target") else []

    total_findings  = Finding.query.count()
    critical_count  = Finding.query.filter_by(severity="Critical").count()
    high_count      = Finding.query.filter_by(severity="High").count()
    medium_count    = Finding.query.filter_by(severity="Medium").count()
    unique_targets  = db.session.query(
        func.count(func.distinct(Finding.target))).scalar() or 0

    # Calculate risk score
    risk_score = min(100, (critical_count * 20 + high_count * 10 +
                           medium_count * 5))

    # Build context for Claude
    finding_summary = []
    for f in findings[:10]:
        finding_summary.append(
            f"- [{f.severity}] {f.name} on {f.target} "
            f"(CVSS: {f.cvss_score or 'N/A'})"
        )

    context = f"""SECURITY POSTURE SUMMARY
Overall Risk Score: {risk_score}/100
Total Findings: {total_findings}
  Critical: {critical_count}
  High:     {high_count}
  Medium:   {medium_count}
Affected Devices: {unique_targets}
Recent Scans: {len(scans)}

TOP FINDINGS:
{chr(10).join(finding_summary) if finding_summary else "No findings data available — using risk score context"}

PLATFORM: AIPET X IoT Security Platform
ORGANISATION TYPE: Enterprise IoT environment
"""

    system_prompt = AUDIENCE_PROMPTS[audience]
    user_prompt   = f"""Based on this security data, generate your risk narrative:

{context}

Generate the narrative now. Be specific about the risks.
If finding data is limited, base the narrative on the risk score
and provide general but actionable guidance."""

    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return jsonify({"error": "ANTHROPIC_API_KEY not configured"}), 500

        payload = json.dumps({
            "model":      "claude-opus-4-5",
            "max_tokens": 1500,
            "system":     system_prompt,
            "messages":   [{"role": "user", "content": user_prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            result      = json.loads(resp.read().decode("utf-8"))
            narrative   = result["content"][0]["text"]
            tokens_used = result.get("usage", {}).get("output_tokens", 0)

        # Save to history
        record = RiskNarrative(
            audience    = audience,
            narrative   = narrative,
            risk_score  = risk_score,
            findings    = total_findings,
            devices     = unique_targets,
            tokens_used = tokens_used,
            created_by  = int(get_jwt_identity()),
        )
        db.session.add(record)
        db.session.commit()

        return jsonify({
            "success":    True,
            "narrative":  narrative,
            "audience":   audience,
            "risk_score": risk_score,
            "findings":   total_findings,
            "devices":    unique_targets,
            "tokens_used":tokens_used,
            "id":         record.id,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@narrative_bp.route("/api/narrative/history", methods=["GET"])
@jwt_required()
def narrative_history():
    narratives = RiskNarrative.query.order_by(
        RiskNarrative.created_at.desc()).limit(20).all()
    return jsonify({"narratives": [n.to_dict() for n in narratives]})


@narrative_bp.route("/api/narrative/history/<int:nid>", methods=["GET"])
@jwt_required()
def get_narrative(nid):
    n = RiskNarrative.query.get_or_404(nid)
    return jsonify(n.to_dict())


@narrative_bp.route("/api/narrative/history/<int:nid>", methods=["DELETE"])
@jwt_required()
def delete_narrative(nid):
    n = RiskNarrative.query.get_or_404(nid)
    db.session.delete(n)
    db.session.commit()
    return jsonify({"success": True})
