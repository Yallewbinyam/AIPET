"""
AIPET X — AI SOC Routes

Endpoints:
  POST /api/aisoc/chat           — SOC analyst chat (Claude API)
  POST /api/aisoc/shift-report   — generate end-of-shift report
  POST /api/aisoc/assess         — threat assessment for specific target
  GET  /api/aisoc/stats          — SOC metrics
"""
import os
import json
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.aisoc.context import build_soc_context

aisoc_bp = Blueprint("aisoc", __name__)

# Claude API endpoint — same as used by AIPET Ask
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-opus-4-5"


def _call_claude(system_prompt, messages, max_tokens=1500):
    """
    Call the Claude API with a system prompt and message history.
    Returns (content_text, tokens_used) or raises on failure.

    Uses the same ANTHROPIC_API_KEY as AIPET Ask and Explain.
    """
    import urllib.request
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set in environment")

    payload = json.dumps({
        "model":      CLAUDE_MODEL,
        "max_tokens": max_tokens,
        "system":     system_prompt,
        "messages":   messages,
    }).encode("utf-8")

    req = urllib.request.Request(
        CLAUDE_API_URL,
        data    = payload,
        headers = {
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        method = "POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data         = json.loads(resp.read().decode("utf-8"))
        content      = data["content"][0]["text"]
        tokens_used  = data.get("usage", {}).get("output_tokens", 0)
        return content, tokens_used


def _soc_system_prompt(context):
    """
    Build the AI SOC system prompt.
    Combines the static analyst persona with the live security context.

    The prompt instructs Claude to behave as an experienced SOC analyst
    who has direct visibility into the AIPET X security platform.
    """
    return f"""You are AIPET SOC — an expert AI Security Operations Centre analyst
with deep knowledge of IoT security, threat hunting, incident response,
and the MITRE ATT&CK framework.

You have real-time visibility into the AIPET X security platform.
Below is the current security posture snapshot — use this data to
answer questions, investigate incidents, and provide actionable guidance.

{context}

Your communication style:
- Direct and decisive — SOC analysts need clear answers
- Always cite specific evidence from the context (device IPs, event titles, CVE IDs)
- Prioritise by business impact and exploitability
- Use MITRE ATT&CK technique IDs where relevant
- Structure responses with clear sections when answering complex questions
- Never speculate beyond what the data shows — say so if data is insufficient

You can:
- Answer questions about current threats and incidents
- Recommend immediate response actions
- Explain why devices were quarantined or flagged
- Generate shift reports and executive briefings
- Guide analysts through investigation steps
- Suggest playbook improvements
- Assess risk for specific devices or IPs"""


@aisoc_bp.route("/api/aisoc/chat", methods=["POST"])
@jwt_required()
def soc_chat():
    """
    Main SOC analyst chat endpoint.

    Accepts a conversation history (list of role/content pairs)
    so the analyst can have a multi-turn investigation session.

    The live security context is rebuilt on every call to ensure
    Claude always has the most current data.
    """
    data     = request.get_json(silent=True) or {}
    messages = data.get("messages", [])

    if not messages:
        return jsonify({"error": "messages array required"}), 400

    # Validate message format
    for msg in messages:
        if msg.get("role") not in ("user", "assistant"):
            return jsonify({"error": "Each message needs role: user|assistant"}), 400
        if not msg.get("content"):
            return jsonify({"error": "Each message needs content"}), 400

    # Build fresh context snapshot for this request
    try:
        context = build_soc_context()
    except Exception as e:
        context = f"Context unavailable: {str(e)}"

    system_prompt = _soc_system_prompt(context)

    try:
        content, tokens = _call_claude(system_prompt, messages, max_tokens=1500)
        return jsonify({
            "content":     content,
            "tokens_used": tokens,
            "success":     True,
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@aisoc_bp.route("/api/aisoc/shift-report", methods=["POST"])
@jwt_required()
def shift_report():
    """
    Generate an end-of-shift SOC report.

    Produces a structured report covering:
    - Executive summary of security posture
    - Key incidents and their current status
    - Autonomous actions taken this shift
    - Devices requiring immediate attention
    - Recommended actions for next shift

    Useful for shift handovers and management reporting.
    """
    data       = request.get_json(silent=True) or {}
    shift_name = data.get("shift", "Day Shift")

    try:
        context = build_soc_context()
    except Exception as e:
        context = f"Context unavailable: {str(e)}"

    system_prompt = _soc_system_prompt(context)

    prompt = f"""Generate a professional end-of-shift SOC report for: {shift_name}

Structure the report with these exact sections:

1. EXECUTIVE SUMMARY
   One paragraph — overall security posture, key numbers, risk level

2. INCIDENTS THIS SHIFT
   List all open/investigating incidents with severity and status

3. CRITICAL DEVICE STATUS
   Any quarantined or restricted devices with trust scores and reasons

4. THREAT INTELLIGENCE HIGHLIGHTS
   Any IOC matches, blocked IPs, or new threat indicators

5. AUTONOMOUS DEFENSE ACTIVITY
   Playbooks triggered, devices quarantined, actions taken

6. IMMEDIATE ACTIONS REQUIRED
   Top 3 things the incoming shift must do first

7. WATCH LIST
   Devices or IPs to monitor closely next shift

Keep each section concise. Use bullet points within sections.
This report will be read by both technical analysts and management."""

    try:
        content, tokens = _call_claude(
            system_prompt,
            [{"role": "user", "content": prompt}],
            max_tokens = 2000,
        )
        return jsonify({
            "report":      content,
            "shift":       shift_name,
            "generated_at":str(datetime.now(timezone.utc)),
            "tokens_used": tokens,
            "success":     True,
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@aisoc_bp.route("/api/aisoc/assess", methods=["POST"])
@jwt_required()
def threat_assess():
    """
    Generate a focused threat assessment for a specific target.

    Input: target IP address or incident title
    Output: structured assessment with risk rating,
            attack chain analysis, and recommended response

    Used when an analyst wants deep analysis of a specific device
    or incident rather than a general overview.
    """
    data   = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "target required (IP or incident title)"}), 400

    try:
        context = build_soc_context()
    except Exception as e:
        context = f"Context unavailable: {str(e)}"

    system_prompt = _soc_system_prompt(context)

    prompt = f"""Perform a focused threat assessment for: {target}

Provide:

RISK RATING: [Critical/High/Medium/Low] — one line justification

CURRENT STATUS:
What do we know about this target right now from the security data?

ATTACK CHAIN ANALYSIS:
Based on the findings and events, what is the likely attack progression?
Map to MITRE ATT&CK techniques where possible.

BUSINESS IMPACT:
What could an attacker do if this target is fully compromised?

IMMEDIATE RESPONSE:
Step-by-step actions the analyst should take right now (numbered list)

CONTAINMENT:
Has autonomous defense already acted? What else needs to happen?

Be specific — reference actual event titles, finding names, and device IPs from the context."""

    try:
        content, tokens = _call_claude(
            system_prompt,
            [{"role": "user", "content": prompt}],
            max_tokens = 1500,
        )
        return jsonify({
            "assessment":  content,
            "target":      target,
            "tokens_used": tokens,
            "success":     True,
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@aisoc_bp.route("/api/aisoc/stats", methods=["GET"])
@jwt_required()
def aisoc_stats():
    """
    SOC metrics for the page header.
    Aggregates key numbers from all AIPET X modules.
    """
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)

    stats = {
        "open_incidents":   0,
        "critical_events":  0,
        "quarantined":      0,
        "actions_today":    0,
        "threat_matches":   0,
        "active_playbooks": 0,
    }

    try:
        from dashboard.backend.siem.models import SiemEvent, SiemIncident
        stats["open_incidents"]  = SiemIncident.query.filter_by(status="open").count()
        stats["critical_events"] = SiemEvent.query.filter(
            SiemEvent.created_at >= today,
            SiemEvent.severity == "Critical").count()
    except Exception:
        pass

    try:
        from dashboard.backend.zerotrust.models import ZtDeviceTrust
        stats["quarantined"] = ZtDeviceTrust.query.filter_by(
            status="quarantined").count()
    except Exception:
        pass

    try:
        from dashboard.backend.defense.models import DefenseAction, DefensePlaybook
        stats["actions_today"]    = DefenseAction.query.filter(
            DefenseAction.created_at >= today).count()
        stats["active_playbooks"] = DefensePlaybook.query.filter_by(
            enabled=True).count()
    except Exception:
        pass

    try:
        from dashboard.backend.threatintel.models import ThreatMatch
        stats["threat_matches"] = ThreatMatch.query.filter(
            ThreatMatch.created_at >= today).count()
    except Exception:
        pass

    return jsonify(stats)
