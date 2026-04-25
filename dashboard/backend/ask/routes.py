"""
AIPET Ask — Natural Language Security Assistant Routes

Endpoints:
    POST /api/ask          — Ask a security question (Pro/Enterprise)
    GET  /api/ask/context  — Inspect the current security context (debug)
    GET  /api/ask/usage    — Current user's today usage and remaining quota
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.ask.context import build_context
from dashboard.backend.explain.claude_client import generate_explanation
from dashboard.backend.ask.usage import (
    check_daily_limit,
    check_and_record_usage,
    get_today_usage,
    DAILY_LIMITS,
)

ask_bp = Blueprint("ask", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]

SYSTEM_PROMPT = """You are AIPET Ask — an expert IoT security advisor embedded inside the AIPET security platform.

You have been given a complete security context report about this specific organisation's network. This report contains:
- Their actual scan findings and vulnerabilities (from both legacy scanner and nmap-based scanner)
- Their device inventory with business functions
- Their financial risk exposure in pounds
- Active CVE alerts matching their devices
- ML anomaly detections (Isolation Forest) and behavioral Z-score deviations
- CISA KEV actively-exploited CVE catalog and OTX threat intelligence IOC counts
- MITRE ATT&CK technique mappings from real detections
- Unified device risk scores (0-100 scale with 8-hour time-decay)
- Recent security events from the unified event feed
- Any automated responses that fired in the last 24 hours
- Network monitoring status and remediation progress

Your role is to answer security questions using ONLY the data in this context. Do not make up data. Do not use generic examples. Always refer to the specific devices, findings, and numbers from the context.

Rules:
- Always give specific, actionable answers using the actual data provided
- When recommending fixes, reference the specific device IP and vulnerability name
- When discussing financial risk, use the exact pound figures from the context
- When discussing attack paths, reference the actual IPs and target functions
- When discussing risk scores, explain what's driving the high score (which modules contribute)
- Keep answers concise and direct — maximum 3 paragraphs unless a report is requested
- Write in plain English — no technical jargon unless the user specifically asks
- If asked to write a report, format it professionally with clear sections
- If the context does not contain information to answer a question, say so clearly

You are talking to a security professional or business decision-maker. Be direct, specific, and helpful."""


@ask_bp.route("/api/ask", methods=["POST"])
@jwt_required()
def ask_question():
    """
    Ask a security question. Returns Claude's answer with full security context.

    Request body:
    {
        "question": "What should I fix first this week?",
        "history": [
            {"role": "user",      "content": "Previous question"},
            {"role": "assistant", "content": "Previous answer"}
        ]
    }

    Multi-turn conversations are supported via the history array (last 10 kept).
    Access: Professional and Enterprise plans only.
    Daily limits: Professional 50 / day, Enterprise 500 / day.
    """
    from dashboard.backend.models import User

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.plan not in ALLOWED_PLANS:
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Ask is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    # ── Daily quota pre-check ────────────────────────────────────────────────
    limit_status = check_daily_limit(current_user_id, user.plan)
    if not limit_status["allowed"]:
        return jsonify({
            "error":     "Daily query limit reached",
            "limit":     limit_status["limit"],
            "used":      limit_status["used"],
            "resets_at": limit_status["resets_at"],
        }), 429

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    question = data.get("question", "").strip()
    history  = data.get("history", [])

    if not question:
        return jsonify({"error": "Question is required"}), 400
    if len(question) > 2000:
        return jsonify({"error": "Question too long. Maximum 2000 characters."}), 400

    # Build the security context for this user
    security_context = build_context(current_user_id, None)

    # Compose the user message — context first, then conversation history, then question
    context_prefix = (
        f"Here is the complete security context for this organisation:\n\n"
        f"{security_context}\n\n"
        f"Please use this data to answer all questions in this conversation."
    )

    # Build full prompt (with history stitched in) for generate_explanation
    full_prompt = context_prefix + "\n\n"

    if history:
        full_prompt += "CONVERSATION HISTORY:\n"
        for msg in history[-10:]:
            role    = msg.get("role", "user").upper()
            content = msg.get("content", "")
            if role in ("USER", "ASSISTANT") and content:
                full_prompt += f"{role}: {content}\n\n"

    full_prompt += f"USER QUESTION: {question}\n\nAIPET Ask response:"

    # ── Call Claude API ───────────────────────────────────────────────────────
    result = generate_explanation(full_prompt, max_tokens=1200,
                                  system_prompt=SYSTEM_PROMPT)

    if not result["success"]:
        return jsonify({
            "error":   "Failed to generate answer",
            "details": result.get("error", "Unknown error"),
        }), 500

    # ── Record usage after successful call ────────────────────────────────────
    usage = check_and_record_usage(
        user_id       = current_user_id,
        plan          = user.plan,
        input_tokens  = result.get("input_tokens", 0),
        output_tokens = result.get("tokens_used", 0),
    )

    return jsonify({
        "answer":      result["content"],
        "tokens_used": result.get("tokens_used", 0),
        "model":       result["model"],
        "usage": {
            "queries_today": usage.get("query_count", 1),
            "limit":         usage.get("limit", DAILY_LIMITS.get(user.plan, 0)),
            "remaining":     usage.get("remaining", 0),
        },
    }), 200


@ask_bp.route("/api/ask/context", methods=["GET"])
@jwt_required()
def get_context():
    """
    Returns the current security context for the user.
    Useful for debugging and showing users what AIPET Ask knows.
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.plan not in ALLOWED_PLANS:
        return jsonify({
            "error":   "Plan upgrade required",
            "message": "AIPET Ask is available on Professional and Enterprise plans.",
            "upgrade": True
        }), 403

    context = build_context(current_user_id, None)
    return jsonify({"context": context}), 200


@ask_bp.route("/api/ask/usage", methods=["GET"])
@jwt_required()
def ask_usage():
    """
    Returns today's query usage and remaining quota for the current user.
    Available to all authenticated users (not plan-gated — so Free users can
    see they need to upgrade).
    """
    from dashboard.backend.models import User
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    today_usage = get_today_usage(current_user_id)
    limit       = DAILY_LIMITS.get(user.plan, 0)
    used        = today_usage["query_count"]
    remaining   = max(0, limit - used)

    from dashboard.backend.ask.usage import _midnight_utc_iso
    return jsonify({
        "plan":          user.plan,
        "limit":         limit,
        "used":          used,
        "remaining":     remaining,
        "resets_at":     _midnight_utc_iso(),
        "input_tokens":  today_usage["input_tokens"],
        "output_tokens": today_usage["output_tokens"],
        "access":        user.plan in ALLOWED_PLANS,
    }), 200
