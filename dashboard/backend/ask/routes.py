"""
AIPET Ask — Natural Language Security Assistant Routes
Handles the AI-powered question and answer endpoint.

Endpoints:
    POST /api/ask          — Ask a security question
    GET  /api/ask/context  — Get the current security context (for debugging)
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.ask.context import build_context
from dashboard.backend.explain.claude_client import generate_explanation

ask_bp = Blueprint("ask", __name__)

ALLOWED_PLANS = ["professional", "enterprise"]

SYSTEM_PROMPT = """You are AIPET Ask — an expert IoT security advisor embedded inside the AIPET security platform.

You have been given a complete security context report about this specific organisation's network. This report contains:
- Their actual scan findings and vulnerabilities
- Their device inventory with business functions
- Their financial risk exposure in pounds
- Active CVE alerts matching their devices
- Network monitoring status
- Attack paths through their network
- Remediation progress

Your role is to answer security questions using ONLY the data in this context. Do not make up data. Do not use generic examples. Always refer to the specific devices, findings, and numbers from the context.

Rules:
- Always give specific, actionable answers using the actual data provided
- When recommending fixes, reference the specific device IP and vulnerability name
- When discussing financial risk, use the exact pound figures from the context
- When discussing attack paths, reference the actual IPs and target functions
- Keep answers concise and direct — maximum 3 paragraphs unless a report is requested
- Write in plain English — no technical jargon unless the user specifically asks
- If asked to write a report, format it professionally with clear sections
- If the context does not contain information to answer a question, say so clearly

You are talking to a security professional or business decision-maker. Be direct, specific, and helpful."""


@ask_bp.route("/api/ask", methods=["POST"])
@jwt_required()
def ask_question():
    """
    Processes a security question using Claude AI with full security context.

    Request body:
    {
        "question": "What should I fix first this week?",
        "history": [
            {"role": "user",      "content": "Previous question"},
            {"role": "assistant", "content": "Previous answer"}
        ]
    }

    The history allows multi-turn conversations where follow-up
    questions reference previous answers correctly.

    Access: Professional and Enterprise plans only.
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

    # Build the full prompt with context + history + question
    # We inject the context as the first user message for compatibility
    context_message = f"""Here is the complete security context for this organisation:

{security_context}

Please use this data to answer all questions in this conversation."""

    # Build messages array for Claude
    messages = []

    # Add context as first exchange
    messages.append({"role": "user",      "content": context_message})
    messages.append({"role": "assistant", "content": "I have reviewed the complete security context for this organisation. I can see the scan findings, device inventory, financial risk exposure, CVE alerts, network monitoring status, attack paths, and remediation progress. I am ready to answer your security questions using this specific data."})

    # Add conversation history (limit to last 10 exchanges to avoid token limits)
    for msg in history[-10:]:
        role    = msg.get("role", "user")
        content = msg.get("content", "")
        if role in ["user", "assistant"] and content:
            messages.append({"role": role, "content": content})

    # Add the current question
    messages.append({"role": "user", "content": question})

    # Build the full prompt for our existing generate_explanation function
    # We need to adapt it to support multi-turn — build a single prompt
    full_prompt = f"""SYSTEM: {SYSTEM_PROMPT}

SECURITY CONTEXT:
{security_context}

"""
    # Add conversation history to prompt
    if history:
        full_prompt += "CONVERSATION HISTORY:\n"
        for msg in history[-6:]:
            role    = msg.get("role", "user").upper()
            content = msg.get("content", "")
            full_prompt += f"{role}: {content}\n\n"

    full_prompt += f"USER QUESTION: {question}\n\nAIPET Ask response:"

    # Call Claude API
    result = generate_explanation(full_prompt, max_tokens=1000)

    if not result["success"]:
        return jsonify({
            "error":   "Failed to generate answer",
            "details": result.get("error", "Unknown error")
        }), 500

    return jsonify({
        "answer":      result["content"],
        "tokens_used": result["tokens_used"],
        "model":       result["model"],
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