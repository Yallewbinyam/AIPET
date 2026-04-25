# ============================================================
# AIPET X — Tests: Capability 10 — Ask AIPET
# ============================================================
import json
from datetime import date, datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest


# ── Fixtures / helpers ────────────────────────────────────────────────────────

def _fake_claude_result(content="This is a mock Claude answer.", input_tokens=100, output_tokens=50):
    return {
        "success":      True,
        "content":      content,
        "input_tokens": input_tokens,
        "tokens_used":  output_tokens,
        "model":        "claude-sonnet-4-20250514",
    }

def _reset_usage(flask_app, test_user, target_date=None):
    """Delete any usage row for test_user on target_date (default today)."""
    from dashboard.backend.ask.usage import AskUsageLog
    from dashboard.backend.models import db
    with flask_app.app_context():
        q = AskUsageLog.query.filter_by(user_id=test_user.id)
        if target_date:
            q = q.filter_by(date=target_date)
        q.delete()
        db.session.commit()


# ── Context builder tests ─────────────────────────────────────────────────────

def test_build_context_returns_string(flask_app, test_user):
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert isinstance(ctx, str)
    assert len(ctx) > 100


def test_build_context_includes_header(flask_app, test_user):
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert "AIPET SECURITY CONTEXT REPORT" in ctx


def test_build_context_includes_risk_scores_section(flask_app, test_user):
    """context.py must include the device_risk_scores section (Capability 9)."""
    from dashboard.backend.ask.context import build_context
    from dashboard.backend.risk_engine.models import DeviceRiskScore
    from dashboard.backend.models import db
    with flask_app.app_context():
        # Seed a risk score row so the section has data
        row = DeviceRiskScore.query.filter_by(user_id=test_user.id, entity="10.cap10.test").first()
        if not row:
            row = DeviceRiskScore(
                user_id=test_user.id, entity="10.cap10.test", entity_type="device",
                score=85, event_count_24h=3, contributing_modules=["ml_anomaly"],
                last_updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
                last_recomputed_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.session.add(row)
            db.session.commit()
        ctx = build_context(test_user.id, None)
    assert "DEVICE RISK SCORES" in ctx or "UNIFIED DEVICE RISK SCORES" in ctx


def test_build_context_includes_central_events_section(flask_app, test_user):
    """context.py must include the central_events section (Capability 7)."""
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert "SECURITY EVENTS" in ctx or "RECENT SECURITY EVENTS" in ctx


def test_build_context_includes_automated_responses_section(flask_app, test_user):
    """context.py must include the automated_response section (Capability 8)."""
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert "AUTOMATED RESPONSES" in ctx


def test_build_context_includes_kev_section(flask_app, test_user):
    """context.py must include the KEV actively-exploited section (Capability 5)."""
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert "KEV" in ctx


def test_build_context_includes_nmap_section(flask_app, test_user):
    """context.py must include the real_scan_results section (Phase 2 scanner)."""
    from dashboard.backend.ask.context import build_context
    with flask_app.app_context():
        ctx = build_context(test_user.id, None)
    assert "NMAP" in ctx


# ── /api/ask endpoint tests ───────────────────────────────────────────────────

def test_ask_endpoint_requires_auth(client):
    r = client.post("/api/ask", json={"question": "Hello"})
    assert r.status_code == 401


def test_ask_endpoint_returns_200_with_valid_question(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()):
        r = client.post("/api/ask", json={"question": "What is my top risk?"},
                        headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "answer" in data
    assert "usage" in data
    assert data["answer"] == "This is a mock Claude answer."


def test_ask_endpoint_passes_system_prompt_to_claude(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()) as mock_gen:
        client.post("/api/ask", json={"question": "Test"}, headers=auth_headers)
    call_kwargs = mock_gen.call_args
    # Verify system_prompt keyword arg is passed
    assert call_kwargs.kwargs.get("system_prompt") or (
        len(call_kwargs.args) >= 3 and call_kwargs.args[2]
    )


def test_ask_endpoint_rejects_empty_question(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()):
        r = client.post("/api/ask", json={"question": "   "}, headers=auth_headers)
    assert r.status_code == 400


def test_ask_endpoint_rejects_question_over_2000_chars(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    long_q = "x" * 2001
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()):
        r = client.post("/api/ask", json={"question": long_q}, headers=auth_headers)
    assert r.status_code == 400


def test_ask_endpoint_includes_history_in_prompt(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    history = [
        {"role": "user",      "content": "previous question"},
        {"role": "assistant", "content": "previous answer"},
    ]
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()) as mock_gen:
        client.post("/api/ask",
                    json={"question": "follow-up question", "history": history},
                    headers=auth_headers)
    call_prompt = mock_gen.call_args.args[0]
    assert "previous question" in call_prompt


def test_ask_endpoint_returns_500_when_claude_fails(client, auth_headers, flask_app, test_user):
    _reset_usage(flask_app, test_user)
    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value={"success": False, "error": "timeout", "content": None,
                             "input_tokens": 0, "tokens_used": 0}):
        r = client.post("/api/ask", json={"question": "test"}, headers=auth_headers)
    assert r.status_code == 500


# ── /api/ask/usage endpoint ───────────────────────────────────────────────────

def test_ask_usage_endpoint_requires_auth(client):
    r = client.get("/api/ask/usage")
    assert r.status_code == 401


def test_ask_usage_endpoint_returns_correct_fields(client, auth_headers):
    r = client.get("/api/ask/usage", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "plan"      in data
    assert "limit"     in data
    assert "used"      in data
    assert "remaining" in data
    assert "resets_at" in data


# ── Usage counter tests (the 4 from spec) ─────────────────────────────────────

def test_ask_usage_log_increments_on_successful_query(client, auth_headers, flask_app, test_user):
    """A successful /api/ask call must increment ask_usage_log.query_count by 1."""
    from dashboard.backend.ask.usage import AskUsageLog, _today_utc
    _reset_usage(flask_app, test_user)

    with flask_app.app_context():
        before = AskUsageLog.query.filter_by(
            user_id=test_user.id, date=_today_utc()
        ).first()
        before_count = before.query_count if before else 0

    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result(input_tokens=120, output_tokens=60)):
        r = client.post("/api/ask", json={"question": "Count test"},
                        headers=auth_headers)
    assert r.status_code == 200

    with flask_app.app_context():
        row = AskUsageLog.query.filter_by(
            user_id=test_user.id, date=_today_utc()
        ).first()
    assert row is not None
    assert row.query_count == before_count + 1
    assert row.total_input_tokens >= 120
    assert row.total_output_tokens >= 60


def test_ask_endpoint_returns_429_when_daily_limit_reached(client, auth_headers, flask_app, test_user):
    """When the user is at their daily limit, /api/ask must return 429."""
    from dashboard.backend.ask.usage import AskUsageLog, _today_utc, DAILY_LIMITS
    from dashboard.backend.models import db

    _reset_usage(flask_app, test_user)
    limit = DAILY_LIMITS.get(test_user.plan, 50)

    with flask_app.app_context():
        today = _today_utc()
        row = AskUsageLog(
            user_id=test_user.id, date=today,
            query_count=limit,           # already AT limit
            total_input_tokens=0, total_output_tokens=0,
        )
        db.session.add(row)
        db.session.commit()

    with patch("dashboard.backend.ask.routes.generate_explanation",
               return_value=_fake_claude_result()) as mock_gen:
        r = client.post("/api/ask", json={"question": "Over limit test"},
                        headers=auth_headers)

    # Claude must NOT be called when user is over limit
    mock_gen.assert_not_called()
    assert r.status_code == 429
    data = r.get_json()
    assert data["error"] == "Daily query limit reached"
    assert "resets_at" in data
    assert data["limit"] == limit
    assert data["used"]  == limit


def test_ask_usage_endpoint_returns_remaining_quota(client, auth_headers, flask_app, test_user):
    """GET /api/ask/usage should show correct remaining count after queries."""
    from dashboard.backend.ask.usage import AskUsageLog, _today_utc, DAILY_LIMITS
    from dashboard.backend.models import db

    _reset_usage(flask_app, test_user)
    limit = DAILY_LIMITS.get(test_user.plan, 50)

    with flask_app.app_context():
        today = _today_utc()
        row   = AskUsageLog(
            user_id=test_user.id, date=today,
            query_count=3, total_input_tokens=300, total_output_tokens=150,
        )
        db.session.add(row)
        db.session.commit()

    r = client.get("/api/ask/usage", headers=auth_headers)
    assert r.status_code == 200
    data = r.get_json()
    assert data["used"]      == 3
    assert data["limit"]     == limit
    assert data["remaining"] == limit - 3


def test_ask_usage_resets_at_midnight_utc(flask_app, test_user):
    """Yesterday's usage must NOT count against today's limit."""
    from dashboard.backend.ask.usage import (
        AskUsageLog, check_daily_limit, _today_utc, DAILY_LIMITS
    )
    from dashboard.backend.models import db

    yesterday = _today_utc() - timedelta(days=1)
    limit = DAILY_LIMITS.get(test_user.plan, 50)

    with flask_app.app_context():
        # Fill yesterday's row to the limit
        AskUsageLog.query.filter_by(user_id=test_user.id, date=yesterday).delete()
        old_row = AskUsageLog(
            user_id=test_user.id, date=yesterday,
            query_count=limit,          # yesterday was at limit
            total_input_tokens=0, total_output_tokens=0,
        )
        db.session.add(old_row)
        # Delete today's row so we start fresh
        AskUsageLog.query.filter_by(user_id=test_user.id, date=_today_utc()).delete()
        db.session.commit()

        # Today's limit check must return allowed=True (yesterday's count irrelevant)
        result = check_daily_limit(test_user.id, test_user.plan)

    assert result["allowed"] is True
    assert result["used"] == 0
    assert result["remaining"] == limit


# ── claude_client SDK tests ───────────────────────────────────────────────────

def test_claude_client_uses_anthropic_sdk(flask_app):
    """generate_explanation must use anthropic SDK, not urllib."""
    import inspect
    from dashboard.backend.explain import claude_client
    source = inspect.getsource(claude_client)
    assert "import anthropic" in source or "from anthropic" in source
    assert "urllib.request" not in source


def test_claude_client_uses_system_parameter(flask_app):
    """generate_explanation must pass system_prompt to the SDK's system field."""
    from dashboard.backend.explain.claude_client import generate_explanation

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="test answer")]
    mock_message.usage.input_tokens = 100
    mock_message.usage.output_tokens = 50

    with patch("dashboard.backend.explain.claude_client._get_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message
        mock_client_fn.return_value = mock_client

        generate_explanation("test prompt", system_prompt="You are an expert.")

    call_kwargs = mock_client.messages.create.call_args.kwargs
    assert "system" in call_kwargs
    assert call_kwargs["system"] == "You are an expert."


def test_claude_client_returns_input_tokens(flask_app):
    """generate_explanation must return input_tokens (new field for cost tracking)."""
    from dashboard.backend.explain.claude_client import generate_explanation

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="answer")]
    mock_message.usage.input_tokens = 123
    mock_message.usage.output_tokens = 45

    with patch("dashboard.backend.explain.claude_client._get_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message
        mock_client_fn.return_value = mock_client

        result = generate_explanation("test")

    assert result["input_tokens"] == 123
    assert result["tokens_used"]  == 45   # backward-compat key
    assert result["success"] is True


def test_claude_client_handles_api_error_gracefully(flask_app):
    """generate_explanation must return success=False on API error, never raise."""
    from dashboard.backend.explain.claude_client import generate_explanation

    with patch("dashboard.backend.explain.claude_client._get_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API unreachable")
        mock_client_fn.return_value = mock_client

        result = generate_explanation("test")

    assert result["success"] is False
    assert "error" in result
