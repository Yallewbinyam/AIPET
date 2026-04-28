# =============================================================
# AIPET X -- Sentry initialisation (PLB-5)
#
# init_sentry() is called once from dashboard/backend/app_cloud.py
# at module import time (BEFORE any framework code runs). Safe to
# call when SENTRY_DSN is unset -- the function logs a single info
# line and returns without initialising the SDK.
#
# Hard rules (PLB-5):
#   * No raw API keys, JWTs, passwords, or `aipet_...` agent keys
#     ever leave this process. Every event passes through
#     `_before_send` which scrubs known-shape secrets to "[Filtered]".
#   * `send_default_pii=False` so the SDK does not auto-attach user
#     IPs / cookies / authorization headers.
#   * `traces_sample_rate=0.1` so production cost is bounded.
#     `profiles_sample_rate=0.0` because profiling is a separate
#     feature, opt-in later.
# =============================================================

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Dict, Optional

log = logging.getLogger("aipet.observability.sentry")


# --- Secret scrubbing ----------------------------------------------------

# Header names we never want forwarded to Sentry, regardless of content.
_HEADER_DENYLIST = frozenset(
    h.lower() for h in (
        "authorization",
        "x-agent-key",
        "x-api-key",
        "cookie",
        "set-cookie",
        "x-csrf-token",
        "x-forwarded-authorization",
        "proxy-authorization",
    )
)

# Body keys (case-insensitive) that always become "[Filtered]"
_BODY_KEY_DENYLIST = frozenset(
    k.lower() for k in (
        "password",
        "current_password",
        "new_password",
        "old_password",
        "confirm_password",
        "secret",
        "client_secret",
        "api_key",
        "agent_key",
        "full_key",
        "private_key",
        "vapid_private_key",
        "stripe_secret_key",
        "anthropic_api_key",
        "otx_api_key",
        "sentry_dsn",
        "jwt",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "session_key",
        # PLB-4: SMTP credentials. Exact-match on these keys covers
        # the common cases where an exception or breadcrumb stuffs
        # MAIL_PASSWORD / SMTP_PASSWORD / etc. into the payload.
        # smtp_user is also denylisted because exposing the username
        # in error messages narrows an attacker's target list.
        "smtp_password",
        "mail_password",
        "smtp_user",
        "mail_username",
    )
)

# Patterns that look like secrets even when the surrounding key name is
# innocent. Tuple-of-(regex, label) so logs can show what type of secret
# was scrubbed without the value itself.
_SECRET_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    # Aipet agent keys: aipet_<urlsafe-base64-ish>
    (re.compile(r"\baipet_[A-Za-z0-9_-]{20,}\b"), "[Filtered:aipet_key]"),
    # JWT tokens: 3 base64url segments separated by '.'  Conservative
    # match: minimum 20 chars per segment to avoid false positives.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b"), "[Filtered:jwt]"),
    # Sentry DSNs: https://<hex public key>@o<digits>.ingest.<...>.sentry.io/<digits>
    # Real DSNs are typically 32 hex but the SDK accepts wider ranges; be
    # permissive but require enough length to avoid false positives.
    (re.compile(r"https://[a-f0-9]{16,64}@[A-Za-z0-9.-]+\.sentry\.io/\d+"), "[Filtered:sentry_dsn]"),
    # Stripe secret keys: sk_live_... / sk_test_...
    (re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "[Filtered:stripe_sk]"),
    # OpenAI / Anthropic keys: sk-... / sk-ant-...
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b"), "[Filtered:llm_key]"),
    # Generic Postgres URI with embedded password
    (re.compile(r"\b(postgres(?:ql)?://[^:]+:)[^@/\s]+(@)"), r"\1[Filtered:db_password]\2"),
)

_FILTERED = "[Filtered]"


def _scrub_str(value: str) -> str:
    """Replace any inline-secret patterns inside a free-form string."""
    out = value
    for pat, label in _SECRET_PATTERNS:
        out = pat.sub(label, out)
    return out


def _scrub_value(key: Optional[str], value: Any) -> Any:
    """Recursively scrub a value. Strings are pattern-scrubbed; dicts
    by key denylist; lists element-wise."""
    if isinstance(value, str):
        return _scrub_str(value)
    if isinstance(value, dict):
        return _scrub_dict(value)
    if isinstance(value, list):
        return [_scrub_value(None, v) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(None, v) for v in value)
    return value


def _scrub_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Walk a dict; replace denylisted keys with `_FILTERED`, recurse otherwise."""
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(k, str) and k.lower() in _BODY_KEY_DENYLIST:
            out[k] = _FILTERED
            continue
        if isinstance(k, str) and k.lower() in _HEADER_DENYLIST:
            out[k] = _FILTERED
            continue
        out[k] = _scrub_value(k, v)
    return out


def _before_send(event: Dict[str, Any], hint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sentry-SDK before_send hook.
    Returns the event (mutated) or None to drop it.
    Never raises -- a hook exception would crash event delivery.
    """
    try:
        if "request" in event and isinstance(event["request"], dict):
            event["request"] = _scrub_dict(event["request"])
        if "extra" in event and isinstance(event["extra"], dict):
            event["extra"] = _scrub_dict(event["extra"])
        if "contexts" in event and isinstance(event["contexts"], dict):
            event["contexts"] = _scrub_dict(event["contexts"])
        if "breadcrumbs" in event:
            crumbs = event["breadcrumbs"]
            if isinstance(crumbs, dict) and "values" in crumbs:
                crumbs["values"] = [_scrub_dict(c) if isinstance(c, dict) else c
                                    for c in crumbs.get("values", [])]
        # Exception messages / values can contain raw secrets when
        # someone formats them into an exception string.
        if "exception" in event and isinstance(event["exception"], dict):
            for exc in event["exception"].get("values", []) or []:
                if isinstance(exc, dict) and "value" in exc and isinstance(exc["value"], str):
                    exc["value"] = _scrub_str(exc["value"])
        if "message" in event and isinstance(event["message"], str):
            event["message"] = _scrub_str(event["message"])
    except Exception as exc:
        # Fail open: if scrubbing crashes, drop the event rather than
        # ship something we couldn't scan. Better to lose telemetry
        # than to leak secrets.
        log.warning("Sentry before_send scrubbing crashed; dropping event: %s",
                    exc.__class__.__name__)
        return None
    return event


# --- Release detection ---------------------------------------------------

def _resolve_release() -> str:
    """
    Priority:
      1. APP_RELEASE env var (set by deploy pipeline)
      2. Short git SHA at process start
      3. "unknown"
    """
    env = os.environ.get("APP_RELEASE", "").strip()
    if env:
        return env
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if sha:
            return sha
    except Exception:
        pass
    return "unknown"


# --- Public init ---------------------------------------------------------

def init_sentry() -> bool:
    """
    Initialise sentry-sdk. Returns True if init happened, False if
    skipped (no DSN). Safe to call multiple times -- the SDK itself
    is idempotent on re-init.
    """
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        log.info("Sentry: SENTRY_DSN not set -- skipping init")
        return False

    # Lazy imports so the project can run on hosts where sentry_sdk
    # is not yet installed (the SDK is only required when DSN is set).
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

    integrations = [FlaskIntegration(), SqlalchemyIntegration()]
    try:
        from sentry_sdk.integrations.celery import CeleryIntegration
        integrations.append(CeleryIntegration())
    except Exception:
        # CeleryIntegration import shouldn't fail with celery installed,
        # but we keep this defensive so a broken celery dep can't break
        # error tracking.
        log.warning("Sentry: CeleryIntegration unavailable; skipping")

    environment = os.environ.get("FLASK_ENV", "development").strip() or "development"
    release = _resolve_release()

    sentry_sdk.init(
        dsn=dsn,
        integrations=integrations,
        environment=environment,
        release=release,
        # 10% of requests get a perf trace -- bounded production cost.
        traces_sample_rate=0.1,
        # Profiling is opt-in later; off for now.
        profiles_sample_rate=0.0,
        # Security platform: do NOT auto-ship user IPs / cookies /
        # Authorization headers. We curate what reaches Sentry.
        send_default_pii=False,
        before_send=_before_send,
    )

    # Use a redacted DSN in logs -- DSNs include a public key but
    # exposing them fully in logs is still poor hygiene.
    redacted = dsn[:14] + "..." + dsn[-12:] if len(dsn) > 30 else "[short DSN]"
    log.info("Sentry: initialised env=%s release=%s dsn=%s", environment, release, redacted)
    return True
