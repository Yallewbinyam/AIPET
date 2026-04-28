# =============================================================
# AIPET X -- Email backend wiring (PLB-4)
#
# init_email(app) is called once from dashboard/backend/app_cloud.py
# during create_app(). Reads SMTP_* env vars (the project's canonical
# names, not the Flask-Mail MAIL_USERNAME convention -- see
# CLAUDE.md). Sets:
#   * Flask config keys MAIL_* that Flask-Mail expects
#   * app.email_enabled = True / False so callers can pre-check
#     before attempting to send
#
# Hard rules (PLB-4):
#   * Skip-if-no-creds: if SMTP_HOST or SMTP_USER or SMTP_PASSWORD
#     is unset, the app loads identically -- email-sending paths
#     pre-check app.email_enabled and degrade gracefully (log a
#     warning, return success-with-no-mail to the caller for the
#     forgot-password path, return a 503-style error elsewhere).
#   * SMTP_PASSWORD never appears in logs / Sentry events / stack
#     traces. The Sentry before_send scrubber's body-key denylist
#     includes 'smtp_password' explicitly.
#
# Two-library project convention (Phase 0 recon, Decision 1A):
#   * Flask-Mail is used for app-flow emails: password reset
#     (auth/routes.py:forgot_password), enterprise PDF reports
#     (enterprise_reporting/routes.py).
#   * Raw smtplib is used for ops alerts
#     (monitoring/alerting.py:send_alert) where Flask app context
#     may not be available (Celery tasks, signal handlers).
#   Both share the same SMTP_* env vars. Future contributors who
#   want to introduce a third pattern: don't.
# =============================================================

from __future__ import annotations

import logging
import os


log = logging.getLogger("aipet.observability.email")


def _resolve_default_sender(smtp_user: str, from_name: str) -> str:
    """Build the From: header value. Format:
        "AIPET X Notifications <byallew@gmail.com>"
    Falls back to bare email if the display name is empty."""
    display = (from_name or "").strip()
    addr = (smtp_user or "noreply@aipet.io").strip()
    if display:
        return f"{display} <{addr}>"
    return addr


def init_email(app) -> bool:
    """
    Initialise Flask-Mail on the app and set app.email_enabled.

    Returns True if email is fully configured, False otherwise.
    Safe to call when env vars are missing -- the app loads
    identically and email-sending paths can pre-check the flag.
    """
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pw   = os.environ.get("SMTP_PASSWORD", "")
    from_name = os.environ.get("SMTP_FROM_NAME", "AIPET X Notifications").strip()

    # Flask-Mail config -- always set so the extension binds cleanly,
    # even when creds are unset. The runtime gate is app.email_enabled.
    app.config["MAIL_SERVER"]         = smtp_host
    app.config["MAIL_PORT"]           = smtp_port
    app.config["MAIL_USE_TLS"]        = True
    app.config["MAIL_USE_SSL"]        = False
    app.config["MAIL_USERNAME"]       = smtp_user
    app.config["MAIL_PASSWORD"]       = smtp_pw
    app.config["MAIL_DEFAULT_SENDER"] = _resolve_default_sender(smtp_user, from_name)

    # Flask-Mail bind. Safe to call even with empty creds -- the
    # Mail() instance just won't actually send anything.
    from flask_mail import Mail
    Mail(app)

    # The runtime gate: HOST is always present (we default to gmail);
    # USER and PASSWORD are the load-bearing checks.
    enabled = bool(smtp_user and smtp_pw)
    app.email_enabled = enabled

    if enabled:
        # Log only the host + user; never the password length / hash.
        log.warning(
            "Email: enabled -- host=%s port=%s user=%s sender=%s",
            smtp_host, smtp_port, smtp_user,
            app.config["MAIL_DEFAULT_SENDER"],
        )
    else:
        log.warning(
            "Email: DISABLED -- SMTP_USER and/or SMTP_PASSWORD not set in .env. "
            "Password reset, enterprise PDF email, and ops alerts will be no-ops "
            "until those vars are populated."
        )

    return enabled


def email_status(app) -> dict:
    """For ops introspection / health endpoints. Never returns the
    password; only the boolean enabled flag and the public config."""
    return {
        "enabled":         bool(getattr(app, "email_enabled", False)),
        "host":            app.config.get("MAIL_SERVER"),
        "port":            app.config.get("MAIL_PORT"),
        "user_configured": bool(app.config.get("MAIL_USERNAME")),
        "default_sender":  app.config.get("MAIL_DEFAULT_SENDER"),
    }
