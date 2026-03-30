# =============================================================
# AIPET Cloud — Error Alerting
# Sends email alerts when critical errors occur.
# Import and use in any part of the application.
# =============================================================

import os
import smtplib
import traceback
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ── Configuration ─────────────────────────────────────────────
# Set these in your .env file
ALERT_EMAIL   = os.environ.get("ALERT_EMAIL",   "")
SMTP_HOST     = os.environ.get("SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER",     "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Only send alerts for these severity levels
ALERT_LEVELS  = {"CRITICAL", "ERROR"}


# ── Core send function ─────────────────────────────────────────
def send_alert(subject, body, level="ERROR"):
    """
    Send an email alert.

    level: "ERROR" or "CRITICAL"

    If SMTP is not configured, the alert is just printed
    to the console — safe to use in development.
    """
    if level not in ALERT_LEVELS:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_body  = f"Time: {timestamp}\nLevel: {level}\n\n{body}"

    # Always print to console so it's visible in logs
    print(f"[ALERT] [{level}] {subject}")
    print(full_body)

    # Send email only if SMTP is configured
    if not all([ALERT_EMAIL, SMTP_USER, SMTP_PASSWORD]):
        print("[ALERT] Email skipped — SMTP not configured in .env")
        return

    try:
        msg            = MIMEMultipart()
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL
        msg["Subject"] = f"[AIPET {level}] {subject}"
        msg.attach(MIMEText(full_body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print(f"[ALERT] Email sent to {ALERT_EMAIL}")

    except Exception as e:
        print(f"[ALERT] Failed to send email: {e}")


# ── Specific alert helpers ─────────────────────────────────────
def alert_database_error(error):
    """Call this when the database connection fails."""
    send_alert(
        subject="Database connection failed",
        body=(
            f"AIPET database error:\n\n"
            f"{str(error)}\n\n"
            f"{traceback.format_exc()}"
        ),
        level="CRITICAL"
    )


def alert_payment_error(user_email, error):
    """Call this when a Stripe payment fails unexpectedly."""
    send_alert(
        subject=f"Payment error for {user_email}",
        body=(
            f"User: {user_email}\n\n"
            f"Error: {str(error)}\n\n"
            f"{traceback.format_exc()}"
        ),
        level="ERROR"
    )


def alert_webhook_error(event_type, error):
    """Call this when a Stripe webhook fails to process."""
    send_alert(
        subject=f"Webhook processing failed: {event_type}",
        body=(
            f"Event type: {event_type}\n\n"
            f"Error: {str(error)}\n\n"
            f"{traceback.format_exc()}"
        ),
        level="ERROR"
    )


def alert_unhandled_exception(request_path, user_id, error):
    """
    Call this for any unhandled exception in Flask.
    Gives you the URL, user, and full stack trace.
    """
    send_alert(
        subject=f"Unhandled exception at {request_path}",
        body=(
            f"URL: {request_path}\n"
            f"User ID: {user_id}\n\n"
            f"Error: {str(error)}\n\n"
            f"{traceback.format_exc()}"
        ),
        level="ERROR"
    )