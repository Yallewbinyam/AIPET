"""
AIPET X — Web Push Dispatcher (Capability 12)

Sends push notifications to all active browser subscriptions for a user.
NEVER raises — caller (automated_response) must not break if push fails.
"""
from __future__ import annotations

import json
import logging
import os
import time as _time
from datetime import datetime, timezone

_LOG = logging.getLogger("aipet.push_notifications")

# Max consecutive failures before auto-disabling a subscription
_MAX_FAILURES = 5

# Module-level import so patch('...dispatcher.webpush') works in tests
try:
    from pywebpush import webpush, WebPushException
except ImportError:  # pragma: no cover
    webpush = None  # type: ignore
    WebPushException = Exception  # type: ignore


def send_web_push(
    user_id: int,
    title:   str,
    body:    str,
    severity: str = "high",
    tag:      str | None = None,
    url:      str = "/",
) -> dict:
    """
    Send a web push to all enabled subscriptions for user_id.

    Returns {attempted, succeeded, failed, disabled} — never raises.
    Subscriptions returning HTTP 410 (Gone) are auto-disabled.
    Subscriptions with failure_count >= _MAX_FAILURES are auto-disabled.
    """
    result = {"attempted": 0, "succeeded": 0, "failed": 0, "disabled": 0}

    try:
        from dashboard.backend.models import db
        from dashboard.backend.push_notifications.models import PushSubscription

        if webpush is None:
            _LOG.warning("send_web_push: pywebpush not installed")
            return result

        subs = PushSubscription.query.filter_by(user_id=user_id, enabled=True).all()
        if not subs:
            return result

        private_key = os.environ.get("VAPID_PRIVATE_KEY", "")
        subject     = os.environ.get("VAPID_SUBJECT", "mailto:admin@aipet.io")

        if not private_key:
            _LOG.warning("send_web_push: VAPID_PRIVATE_KEY not set — skipping")
            return result

        # Restore actual newlines if .env stored them as \n literals
        if "\\n" in private_key:
            private_key = private_key.replace("\\n", "\n")

        vapid_claims = {
            "sub": subject,
            "exp": int(_time.time()) + 12 * 3600,
        }

        payload = json.dumps({
            "title":    title,
            "body":     body,
            "icon":     "/icons/icon-192.png",
            "badge":    "/icons/icon-72.png",
            "tag":      tag or f"aipet-{severity}",
            "url":      url,
            "critical": severity == "critical",
        })

        now = datetime.now(timezone.utc)

        for sub in subs:
            result["attempted"] += 1
            try:
                webpush(
                    subscription_info={
                        "endpoint": sub.endpoint,
                        "keys": {
                            "p256dh": sub.p256dh_key,
                            "auth":   sub.auth_secret,
                        },
                    },
                    data=payload,
                    vapid_private_key=private_key,
                    vapid_claims=vapid_claims,
                    content_encoding="aes128gcm",
                    timeout=10,
                )
                sub.last_sent_at  = now
                sub.failure_count = 0
                result["succeeded"] += 1

            except WebPushException as wpe:
                status = getattr(wpe.response, "status_code", None) if wpe.response else None
                if status == 410:
                    # Subscription expired — browser revoked it
                    sub.enabled         = False
                    sub.last_failure_at = now
                    result["disabled"] += 1
                    _LOG.info("send_web_push: subscription %d disabled (410 Gone)", sub.id)
                else:
                    sub.failure_count   += 1
                    sub.last_failure_at  = now
                    if sub.failure_count >= _MAX_FAILURES:
                        sub.enabled      = False
                        result["disabled"] += 1
                        _LOG.warning(
                            "send_web_push: subscription %d disabled after %d failures",
                            sub.id, sub.failure_count,
                        )
                    result["failed"] += 1
                    _LOG.warning(
                        "send_web_push: WebPushException for sub %d status=%s: %s",
                        sub.id, status, str(wpe)[:200],
                    )

            except Exception:
                sub.failure_count   += 1
                sub.last_failure_at  = now
                if sub.failure_count >= _MAX_FAILURES:
                    sub.enabled      = False
                    result["disabled"] += 1
                result["failed"] += 1
                _LOG.exception("send_web_push: unexpected error for sub %d", sub.id)

        try:
            db.session.commit()
        except Exception:
            _LOG.exception("send_web_push: failed to commit subscription updates")
            try:
                db.session.rollback()
            except Exception:
                pass

    except Exception:
        _LOG.exception("send_web_push: top-level error (non-fatal)")

    return result
