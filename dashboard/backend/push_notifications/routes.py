"""
AIPET X — Push Notification Endpoints (Capability 12)

GET  /api/push/vapid-public-key   — returns VAPID public key (no auth needed)
POST /api/push/subscribe          — register a browser subscription
POST /api/push/unsubscribe        — remove a browser subscription
GET  /api/push/subscriptions      — list user's active subscriptions
POST /api/push/test               — send a test push to all user subscriptions
"""
import os
import re
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from dashboard.backend.models import db
from dashboard.backend.push_notifications.models import PushSubscription
from dashboard.backend.push_notifications.dispatcher import send_web_push
from dashboard.backend.validation import validate_body, optional, is_safe_string

push_bp = Blueprint("push_notifications", __name__)

# ── Validation helpers ───────────────────────────────────────────────────��────

_HTTPS_RE = re.compile(r'^https://.{4,}', re.ASCII)


def _is_https_url(v) -> bool:
    return isinstance(v, str) and bool(_HTTPS_RE.match(v)) and len(v) <= 2048


def _is_base64url(v) -> bool:
    if not isinstance(v, str) or not v:
        return False
    return bool(re.match(r'^[A-Za-z0-9+/=_\-]+$', v)) and len(v) <= 1024


SUBSCRIBE_SCHEMA = {
    "endpoint":     _is_https_url,
    "keys":         lambda v: isinstance(v, dict),
    "user_agent":   optional(lambda v: is_safe_string(v, 512)),
    "device_label": optional(lambda v: is_safe_string(v, 128)),
}

UNSUBSCRIBE_SCHEMA = {
    "endpoint": _is_https_url,
}


# ── Routes ────────────────────────────────────────────────────────────────────

@push_bp.route("/api/push/vapid-public-key", methods=["GET"])
def get_vapid_public_key():
    """Returns the VAPID public key — public by definition, no auth required."""
    pub = os.environ.get("VAPID_PUBLIC_KEY", "")
    if not pub:
        return jsonify({"error": "VAPID not configured"}), 503
    return jsonify({"public_key": pub}), 200


@push_bp.route("/api/push/subscribe", methods=["POST"])
@jwt_required()
@validate_body(SUBSCRIBE_SCHEMA)
def subscribe():
    """Upsert a browser push subscription for the current user."""
    uid  = int(get_jwt_identity())
    body = request.get_json()

    endpoint     = body["endpoint"]
    keys         = body.get("keys", {})
    p256dh       = keys.get("p256dh", "")
    auth_secret  = keys.get("auth", "")
    user_agent   = body.get("user_agent", "")[:512]
    device_label = body.get("device_label", "")[:128]

    if not _is_base64url(p256dh) or not _is_base64url(auth_secret):
        return jsonify({"error": "Invalid keys format"}), 400

    # Upsert by endpoint — a browser may re-subscribe with same endpoint
    sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if sub:
        if sub.user_id != uid:
            return jsonify({"error": "Endpoint belongs to another user"}), 403
        sub.p256dh_key   = p256dh
        sub.auth_secret  = auth_secret
        sub.user_agent   = user_agent or sub.user_agent
        sub.device_label = device_label or sub.device_label
        sub.enabled      = True
        sub.failure_count = 0
        created = False
    else:
        sub = PushSubscription(
            user_id      = uid,
            endpoint     = endpoint,
            p256dh_key   = p256dh,
            auth_secret  = auth_secret,
            user_agent   = user_agent,
            device_label = device_label or _label_from_ua(user_agent),
        )
        db.session.add(sub)
        created = True

    db.session.commit()
    return jsonify({"status": "ok", "created": created, "id": sub.id}), 201 if created else 200


@push_bp.route("/api/push/unsubscribe", methods=["POST"])
@jwt_required()
@validate_body(UNSUBSCRIBE_SCHEMA)
def unsubscribe():
    """Mark a subscription disabled (soft delete)."""
    uid      = int(get_jwt_identity())
    endpoint = request.get_json()["endpoint"]

    sub = PushSubscription.query.filter_by(endpoint=endpoint, user_id=uid).first()
    if not sub:
        return jsonify({"error": "Subscription not found"}), 404

    sub.enabled = False
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@push_bp.route("/api/push/subscriptions", methods=["GET"])
@jwt_required()
def list_subscriptions():
    """List the current user's active subscriptions (no key material returned)."""
    uid  = int(get_jwt_identity())
    subs = PushSubscription.query.filter_by(user_id=uid, enabled=True).order_by(
        PushSubscription.created_at.desc()
    ).all()
    return jsonify({"subscriptions": [s.to_safe_dict() for s in subs]}), 200


@push_bp.route("/api/push/test", methods=["POST"])
@jwt_required()
def test_push():
    """Send a test notification to all active subscriptions for the current user."""
    uid = int(get_jwt_identity())
    result = send_web_push(
        user_id  = uid,
        title    = "AIPET X — Test Notification",
        body     = "Push notifications are working. You will receive emergency alerts here.",
        severity = "info",
        tag      = "aipet-test",
        url      = "/",
    )
    return jsonify({
        "status":    "ok",
        "sent":      result["succeeded"],
        "failed":    result["failed"],
        "attempted": result["attempted"],
    }), 200


# ── Helpers ───────────────────────────────────────────────────────────────────

def _label_from_ua(ua: str) -> str:
    if not ua:
        return "Browser"
    ua = ua.lower()
    if "iphone" in ua:  return "iPhone"
    if "ipad"   in ua:  return "iPad"
    if "android" in ua: return "Android device"
    if "mac"    in ua:  return "Mac browser"
    if "windows" in ua: return "Windows browser"
    return "Browser"
