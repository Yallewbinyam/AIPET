"""
AIPET X — Web Push / PWA Tests (Capability 12)

Follows the pattern established in test_ml_anomaly.py.
All pywebpush calls are mocked — no real push servers contacted.
"""
import json
from unittest.mock import patch, MagicMock

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

FAKE_ENDPOINT   = "https://push.example.com/sub/abc123"
FAKE_P256DH     = "BNFxFXBnFxFXBnFxFXBnFxFXBnFxFXBnFxFXBnFxFXBnFxFXBn=="
FAKE_AUTH       = "FXBnFxFXBnFxFQ=="

SUBSCRIBE_BODY  = {
    "endpoint":     FAKE_ENDPOINT,
    "keys":         {"p256dh": FAKE_P256DH, "auth": FAKE_AUTH},
    "user_agent":   "Mozilla/5.0 (Test)",
    "device_label": "Test Device",
}


def _sub_body(endpoint=FAKE_ENDPOINT):
    return {**SUBSCRIBE_BODY, "endpoint": endpoint}


# ── Subscription endpoint tests ───────────────────────────────────────────────

class TestSubscribeEndpoint:
    def test_subscribe_creates_subscription(self, client, auth_headers, flask_app):
        resp = client.post("/api/push/subscribe",
            data=json.dumps(SUBSCRIBE_BODY),
            headers=auth_headers)
        assert resp.status_code in (200, 201), resp.data
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["id"] is not None

    def test_subscribe_upserts_on_duplicate_endpoint(self, client, auth_headers, flask_app):
        resp1 = client.post("/api/push/subscribe",
            data=json.dumps(_sub_body("https://push.example.com/dup-sub")),
            headers=auth_headers)
        assert resp1.status_code in (200, 201)

        resp2 = client.post("/api/push/subscribe",
            data=json.dumps(_sub_body("https://push.example.com/dup-sub")),
            headers=auth_headers)
        assert resp2.status_code == 200
        assert resp2.get_json()["created"] is False

    def test_subscribe_rejects_non_https_endpoint(self, client, auth_headers):
        body = {**SUBSCRIBE_BODY, "endpoint": "http://insecure.example.com/sub"}
        resp = client.post("/api/push/subscribe",
            data=json.dumps(body), headers=auth_headers)
        assert resp.status_code == 422

    def test_subscribe_validates_missing_endpoint(self, client, auth_headers):
        body = {"keys": {"p256dh": FAKE_P256DH, "auth": FAKE_AUTH}}
        resp = client.post("/api/push/subscribe",
            data=json.dumps(body), headers=auth_headers)
        assert resp.status_code == 422

    def test_unsubscribe_marks_disabled(self, client, auth_headers, flask_app):
        endpoint = "https://push.example.com/to-disable"
        client.post("/api/push/subscribe",
            data=json.dumps(_sub_body(endpoint)), headers=auth_headers)
        resp = client.post("/api/push/unsubscribe",
            data=json.dumps({"endpoint": endpoint}),
            headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

        from dashboard.backend.push_notifications.models import PushSubscription
        with flask_app.app_context():
            sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
            assert sub is not None
            assert sub.enabled is False

    def test_unsubscribe_404_when_not_owned(self, client, auth_headers):
        resp = client.post("/api/push/unsubscribe",
            data=json.dumps({"endpoint": "https://push.example.com/nonexistent"}),
            headers=auth_headers)
        assert resp.status_code == 404

    def test_subscriptions_endpoint_user_scoped(self, client, auth_headers, test_user):
        resp = client.get("/api/push/subscriptions", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "subscriptions" in data
        # Keys must not appear in list
        for sub in data["subscriptions"]:
            assert "p256dh_key" not in sub
            assert "auth_secret" not in sub

    def test_vapid_public_key_no_auth_required(self, client, flask_app):
        import os
        with patch.dict(os.environ, {"VAPID_PUBLIC_KEY": "BTestPublicKey123"}):
            resp = client.get("/api/push/vapid-public-key")
        assert resp.status_code == 200
        assert "public_key" in resp.get_json()


# ── Dispatcher tests ──────────────────────────────────────────────────────────

class TestDispatcher:
    def test_send_web_push_returns_zero_when_no_subscriptions(self, flask_app):
        from dashboard.backend.push_notifications.dispatcher import send_web_push
        result = send_web_push(user_id=999999, title="T", body="B")
        assert result["attempted"] == 0
        assert result["succeeded"] == 0

    def test_send_web_push_calls_webpush_for_each_subscription(
            self, client, auth_headers, flask_app, test_user):
        endpoint = "https://push.example.com/dispatch-test"
        client.post("/api/push/subscribe",
            data=json.dumps(_sub_body(endpoint)), headers=auth_headers)

        mock_wp = MagicMock()
        import os
        with patch("dashboard.backend.push_notifications.dispatcher.webpush", mock_wp), \
             patch.dict(os.environ, {"VAPID_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"}):
            from dashboard.backend.push_notifications.dispatcher import send_web_push
            result = send_web_push(user_id=test_user.id, title="T", body="B")

        mock_wp.assert_called()
        assert result["attempted"] >= 1

    def test_send_web_push_handles_410_gone_marks_disabled(
            self, client, auth_headers, flask_app, test_user):
        from pywebpush import WebPushException

        endpoint = "https://push.example.com/gone-test"
        client.post("/api/push/subscribe",
            data=json.dumps(_sub_body(endpoint)), headers=auth_headers)

        mock_resp = MagicMock()
        mock_resp.status_code = 410
        exc = WebPushException("Gone", response=mock_resp)

        import os
        with patch("dashboard.backend.push_notifications.dispatcher.webpush", side_effect=exc), \
             patch.dict(os.environ, {"VAPID_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"}):
            from dashboard.backend.push_notifications.dispatcher import send_web_push
            result = send_web_push(user_id=test_user.id, title="T", body="B")

        from dashboard.backend.push_notifications.models import PushSubscription
        sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
        assert sub is None or sub.enabled is False
        assert result["disabled"] >= 1

    def test_send_web_push_increments_failure_count_on_other_errors(
            self, client, auth_headers, flask_app, test_user):
        from pywebpush import WebPushException

        endpoint = "https://push.example.com/fail-count-test"
        client.post("/api/push/subscribe",
            data=json.dumps(_sub_body(endpoint)), headers=auth_headers)

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        exc = WebPushException("Server Error", response=mock_resp)

        import os
        with patch("dashboard.backend.push_notifications.dispatcher.webpush", side_effect=exc), \
             patch.dict(os.environ, {"VAPID_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"}):
            from dashboard.backend.push_notifications.dispatcher import send_web_push
            result = send_web_push(user_id=test_user.id, title="T", body="B")

        from dashboard.backend.push_notifications.models import PushSubscription
        sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
        assert sub is not None
        assert sub.failure_count >= 1
        assert result["failed"] >= 1

    def test_send_web_push_disables_after_5_failures(
            self, client, auth_headers, flask_app, test_user):
        from pywebpush import WebPushException
        from dashboard.backend.push_notifications.models import PushSubscription
        from dashboard.backend.models import db

        endpoint = "https://push.example.com/max-fail-test"
        client.post("/api/push/subscribe",
            data=json.dumps(_sub_body(endpoint)), headers=auth_headers)

        sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
        sub.failure_count = 4  # one more will hit the limit
        db.session.commit()

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        exc = WebPushException("Error", response=mock_resp)

        import os
        with patch("dashboard.backend.push_notifications.dispatcher.webpush", side_effect=exc), \
             patch.dict(os.environ, {"VAPID_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"}):
            from dashboard.backend.push_notifications.dispatcher import send_web_push
            result = send_web_push(user_id=test_user.id, title="T", body="B")

        sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
        assert sub.enabled is False
        assert result["disabled"] >= 1

    def test_send_web_push_never_raises(self, flask_app, test_user):
        """Dispatcher must not propagate any exception to the caller."""
        import os
        with patch("dashboard.backend.push_notifications.dispatcher.webpush",
                   side_effect=RuntimeError("catastrophic")), \
             patch.dict(os.environ, {"VAPID_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"}):
            from dashboard.backend.push_notifications.dispatcher import send_web_push
            result = send_web_push(user_id=test_user.id, title="T", body="B")
        # Must return a dict, not raise
        assert isinstance(result, dict)


# ── Integration with automated_response ──────────────────────────────────────

def _get_or_create_playbook(db):
    from dashboard.backend.defense.models import DefensePlaybook
    pb = DefensePlaybook.query.filter_by(name="Auto-quarantine critical devices").first()
    if not pb:
        pb = DefensePlaybook(
            name="Auto-quarantine critical devices", enabled=True,
            actions=json.dumps(["send_alert"]),
            trigger_field="severity", trigger_op="eq", trigger_value="critical",
        )
        db.session.add(pb); db.session.commit()
    return pb


def _get_or_create_threshold(db, user_id, name, min_score, playbook_id, cooldown=4):
    from dashboard.backend.automated_response.models import ResponseThreshold
    t = ResponseThreshold.query.filter_by(user_id=user_id, name=name).first()
    if not t:
        t = ResponseThreshold(
            user_id=user_id, name=name,
            min_score=min_score, enabled=True,
            cooldown_hours=cooldown, playbook_id=playbook_id,
        )
        db.session.add(t); db.session.commit()
    else:
        t.playbook_id = playbook_id
        t.enabled = True
        t.cooldown_hours = cooldown
        db.session.commit()
    return t


class TestAutomatedResponsePushIntegration:
    def test_emergency_triggers_web_push_dispatch(self, flask_app, test_user):
        mock_dispatcher = MagicMock(return_value={"succeeded": 1, "failed": 0, "attempted": 1, "disabled": 0})

        from dashboard.backend.automated_response.engine import fire_response
        from dashboard.backend.models import db

        pb = _get_or_create_playbook(db)
        threshold = _get_or_create_threshold(db, test_user.id, "emergency", 95, pb.id)

        with patch("dashboard.backend.push_notifications.dispatcher.send_web_push", mock_dispatcher):
            result = fire_response(test_user.id, "10.0.0.99", "device", 98, threshold)

        assert result.get("web_push_sent") is True
        mock_dispatcher.assert_called_once()

    def test_high_alert_does_NOT_trigger_web_push(self, flask_app, test_user):
        mock_dispatcher = MagicMock()

        from dashboard.backend.automated_response.engine import fire_response
        from dashboard.backend.models import db

        pb = _get_or_create_playbook(db)
        threshold = _get_or_create_threshold(db, test_user.id, "high_alert", 80, pb.id)

        with patch("dashboard.backend.push_notifications.dispatcher.send_web_push", mock_dispatcher):
            result = fire_response(test_user.id, "10.0.0.80", "device", 82, threshold)

        mock_dispatcher.assert_not_called()
        assert result.get("web_push_sent") is False

    def test_notify_does_NOT_trigger_web_push(self, flask_app, test_user):
        mock_dispatcher = MagicMock()

        from dashboard.backend.automated_response.engine import fire_response
        from dashboard.backend.models import db

        pb = _get_or_create_playbook(db)
        threshold = _get_or_create_threshold(db, test_user.id, "notify", 60, pb.id)

        with patch("dashboard.backend.push_notifications.dispatcher.send_web_push", mock_dispatcher):
            result = fire_response(test_user.id, "10.0.0.61", "device", 62, threshold)

        mock_dispatcher.assert_not_called()
        assert result.get("web_push_sent") is False

    def test_automated_response_continues_when_push_fails(self, flask_app, test_user):
        """fire_response must not raise even when the push dispatcher explodes."""
        from dashboard.backend.automated_response.engine import fire_response
        from dashboard.backend.models import db

        pb = _get_or_create_playbook(db)
        threshold = _get_or_create_threshold(db, test_user.id, "emergency", 95, pb.id, cooldown=0)

        with patch(
            "dashboard.backend.push_notifications.dispatcher.send_web_push",
            side_effect=RuntimeError("push infrastructure down"),
        ):
            result = fire_response(test_user.id, "10.0.0.crash", "device", 99, threshold)

        assert isinstance(result, dict)
        assert result.get("web_push_sent") is False


# ── Service worker regression notes ──────────────────────────────────────────
# These are not executable backend tests (the SW runs in the browser), but they
# document the bugs that were fixed so future regressions are caught in review.

class TestServiceWorkerRegressionNotes:
    def test_sw_version_is_4_0_1(self):
        """v4.0.1 bumped to force browsers to pick up the non-http scheme fix."""
        import pathlib
        sw = pathlib.Path(__file__).parents[1] / "dashboard/frontend/aipet-dashboard/public/sw.js"
        content = sw.read_text()
        assert "v4.0.1" in content, "SW version must be 4.0.1 after the scheme fix"

    def test_sw_has_http_protocol_guard(self):
        """
        Regression: chrome-extension:// requests crashed the SW with
        'TypeError: Failed to execute put on Cache: Request scheme chrome-extension
        is unsupported'. Fix: skip any request whose URL protocol is not http/https.
        """
        import pathlib
        sw = pathlib.Path(__file__).parents[1] / "dashboard/frontend/aipet-dashboard/public/sw.js"
        content = sw.read_text()
        assert "url.protocol.startsWith('http')" in content, (
            "Fetch handler must guard against non-http schemes"
        )
