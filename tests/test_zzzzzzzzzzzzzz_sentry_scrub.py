# =============================================================
# AIPET X — PLB-5: Sentry before_send PII/secret scrubbing tests
# =============================================================
# These tests verify that the before_send hook in
# dashboard/backend/observability/sentry_setup.py scrubs every known
# secret shape from outbound Sentry events. They run without a live
# Sentry DSN — we drive _before_send directly with fabricated events.

from dashboard.backend.observability import sentry_setup as sb


# ---------------------------------------------------------------- regex patterns

class TestSecretRegexes:
    def test_aipet_agent_key_pattern_matches(self):
        s = "auth: aipet_VHa_c3LF7Gvz8MDgaaKVKxjcTTKSqzeAkszPUpI2"
        assert "[Filtered:aipet_key]" in sb._scrub_str(s)

    def test_aipet_pattern_is_word_bounded(self):
        # Don't match short non-key strings that happen to contain "aipet_"
        s = "saw aipet_ short"
        assert sb._scrub_str(s) == s

    def test_jwt_pattern_matches_three_dot_segments(self):
        s = "tok=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.aaaaaaaaaaaaaaaaaaa"
        assert "[Filtered:jwt]" in sb._scrub_str(s)

    def test_jwt_pattern_does_not_match_random_eyJ(self):
        s = "eyJ short"
        assert sb._scrub_str(s) == s

    def test_sentry_dsn_pattern_matches(self):
        s = "https://abc1234567890abcdef1234567890abcd@o123.ingest.us.sentry.io/4567"
        assert "[Filtered:sentry_dsn]" in sb._scrub_str(s)

    def test_stripe_secret_key_pattern_matches(self):
        for prefix in ("sk_live_", "sk_test_"):
            s = f"key={prefix}abcdef1234567890ABCDEF"
            assert "[Filtered:stripe_sk]" in sb._scrub_str(s)

    def test_anthropic_key_pattern_matches(self):
        s = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghij1234567890abcdefghij1234567890XXXX"
        assert "[Filtered:llm_key]" in sb._scrub_str(s)

    def test_postgres_password_in_uri_filtered(self):
        s = "postgresql://aipet_user:aipet_password@localhost:5433/aipet_db"
        out = sb._scrub_str(s)
        assert "aipet_password" not in out
        assert "[Filtered:db_password]" in out
        # Username and host are preserved; only the password between : and @ is replaced
        assert "aipet_user" in out
        assert "@localhost" in out


# ---------------------------------------------------------------- header denylist

class TestHeaderDenylist:
    def test_authorization_header_filtered(self):
        ev = {"request": {"headers": {"Authorization": "Bearer xyz", "User-Agent": "ok"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["headers"]["Authorization"] == "[Filtered]"
        assert out["request"]["headers"]["User-Agent"] == "ok"

    def test_x_agent_key_header_filtered(self):
        ev = {"request": {"headers": {"X-Agent-Key": "aipet_xxxxxxxxxxxxxxxxxxxxxxxx"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["headers"]["X-Agent-Key"] == "[Filtered]"

    def test_cookie_header_filtered(self):
        ev = {"request": {"headers": {"Cookie": "session=secret"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["headers"]["Cookie"] == "[Filtered]"

    def test_header_denylist_is_case_insensitive(self):
        ev = {"request": {"headers": {"AUTHORIZATION": "Bearer X", "x-Agent-key": "a"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["headers"]["AUTHORIZATION"] == "[Filtered]"
        assert out["request"]["headers"]["x-Agent-key"] == "[Filtered]"


# ---------------------------------------------------------------- body key denylist

class TestBodyKeyDenylist:
    def test_password_field_filtered(self):
        ev = {"request": {"data": {"password": "Test1234!", "username": "alice"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["data"]["password"] == "[Filtered]"
        assert out["request"]["data"]["username"] == "alice"

    def test_agent_key_field_filtered(self):
        ev = {"request": {"data": {"agent_key": "aipet_xxx"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["data"]["agent_key"] == "[Filtered]"

    def test_token_field_filtered(self):
        for key in ("token", "access_token", "refresh_token", "id_token", "jwt"):
            ev = {"request": {"data": {key: "value"}}}
            out = sb._before_send(ev, {})
            assert out["request"]["data"][key] == "[Filtered]", key

    def test_body_key_match_is_case_insensitive(self):
        ev = {"request": {"data": {"PASSWORD": "x", "Api_Key": "y"}}}
        out = sb._before_send(ev, {})
        assert out["request"]["data"]["PASSWORD"] == "[Filtered]"
        assert out["request"]["data"]["Api_Key"] == "[Filtered]"

    def test_nested_dicts_recursed(self):
        ev = {"request": {"data": {"profile": {"password": "x"}}}}
        out = sb._before_send(ev, {})
        assert out["request"]["data"]["profile"]["password"] == "[Filtered]"

    def test_lists_of_dicts_recursed(self):
        ev = {"request": {"data": {"users": [{"password": "a"}, {"password": "b"}]}}}
        out = sb._before_send(ev, {})
        assert out["request"]["data"]["users"][0]["password"] == "[Filtered]"
        assert out["request"]["data"]["users"][1]["password"] == "[Filtered]"


# ---------------------------------------------------------------- exception/message scrubbing

class TestExceptionScrubbing:
    def test_exception_value_string_scrubbed(self):
        ev = {"exception": {"values": [{"type": "ValueError",
            "value": "tok aipet_xxxxxxxxxxxxxxxxxxxxxxxx leaked"}]}}
        out = sb._before_send(ev, {})
        assert "aipet_xxxxxxxxxxxxxxxxxxxxxxxx" not in out["exception"]["values"][0]["value"]
        assert "[Filtered:aipet_key]" in out["exception"]["values"][0]["value"]

    def test_top_level_message_scrubbed(self):
        ev = {"message": "tok eyJabc123def456ghi789jkl0.eyJsubclaim1234567890.signaturebytes_xxxxxxxxxx"}
        out = sb._before_send(ev, {})
        assert "[Filtered:jwt]" in out["message"]


# ---------------------------------------------------------------- breadcrumbs

class TestBreadcrumbs:
    def test_breadcrumb_data_scrubbed(self):
        ev = {"breadcrumbs": {"values": [
            {"category": "http", "data": {"Authorization": "Bearer X", "url": "/x"}},
        ]}}
        out = sb._before_send(ev, {})
        assert out["breadcrumbs"]["values"][0]["data"]["Authorization"] == "[Filtered]"
        assert out["breadcrumbs"]["values"][0]["data"]["url"] == "/x"


# ---------------------------------------------------------------- fail-open guarantee

class TestFailureMode:
    def test_scrubber_drops_event_if_it_crashes(self, monkeypatch):
        # Force _scrub_dict to raise; confirm before_send returns None
        # (drop event) rather than letting raw data through.
        def _boom(*a, **kw):
            raise RuntimeError("boom")
        monkeypatch.setattr(sb, "_scrub_dict", _boom)
        out = sb._before_send({"request": {"headers": {"Authorization": "Bearer x"}}}, {})
        assert out is None


# ---------------------------------------------------------------- release detection

class TestReleaseDetection:
    def test_app_release_env_var_wins(self, monkeypatch):
        monkeypatch.setenv("APP_RELEASE", "v1.2.3-custom")
        assert sb._resolve_release() == "v1.2.3-custom"

    def test_falls_back_to_short_git_sha(self, monkeypatch):
        monkeypatch.delenv("APP_RELEASE", raising=False)
        rel = sb._resolve_release()
        # In this repo we always have a git SHA available
        assert rel == "unknown" or len(rel) >= 7
