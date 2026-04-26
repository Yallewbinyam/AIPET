# =============================================================
# AIPET X — Capability 13 Day 2: Install Package + Watchdog Tests
# =============================================================

import os
import re
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = REPO_ROOT / "agent" / "packaging" / "deb"
INSTALL_SH = REPO_ROOT / "agent" / "packaging" / "install.sh"
BUILD_DEB_SH = REPO_ROOT / "agent" / "packaging" / "build_deb.sh"
SERVICE_FILE = PKG_DIR / "lib" / "systemd" / "system" / "aipet-agent.service"
CONTROL_FILE = PKG_DIR / "DEBIAN" / "control"
POSTINST = PKG_DIR / "DEBIAN" / "postinst"
PRERM = PKG_DIR / "DEBIAN" / "prerm"
POSTRM = PKG_DIR / "DEBIAN" / "postrm"
WRAPPER = PKG_DIR / "usr" / "bin" / "aipet-agent"
CONF_EXAMPLE = PKG_DIR / "etc" / "aipet-agent" / "agent.conf.example"


# ═══════════════════════════════════════════════════════════
# WATCHDOG TESTS
# ═══════════════════════════════════════════════════════════

class TestWatchdog:
    def setup_method(self):
        # Make `import watchdog` resolve to agent/watchdog.py without
        # touching the agent's package layout.
        import sys
        agent_dir = str(REPO_ROOT / "agent")
        if agent_dir not in sys.path:
            sys.path.insert(0, agent_dir)
        if "watchdog" in sys.modules:
            del sys.modules["watchdog"]

    def test_check_key_valid_returns_true_on_200(self):
        import watchdog
        fake = mock.Mock(status_code=200)
        with mock.patch.object(watchdog.requests, "get", return_value=fake):
            ok, reason = watchdog.check_key_valid("http://x", "aipet_abc")
            assert ok is True
            assert reason is None

    def test_check_key_valid_returns_false_on_401(self):
        import watchdog
        fake = mock.Mock(status_code=401)
        with mock.patch.object(watchdog.requests, "get", return_value=fake):
            ok, reason = watchdog.check_key_valid("http://x", "aipet_abc")
            assert ok is False
            assert "revoked" in (reason or "").lower()

    def test_check_key_valid_treats_network_error_as_transient(self):
        import watchdog
        with mock.patch.object(
            watchdog.requests, "get",
            side_effect=watchdog.requests.ConnectionError("nope"),
        ):
            ok, reason = watchdog.check_key_valid("http://x", "aipet_abc")
            # Don't kill the agent on transient network issues
            assert ok is True
            assert "transient" in (reason or "").lower()

    def test_check_key_valid_treats_5xx_as_transient(self):
        import watchdog
        fake = mock.Mock(status_code=503)
        with mock.patch.object(watchdog.requests, "get", return_value=fake):
            ok, reason = watchdog.check_key_valid("http://x", "aipet_abc")
            assert ok is True
            assert "503" in (reason or "")

    def test_check_key_valid_rejects_empty_key(self):
        import watchdog
        ok, reason = watchdog.check_key_valid("http://x", "")
        assert ok is False

    def test_watchdog_loop_invokes_callback_on_revoke(self):
        import watchdog
        fake = mock.Mock(status_code=401)
        called = {"reason": None}

        def on_revoked(reason):
            called["reason"] = reason

        with mock.patch.object(watchdog.requests, "get", return_value=fake):
            with mock.patch.object(watchdog.time, "sleep", lambda *_: None):
                watchdog.watchdog_loop(
                    "http://x", "aipet_abc",
                    interval_seconds=0,
                    on_revoked=on_revoked,
                )
        assert called["reason"] is not None
        assert "401" in called["reason"]

    def test_watchdog_exit_code_is_one(self):
        import watchdog
        # systemd's RestartPreventExitStatus=1 — must stay aligned
        assert watchdog.EXIT_CODE_KEY_REVOKED == 1


# ═══════════════════════════════════════════════════════════
# /api/agent/keys/me ENDPOINT
# ═══════════════════════════════════════════════════════════

class TestAgentKeyMeEndpoint:
    def _make_key(self, user_id):
        from dashboard.backend.agent_keys.auth import generate_api_key
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db

        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=user_id, label="me-test",
            key_prefix=prefix, key_hash=key_hash,
            scope="agent", permissions=["scan:write"],
            enabled=True,
        )
        db.session.add(row)
        db.session.commit()
        return full_key, row

    def test_returns_200_when_key_valid(self, client, flask_app, test_user):
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id)
        r = client.get("/api/agent/keys/me", headers={"X-Agent-Key": full_key})
        assert r.status_code == 200
        body = r.get_json()
        assert body["enabled"] is True
        assert body["scope"] == "agent"
        assert body["label"] == "me-test"

    def test_returns_401_when_key_revoked(self, client, flask_app, test_user):
        from dashboard.backend.models import db
        with flask_app.app_context():
            full_key, row = self._make_key(test_user.id)
            row.enabled = False
            db.session.commit()
        r = client.get("/api/agent/keys/me", headers={"X-Agent-Key": full_key})
        assert r.status_code == 401

    def test_returns_401_when_no_header(self, client):
        r = client.get("/api/agent/keys/me")
        assert r.status_code == 401

    def test_returns_metadata_fields(self, client, flask_app, test_user):
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id)
        r = client.get("/api/agent/keys/me", headers={"X-Agent-Key": full_key})
        body = r.get_json()
        for field in ("id", "label", "scope", "permissions", "enabled",
                      "key_prefix", "created_at"):
            assert field in body, f"missing field: {field}"

    def test_full_key_never_returned(self, client, flask_app, test_user):
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id)
        r = client.get("/api/agent/keys/me", headers={"X-Agent-Key": full_key})
        assert full_key not in r.get_data(as_text=True)


# ═══════════════════════════════════════════════════════════
# DEB PACKAGE STRUCTURE
# ═══════════════════════════════════════════════════════════

class TestDebPackageStructure:
    def test_control_file_exists(self):
        assert CONTROL_FILE.exists()

    def test_control_has_required_fields(self):
        text = CONTROL_FILE.read_text()
        for field in ("Package:", "Version:", "Architecture:",
                      "Maintainer:", "Description:", "Depends:"):
            assert field in text, f"control missing: {field}"

    def test_control_declares_python3_and_nmap_deps(self):
        text = CONTROL_FILE.read_text()
        assert "python3" in text
        assert "nmap" in text
        assert "systemd" in text

    def test_postinst_creates_aipet_agent_user(self):
        text = POSTINST.read_text()
        assert "useradd" in text
        assert "aipet-agent" in text
        assert "/usr/sbin/nologin" in text

    def test_postinst_creates_state_dirs(self):
        text = POSTINST.read_text()
        for d in ("/var/lib/aipet-agent", "/var/log/aipet-agent",
                  "/etc/aipet-agent"):
            assert d in text, f"postinst missing dir: {d}"

    def test_postinst_does_not_auto_start_service(self):
        # Auto-start would fire before the user has configured the API key.
        # The postinst's MSG heredoc tells the user to run
        # `sudo systemctl enable --now aipet-agent` manually — that's text,
        # not an executed command. We assert no UNCOMMENTED `systemctl start`
        # or `systemctl enable …aipet-agent` ever runs.
        text = POSTINST.read_text()
        # Slice off the heredoc help text (everything from "<<'MSG'" to "MSG\n")
        body = re.sub(r"<<'MSG'.*?\nMSG\b", "", text, flags=re.DOTALL)
        assert "systemctl start" not in body
        assert "systemctl enable" not in body

    def test_prerm_stops_service(self):
        text = PRERM.read_text()
        assert "systemctl stop aipet-agent" in text
        assert "systemctl disable aipet-agent" in text

    def test_postrm_purge_removes_user_and_files(self):
        text = POSTRM.read_text()
        assert "purge" in text
        assert "userdel aipet-agent" in text
        for d in ("/var/lib/aipet-agent", "/var/log/aipet-agent",
                  "/etc/aipet-agent"):
            assert d in text

    def test_maintainer_scripts_use_set_e(self):
        for script in (POSTINST, PRERM, POSTRM):
            text = script.read_text()
            assert "\nset -e\n" in text, f"{script.name} missing 'set -e'"

    def test_wrapper_script_supports_setup_test_uninstall(self):
        text = WRAPPER.read_text()
        for cmd in ("cmd_setup", "cmd_test", "cmd_uninstall", "cmd_status"):
            assert cmd in text


# ═══════════════════════════════════════════════════════════
# SYSTEMD UNIT — security hardening assertions
# ═══════════════════════════════════════════════════════════

class TestSystemdUnit:
    def test_unit_exists(self):
        assert SERVICE_FILE.exists()

    def test_unit_runs_as_dedicated_user(self):
        text = SERVICE_FILE.read_text()
        assert "User=aipet-agent" in text
        assert "Group=aipet-agent" in text

    def test_unit_has_security_hardening(self):
        text = SERVICE_FILE.read_text()
        for directive in (
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ReadWritePaths=",
        ):
            assert directive in text, f"missing hardening: {directive}"

    def test_unit_grants_only_net_caps(self):
        text = SERVICE_FILE.read_text()
        assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in text
        assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in text

    def test_unit_uses_environment_file(self):
        text = SERVICE_FILE.read_text()
        assert "EnvironmentFile=/etc/aipet-agent/agent.conf" in text

    def test_unit_does_not_restart_on_revoked_key(self):
        # Watchdog exits with code 1; systemd must NOT restart it.
        text = SERVICE_FILE.read_text()
        assert "RestartPreventExitStatus=1" in text

    def test_unit_targets_multi_user(self):
        assert "WantedBy=multi-user.target" in SERVICE_FILE.read_text()


# ═══════════════════════════════════════════════════════════
# INSTALL SCRIPT — validation logic & lint
# ═══════════════════════════════════════════════════════════

class TestInstallScript:
    def test_install_sh_exists_and_executable(self):
        assert INSTALL_SH.exists()
        # Permission bits aren't preserved through git on Windows checkouts,
        # so this is a soft check.
        text = INSTALL_SH.read_text()
        assert text.startswith("#!/usr/bin/env bash")

    def test_install_sh_has_set_e(self):
        text = INSTALL_SH.read_text()
        assert "set -e" in text
        assert "set -o pipefail" in text

    def test_install_sh_validates_api_key_format(self):
        text = INSTALL_SH.read_text()
        # Regex must enforce aipet_ prefix and minimum-length body
        assert re.search(r"\^aipet_\[A-Za-z0-9_-\]\{20", text)

    def test_install_sh_validates_subnet_format(self):
        text = INSTALL_SH.read_text()
        assert "([0-9]{1,3}\\.){3}" in text

    def test_install_sh_refuses_non_root(self):
        text = INSTALL_SH.read_text()
        assert 'id -u' in text
        assert "sudo" in text.lower()

    def test_install_sh_detects_non_debian(self):
        text = INSTALL_SH.read_text()
        assert "apt-get" in text
        assert "Debian/Ubuntu only" in text

    def test_install_sh_supports_local_file_url(self):
        text = INSTALL_SH.read_text()
        assert "file://" in text
        assert "AIPET_DEB_URL" in text

    def test_install_sh_self_test_uses_keys_me(self):
        text = INSTALL_SH.read_text()
        assert "/api/agent/keys/me" in text

    @pytest.mark.skipif(
        shutil.which("shellcheck") is None,
        reason="shellcheck not installed",
    )
    def test_install_sh_passes_shellcheck(self):
        result = subprocess.run(
            ["shellcheck", "-S", "warning", str(INSTALL_SH)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"shellcheck failures:\n{result.stdout}\n{result.stderr}"
        )

    @pytest.mark.skipif(
        shutil.which("shellcheck") is None,
        reason="shellcheck not installed",
    )
    def test_wrapper_passes_shellcheck(self):
        result = subprocess.run(
            ["shellcheck", "-S", "warning", str(WRAPPER)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"shellcheck failures:\n{result.stdout}\n{result.stderr}"
        )


# ═══════════════════════════════════════════════════════════
# CONF EXAMPLE / BACKWARD COMPAT
# ═══════════════════════════════════════════════════════════

class TestConfigExample:
    def test_conf_example_has_all_keys(self):
        text = CONF_EXAMPLE.read_text()
        for key in (
            "AIPET_API",
            "AIPET_AGENT_KEY",
            "AIPET_AGENT_LABEL",
            "AIPET_SCAN_TARGET",
            "AIPET_SCAN_INTERVAL_HOURS",
            "AIPET_WATCHDOG_INTERVAL",
        ):
            assert key in text, f"agent.conf.example missing: {key}"

    def test_conf_example_has_no_real_key(self):
        # Make sure no leaked real key ever ships in the package
        text = CONF_EXAMPLE.read_text()
        # AIPET_AGENT_KEY= must be empty in the example
        m = re.search(r"^AIPET_AGENT_KEY=(.*)$", text, re.MULTILINE)
        assert m is not None
        assert m.group(1).strip() == ""


class TestAgentScriptBackwardCompat:
    """Ensure existing CLI flags and env-vars still work after the v1.2.0 update."""

    def test_aipet_agent_supports_legacy_email_password_args(self):
        text = (REPO_ROOT / "agent" / "aipet_agent.py").read_text()
        assert "--email" in text and "--password" in text

    def test_aipet_agent_supports_agent_key_arg(self):
        text = (REPO_ROOT / "agent" / "aipet_agent.py").read_text()
        assert "--agent-key" in text

    def test_aipet_agent_supports_one_shot_scan(self):
        text = (REPO_ROOT / "agent" / "aipet_agent.py").read_text()
        assert "--scan" in text

    def test_aipet_agent_imports_watchdog_optionally(self):
        # Running without watchdog.py installed must not break the agent
        text = (REPO_ROOT / "agent" / "aipet_agent.py").read_text()
        assert "watchdog module not found" in text or "from watchdog import" in text


# ═══════════════════════════════════════════════════════════
# BUILD SCRIPT
# ═══════════════════════════════════════════════════════════

class TestTelemetryHybridAuth:
    """
    /api/agent/telemetry must accept BOTH JWT (dashboard humans) and
    X-Agent-Key (systemd-managed device agent). Day 1 left it JWT-only,
    which broke the systemd agent's telemetry loop after Day 2 install.
    """

    PAYLOAD = {
        "agent_id":     "agent-hybridtest-0001",
        "hostname":     "verify-host",
        "platform":     "Linux 6.6",
        "agent_version":"1.2.0",
        "cpu_percent":  4.2,
        "cpu_count":    8,
        "mem_total_gb": 16.0,
        "mem_used_gb":  3.0,
        "mem_percent":  18.7,
        "disk_total_gb":256.0,
        "disk_used_gb": 120.0,
        "disk_percent": 47.0,
        "processes":    [],
        "connections":  [],
        "disks":        [],
    }

    def _make_key(self, user_id, *, perms=None, enabled=True, scope="agent"):
        from dashboard.backend.agent_keys.auth import generate_api_key
        from dashboard.backend.agent_keys.models import AgentApiKey
        from dashboard.backend.models import db
        full_key, prefix, key_hash = generate_api_key()
        row = AgentApiKey(
            user_id=user_id, label="hybrid-auth",
            key_prefix=prefix, key_hash=key_hash,
            scope=scope,
            permissions=perms if perms is not None else ["scan:write", "telemetry:write"],
            enabled=enabled,
        )
        db.session.add(row)
        db.session.commit()
        return full_key, row

    # JWT path — must keep working for the dashboard
    def test_telemetry_accepts_jwt(self, client, auth_headers):
        r = client.post("/api/agent/telemetry", json=self.PAYLOAD, headers=auth_headers)
        assert r.status_code == 200, r.get_data(as_text=True)
        assert r.get_json()["ok"] is True

    # Agent key path — the new contract
    def test_telemetry_accepts_agent_key(self, client, flask_app, test_user):
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id)
        r = client.post(
            "/api/agent/telemetry", json=self.PAYLOAD,
            headers={"X-Agent-Key": full_key, "Content-Type": "application/json"},
        )
        assert r.status_code == 200, r.get_data(as_text=True)
        assert r.get_json()["ok"] is True

    def test_telemetry_rejects_missing_auth(self, client):
        r = client.post(
            "/api/agent/telemetry", json=self.PAYLOAD,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 401

    def test_telemetry_rejects_revoked_agent_key(self, client, flask_app, test_user):
        from dashboard.backend.models import db
        with flask_app.app_context():
            full_key, row = self._make_key(test_user.id)
            row.enabled = False
            db.session.commit()
        r = client.post(
            "/api/agent/telemetry", json=self.PAYLOAD,
            headers={"X-Agent-Key": full_key, "Content-Type": "application/json"},
        )
        assert r.status_code == 401

    def test_telemetry_rejects_wrong_scope(self, client, flask_app, test_user):
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id, scope="not-agent")
        r = client.post(
            "/api/agent/telemetry", json=self.PAYLOAD,
            headers={"X-Agent-Key": full_key, "Content-Type": "application/json"},
        )
        assert r.status_code == 403

    def test_telemetry_rejects_key_without_telemetry_permission(self, client, flask_app, test_user):
        with flask_app.app_context():
            # Key only has scan:write — no telemetry:write
            full_key, _ = self._make_key(test_user.id, perms=["scan:write"])
        r = client.post(
            "/api/agent/telemetry", json=self.PAYLOAD,
            headers={"X-Agent-Key": full_key, "Content-Type": "application/json"},
        )
        assert r.status_code == 403

    def test_devices_endpoint_still_jwt_only(self, client, flask_app, test_user):
        # /api/agent/devices is for the dashboard — agent keys must NOT see it.
        with flask_app.app_context():
            full_key, _ = self._make_key(test_user.id)
        r = client.get(
            "/api/agent/devices",
            headers={"X-Agent-Key": full_key, "Content-Type": "application/json"},
        )
        # Without JWT this should fail; an agent key alone can't list devices.
        assert r.status_code in (401, 422)


class TestBuildScript:
    def test_build_script_exists(self):
        assert BUILD_DEB_SH.exists()

    def test_build_script_uses_dpkg_deb(self):
        assert "dpkg-deb" in BUILD_DEB_SH.read_text()

    def test_build_script_copies_agent_and_watchdog(self):
        text = BUILD_DEB_SH.read_text()
        assert "aipet_agent.py" in text
        assert "watchdog.py" in text

    @pytest.mark.skipif(
        shutil.which("dpkg-deb") is None,
        reason="dpkg-deb not available",
    )
    def test_build_script_produces_valid_deb(self, tmp_path):
        # Run the build, then validate the output with dpkg-deb -I
        env = os.environ.copy()
        result = subprocess.run(
            ["bash", str(BUILD_DEB_SH)],
            capture_output=True, text=True, env=env,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, f"build failed:\n{result.stderr}"

        deb = REPO_ROOT / "agent" / "packaging" / "aipet-agent_1.0.0_all.deb"
        assert deb.exists()
        info = subprocess.run(
            ["dpkg-deb", "-I", str(deb)],
            capture_output=True, text=True,
        )
        assert info.returncode == 0
        assert "Package: aipet-agent" in info.stdout
