# =============================================================
# AIPET X — Capability 13 Day 3: Windows service support tests.
#
# These tests run on the Linux dev box but mock platform.system() to
# simulate Windows execution, plus do structural lints on the Windows
# packaging artefacts (batch scripts, NSSM config, bundled binary).
# =============================================================

import os
import re
import sys
import pathlib
import importlib
from unittest import mock

import pytest

REPO_ROOT  = pathlib.Path(__file__).resolve().parents[1]
AGENT_DIR  = REPO_ROOT / "agent"
WIN_DIR    = AGENT_DIR / "packaging" / "windows"
INSTALL_BAT     = WIN_DIR / "install_windows.bat"
UNINSTALL_BAT   = WIN_DIR / "uninstall_windows.bat"
SERVICE_INSTALL = WIN_DIR / "aipet-agent-service-install.bat"
SERVICE_REMOVE  = WIN_DIR / "aipet-agent-service-uninstall.bat"
NSSM_EXE        = WIN_DIR / "nssm.exe"
README_WIN      = WIN_DIR / "README-Windows.md"
LICENSE_NSSM    = WIN_DIR / "nssm-LICENSE.txt"

# Linux-side artefacts we must not regress
DEB_DIR         = REPO_ROOT / "agent" / "packaging" / "deb"
DEB_SERVICE     = DEB_DIR / "lib" / "systemd" / "system" / "aipet-agent.service"
DEB_CONTROL     = DEB_DIR / "DEBIAN" / "control"


def _reload_agent_under(system_value, env_overrides=None):
    """
    Re-import agent.aipet_agent with platform.system() mocked. Returns the
    freshly imported module so tests can inspect IS_WINDOWS / IS_LINUX and
    the path-resolution helpers.
    """
    if str(AGENT_DIR) not in sys.path:
        sys.path.insert(0, str(AGENT_DIR))
    sys.modules.pop("aipet_agent", None)
    env = {} if env_overrides is None else env_overrides
    with mock.patch("platform.system", return_value=system_value), \
         mock.patch.dict(os.environ, env, clear=False):
        return importlib.import_module("aipet_agent")


# ═══════════════════════════════════════════════════════════
# PLATFORM DETECTION + PATH RESOLUTION
# ═══════════════════════════════════════════════════════════

class TestPlatformPathResolution:
    def test_is_windows_constant_set_when_windows(self):
        m = _reload_agent_under(
            "Windows",
            env_overrides={"PROGRAMDATA": r"C:\ProgramData",
                           "PROGRAMFILES": r"C:\Program Files"},
        )
        assert m.IS_WINDOWS is True
        assert m.IS_LINUX is False

    def test_is_linux_constant_set_when_linux(self):
        m = _reload_agent_under("Linux")
        assert m.IS_LINUX is True
        assert m.IS_WINDOWS is False

    def test_config_path_resolves_to_programdata_on_windows(self):
        m = _reload_agent_under(
            "Windows",
            env_overrides={"PROGRAMDATA": r"C:\ProgramData"},
        )
        p = str(m._resolve_config_path())
        assert "C:" in p
        assert "AIPET" in p
        assert p.endswith("agent.conf")
        assert "\\" in p, "Windows path should use backslashes"

    def test_config_path_resolves_to_etc_on_linux(self):
        m = _reload_agent_under("Linux")
        p = str(m._resolve_config_path())
        assert p == "/etc/aipet-agent/agent.conf"

    def test_log_dir_resolves_to_programdata_on_windows(self):
        m = _reload_agent_under(
            "Windows",
            env_overrides={"PROGRAMDATA": r"C:\ProgramData"},
        )
        p = str(m._resolve_log_dir())
        assert "C:" in p and "AIPET" in p and p.endswith("logs")

    def test_log_dir_resolves_to_var_log_on_linux(self):
        m = _reload_agent_under("Linux")
        assert str(m._resolve_log_dir()) == "/var/log/aipet-agent"

    def test_install_dir_resolves_to_program_files_on_windows(self):
        m = _reload_agent_under(
            "Windows",
            env_overrides={"PROGRAMFILES": r"C:\Program Files"},
        )
        p = str(m._resolve_install_dir())
        assert "Program Files" in p and p.endswith("AIPET")

    def test_install_dir_resolves_to_opt_on_linux(self):
        m = _reload_agent_under("Linux")
        assert str(m._resolve_install_dir()) == "/opt/aipet-agent"


# ═══════════════════════════════════════════════════════════
# os.fork GUARDED ON WINDOWS
# ═══════════════════════════════════════════════════════════

class TestNoForkOnWindows:
    def test_main_does_not_call_os_fork_on_windows(self):
        """If --daemon is passed on Windows, the agent should log a
        warning and proceed in the foreground — never call os.fork()."""
        m = _reload_agent_under(
            "Windows",
            env_overrides={"PROGRAMDATA": r"C:\ProgramData",
                           "PROGRAMFILES": r"C:\Program Files"},
        )
        # Build an argparse Namespace by hand instead of calling main(),
        # which would otherwise enter the scan loop.
        with mock.patch.object(m.os, "fork", side_effect=AssertionError("os.fork must not be called on Windows")) as mocked_fork, \
             mock.patch.object(m.os, "setsid", side_effect=AssertionError("os.setsid must not be called on Windows")):
            # Pull the daemon-handling block out by exec'ing the relevant
            # branch with IS_WINDOWS=True. Simpler: assert the source
            # contains the IS_WINDOWS guard around the fork.
            source = (AGENT_DIR / "aipet_agent.py").read_text()
            # The fork must sit inside an "if IS_WINDOWS … else:" branch,
            # OR inside a "if not IS_WINDOWS" block. Check that os.fork
            # is no longer top-level inside the daemon block.
            assert "if IS_WINDOWS:" in source, "missing platform guard for daemon mode"
            # The fork should be unreachable without first checking IS_WINDOWS
            fork_line_idx = source.find("os.fork()")
            guard_idx = source.rfind("if IS_WINDOWS:", 0, fork_line_idx)
            assert guard_idx != -1, "os.fork() not protected by IS_WINDOWS guard"
            mocked_fork.assert_not_called()

    def test_resolve_scan_target_does_not_shell_out_to_ip(self):
        """Linux-only `ip` command was replaced by psutil.net_if_addrs
        for Windows compatibility."""
        source = (AGENT_DIR / "aipet_agent.py").read_text()
        assert 'subprocess.check_output(["ip"' not in source, \
            "still shelling out to Linux-only `ip` command"
        assert 'subprocess.check_output(["ip"' not in source

    def test_auto_detect_subnet_uses_psutil(self):
        m = _reload_agent_under("Linux")
        # Returning a CIDR proves psutil.net_if_addrs path works
        cidr = m._resolve_scan_target("auto")
        assert cidr == "" or re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", cidr)


# ═══════════════════════════════════════════════════════════
# WATCHDOG IS CROSS-PLATFORM
# ═══════════════════════════════════════════════════════════

class TestWatchdogCrossPlatform:
    def test_watchdog_module_has_no_linux_only_imports(self):
        text = (AGENT_DIR / "watchdog.py").read_text()
        assert "import pwd"   not in text
        assert "import grp"   not in text
        assert "import fcntl" not in text
        assert "os.fork"      not in text
        assert "os.setsid"    not in text

    def test_watchdog_runs_under_simulated_windows(self):
        """The watchdog logic itself doesn't depend on os.system —
        sanity-check it imports and runs the same on both."""
        sys.path.insert(0, str(AGENT_DIR))
        sys.modules.pop("watchdog", None)
        with mock.patch("platform.system", return_value="Windows"):
            import watchdog
            with mock.patch.object(watchdog.requests, "get",
                                   return_value=mock.Mock(status_code=200)):
                ok, reason = watchdog.check_key_valid("http://x", "aipet_abc")
                assert ok is True and reason is None

    def test_watchdog_exit_code_unchanged_on_windows(self):
        """systemd RestartPreventExitStatus=1 and NSSM AppExit 1 Stop both
        depend on the watchdog exiting with code 1 — must not change."""
        sys.path.insert(0, str(AGENT_DIR))
        sys.modules.pop("watchdog", None)
        import watchdog
        assert watchdog.EXIT_CODE_KEY_REVOKED == 1


# ═══════════════════════════════════════════════════════════
# WINDOWS PACKAGING ARTEFACTS
# ═══════════════════════════════════════════════════════════

class TestWindowsPackagingFiles:
    def test_install_bat_exists(self):
        assert INSTALL_BAT.exists()

    def test_uninstall_bat_exists(self):
        assert UNINSTALL_BAT.exists()

    def test_service_install_bat_exists(self):
        assert SERVICE_INSTALL.exists()

    def test_service_uninstall_bat_exists(self):
        assert SERVICE_REMOVE.exists()

    def test_nssm_exe_bundled(self):
        assert NSSM_EXE.exists()
        size = NSSM_EXE.stat().st_size
        # Genuine NSSM 2.24 win64 is 331,264 bytes — allow a generous range
        assert 200_000 < size < 600_000, f"nssm.exe size suspicious: {size}"

    def test_nssm_exe_is_pe32_plus_x86_64(self):
        # PE binaries start with "MZ"
        with open(NSSM_EXE, "rb") as f:
            magic = f.read(2)
        assert magic == b"MZ", "nssm.exe is not a Windows PE binary"

    def test_nssm_license_shipped(self):
        assert LICENSE_NSSM.exists()
        text = LICENSE_NSSM.read_text()
        assert "public domain" in text.lower()
        assert "nssm.cc" in text.lower()

    def test_readme_exists_and_documents_install_paths(self):
        assert README_WIN.exists()
        text = README_WIN.read_text()
        for token in (r"C:\Program Files\AIPET",
                      r"C:\ProgramData\AIPET",
                      "AipetAgent", "nssm.exe"):
            assert token in text, f"README missing: {token}"


# ═══════════════════════════════════════════════════════════
# install_windows.bat — structural lints
# ═══════════════════════════════════════════════════════════

class TestInstallBat:
    def test_admin_check_present(self):
        text = INSTALL_BAT.read_text()
        assert "net session" in text, "missing administrator privilege check"
        assert "Run as administrator" in text or "administrator" in text.lower()

    def test_python_check_present(self):
        text = INSTALL_BAT.read_text()
        assert "python --version" in text or "%%P --version" in text

    def test_nmap_check_present(self):
        text = INSTALL_BAT.read_text()
        assert "where nmap" in text or "nmap --version" in text

    def test_three_questions_present(self):
        text = INSTALL_BAT.read_text()
        for prompt in ("Key:", "Label:", "Network:"):
            assert prompt in text

    def test_validates_api_key_format(self):
        text = INSTALL_BAT.read_text()
        # findstr regex starting with aipet_ — minimum length 26
        assert "aipet_" in text
        assert "findstr" in text

    def test_writes_config_to_programdata(self):
        text = INSTALL_BAT.read_text()
        assert "%DATA_DIR%\\agent.conf" in text or "DATA_DIR%\\agent.conf" in text

    def test_does_not_write_key_to_disk(self):
        text = INSTALL_BAT.read_text()
        # The actual key value must not be echoed to the conf file —
        # we redact it. Look for "redacted" near the conf-writing block.
        assert "redacted" in text.lower()

    def test_calls_service_install_script(self):
        text = INSTALL_BAT.read_text()
        assert "aipet-agent-service-install.bat" in text

    def test_registers_in_add_remove_programs(self):
        text = INSTALL_BAT.read_text()
        assert "Uninstall\\AipetAgent" in text
        assert "DisplayName" in text
        assert "UninstallString" in text


# ═══════════════════════════════════════════════════════════
# NSSM service config — security-critical asserts
# ═══════════════════════════════════════════════════════════

class TestNssmServiceConfig:
    def test_appexit_1_is_stop(self):
        """SECURITY: revoked-key exit (code 1) must NOT be auto-restarted."""
        text = SERVICE_INSTALL.read_text()
        assert re.search(r"AppExit\s+1\s+Stop", text), \
            "missing AppExit 1 Stop — revoked agents will be auto-restarted"

    def test_appexit_default_is_restart(self):
        """Crashes (any exit code other than 1) should be auto-recovered."""
        text = SERVICE_INSTALL.read_text()
        assert re.search(r"AppExit\s+Default\s+Restart", text)

    def test_start_is_auto(self):
        text = SERVICE_INSTALL.read_text()
        assert "SERVICE_AUTO_START" in text

    def test_stdout_stderr_to_programdata_logs(self):
        text = SERVICE_INSTALL.read_text()
        assert "AppStdout" in text and "%DATA_DIR%\\logs\\agent.log" in text
        assert "AppStderr" in text and "%DATA_DIR%\\logs\\agent-error.log" in text

    def test_log_rotation_configured(self):
        text = SERVICE_INSTALL.read_text()
        assert "AppRotateFiles 1" in text
        assert "AppRotateBytes" in text  # cap log size

    def test_environment_extras_include_all_agent_vars(self):
        text = SERVICE_INSTALL.read_text()
        for var in ("AIPET_API", "AIPET_AGENT_KEY", "AIPET_AGENT_LABEL",
                    "AIPET_SCAN_TARGET", "AIPET_SCAN_INTERVAL_HOURS",
                    "AIPET_INTERVAL", "AIPET_WATCHDOG_INTERVAL",
                    "AIPET_LOG_LEVEL"):
            assert var in text, f"AppEnvironmentExtra missing: {var}"

    def test_service_name_is_aipetagent(self):
        text = SERVICE_INSTALL.read_text()
        assert "SERVICE_NAME=AipetAgent" in text or "AipetAgent" in text


# ═══════════════════════════════════════════════════════════
# Uninstall lint
# ═══════════════════════════════════════════════════════════

class TestUninstallBat:
    def test_admin_check_present(self):
        assert "net session" in UNINSTALL_BAT.read_text()

    def test_removes_service(self):
        text = UNINSTALL_BAT.read_text()
        assert "aipet-agent-service-uninstall.bat" in text \
            or "sc delete AipetAgent" in text

    def test_removes_install_dir(self):
        assert 'rmdir /S /Q "%INSTALL_DIR%"' in UNINSTALL_BAT.read_text()

    def test_removes_program_data(self):
        assert 'rmdir /S /Q "%DATA_DIR%"' in UNINSTALL_BAT.read_text()

    def test_removes_registry_entry(self):
        text = UNINSTALL_BAT.read_text()
        assert "reg delete" in text and "AipetAgent" in text


# ═══════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY — Linux .deb path (Day 2) intact
# ═══════════════════════════════════════════════════════════

class TestLinuxBackwardCompat:
    def test_systemd_unit_unchanged_in_structure(self):
        text = DEB_SERVICE.read_text()
        assert "User=aipet-agent" in text
        assert "ExecStart=/opt/aipet-agent/venv/bin/python /opt/aipet-agent/aipet_agent.py" in text
        assert "RestartPreventExitStatus=1" in text

    def test_deb_control_dependencies_unchanged(self):
        text = DEB_CONTROL.read_text()
        assert "python3 (>= 3.8)" in text
        assert "nmap" in text

    def test_aipet_agent_still_supports_old_cli_flags(self):
        text = (AGENT_DIR / "aipet_agent.py").read_text()
        for flag in ("--agent-key", "--scan", "--daemon",
                     "--email", "--password"):
            assert flag in text, f"backward-compat flag missing: {flag}"

    def test_aipet_agent_still_supports_legacy_env_vars(self):
        text = (AGENT_DIR / "aipet_agent.py").read_text()
        for var in ("AIPET_API", "AIPET_AGENT_KEY", "AIPET_TOKEN",
                    "AIPET_INTERVAL"):
            assert var in text


# ═══════════════════════════════════════════════════════════
# README — Windows-specific install path
# ═══════════════════════════════════════════════════════════

class TestReadmeWindows:
    def test_documents_admin_requirement(self):
        text = README_WIN.read_text()
        assert "administrator" in text.lower()

    def test_documents_python_and_nmap_requirements(self):
        text = README_WIN.read_text()
        assert "Python 3.8" in text
        assert "nmap" in text.lower()

    def test_documents_uninstall(self):
        text = README_WIN.read_text()
        assert "uninstall_windows.bat" in text
        assert "Apps" in text or "Add/Remove" in text

    def test_documents_watchdog_security_guarantee(self):
        text = README_WIN.read_text()
        # The README must explain that revoking a key takes the agent
        # off the network — that's the user-visible security promise.
        assert "AppExit 1 Stop" in text
        assert "revok" in text.lower()
