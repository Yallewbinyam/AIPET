# ============================================================
# AIPET X — Agent watchdog
# Periodically re-validates the agent API key by calling
# GET /api/agent/keys/me. On 401 the agent exits with code 1
# (the systemd unit ships with `RestartPreventExitStatus=1`,
# so systemd will not bring it back up).
# ============================================================

from __future__ import annotations

import logging
import sys
import threading
import time

import requests

EXIT_CODE_KEY_REVOKED = 1   # systemd will NOT restart on this
EXIT_CODE_NORMAL = 0
DEFAULT_INTERVAL = 300       # 5 minutes

log = logging.getLogger("aipet-agent.watchdog")


def check_key_valid(api_url: str, agent_key: str, *, timeout: float = 10.0) -> tuple[bool, str | None]:
    """
    Probe GET /api/agent/keys/me with the agent key.

    Returns (is_valid, error_message):
      * (True, None)        — HTTP 200, key still good.
      * (False, <reason>)   — HTTP 401, key revoked or no longer valid.
      * (True, <reason>)    — Network/transport error. We deliberately do
                              NOT exit on transient failures so a flaky
                              connection cannot evict the agent.

    No tracebacks are ever raised — every error path returns a tuple.
    """
    if not agent_key:
        return False, "No agent key configured"

    url = f"{api_url.rstrip('/')}/api/agent/keys/me"
    try:
        r = requests.get(
            url,
            headers={"X-Agent-Key": agent_key},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return True, f"transient network error: {exc.__class__.__name__}"

    if r.status_code == 200:
        return True, None
    if r.status_code == 401:
        return False, "Agent key revoked or invalid (HTTP 401)"
    # 5xx or anything else — treat as transient, don't kill the agent.
    return True, f"unexpected HTTP {r.status_code}"


def watchdog_loop(api_url: str, agent_key: str, interval_seconds: int = DEFAULT_INTERVAL,
                  on_revoked=None) -> None:
    """
    Long-running loop. Calls check_key_valid every `interval_seconds`.

    On revocation:
      * Logs a plain-English message (no Python traceback).
      * Calls `on_revoked` callback if supplied (used by tests).
      * Calls sys.exit(EXIT_CODE_KEY_REVOKED) — systemd will see exit
        code 1 and (because RestartPreventExitStatus=1) NOT restart.
    """
    log.info(f"Watchdog started (check every {interval_seconds}s, target {api_url})")
    while True:
        time.sleep(interval_seconds)
        is_valid, reason = check_key_valid(api_url, agent_key)
        if is_valid:
            if reason:
                log.warning(f"Watchdog: {reason} — continuing")
            else:
                log.debug("Watchdog: key still valid")
            continue

        # Revoked path. Log plainly, then exit.
        log.error("───────────────────────────────────────────────────────────────")
        log.error("AIPET agent key revoked or invalid. Stopping.")
        log.error("Get a new key from the dashboard:")
        log.error("  https://app.aipet.io/settings/agents")
        log.error(f"Reason: {reason}")
        log.error("───────────────────────────────────────────────────────────────")
        if on_revoked is not None:
            on_revoked(reason)
            return  # tests can drive the loop without exiting
        sys.exit(EXIT_CODE_KEY_REVOKED)


def start_watchdog_thread(api_url: str, agent_key: str,
                          interval_seconds: int = DEFAULT_INTERVAL) -> threading.Thread:
    """
    Start the watchdog as a daemon thread. Used by aipet_agent.py so the
    main scan loop continues uninterrupted.
    """
    t = threading.Thread(
        target=watchdog_loop,
        args=(api_url, agent_key, interval_seconds),
        name="aipet-watchdog",
        daemon=True,
    )
    t.start()
    return t
