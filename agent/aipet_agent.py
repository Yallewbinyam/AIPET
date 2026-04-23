#!/usr/bin/env python3
# ============================================================
# AIPET X — Device Agent v1.0.0
# Collects system telemetry and sends to AIPET platform
#
# Install:   pip install psutil requests
# Configure: set AIPET_API and AIPET_TOKEN below or via env
# Run:       python3 aipet_agent.py
# Daemon:    python3 aipet_agent.py --daemon
# ============================================================

import os
import sys
import uuid
import json
import time
import socket
import hashlib
import logging
import argparse
import platform
import datetime

try:
    import psutil
except ImportError:
    sys.exit("ERROR: psutil not installed. Run: pip install psutil")

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed. Run: pip install requests")

# ── Configuration ─────────────────────────────────────────
API_BASE      = os.environ.get("AIPET_API",   "http://localhost:5001")
AUTH_TOKEN    = os.environ.get("AIPET_TOKEN", "")   # JWT from /api/auth/login
INTERVAL_SEC  = int(os.environ.get("AIPET_INTERVAL", "30"))
AGENT_VERSION = "1.0.0"
LOG_LEVEL     = os.environ.get("AIPET_LOG_LEVEL", "INFO")

# ── Agent identity ────────────────────────────────────────
def _get_agent_id() -> str:
    """Stable ID derived from hostname + MAC address."""
    hw = f"{socket.gethostname()}-{uuid.getnode()}"
    return "agent-" + hashlib.sha256(hw.encode()).hexdigest()[:16]

AGENT_ID = _get_agent_id()

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("aipet-agent")

# ── Telemetry collection ──────────────────────────────────

def collect_cpu() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "cpu_count":   psutil.cpu_count(logical=True),
    }


def collect_memory() -> dict:
    mem = psutil.virtual_memory()
    return {
        "mem_total_gb": round(mem.total / 1e9, 2),
        "mem_used_gb":  round(mem.used  / 1e9, 2),
        "mem_percent":  mem.percent,
    }


def collect_disk() -> dict:
    partitions = []
    total_used = total_size = 0
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            entry = {
                "device":     part.device,
                "mountpoint": part.mountpoint,
                "fstype":     part.fstype,
                "total_gb":   round(usage.total / 1e9, 2),
                "used_gb":    round(usage.used  / 1e9, 2),
                "percent":    usage.percent,
            }
            partitions.append(entry)
            total_used += usage.used
            total_size += usage.total
        except (PermissionError, OSError):
            continue
    return {
        "disk_total_gb": round(total_size / 1e9, 2),
        "disk_used_gb":  round(total_used / 1e9, 2),
        "disk_percent":  round(total_used / max(total_size, 1) * 100, 1),
        "disks":         partitions,
    }


def collect_processes() -> list:
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status", "create_time", "cmdline"]):
        try:
            info = p.info
            procs.append({
                "pid":        info["pid"],
                "name":       info["name"] or "",
                "user":       info["username"] or "",
                "cpu":        round(info["cpu_percent"] or 0, 1),
                "mem":        round(info["memory_percent"] or 0, 2),
                "status":     info["status"] or "",
                "cmd":        " ".join(info["cmdline"] or [])[:120],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Sort by CPU desc, return top 20
    procs.sort(key=lambda x: x["cpu"], reverse=True)
    return procs[:20]


def collect_connections() -> list:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                conns.append({
                    "fd":     c.fd,
                    "type":   "TCP" if c.type == 1 else "UDP",
                    "laddr":  laddr,
                    "raddr":  raddr,
                    "status": c.status or "",
                    "pid":    c.pid,
                })
            except Exception:
                continue
    except (psutil.AccessDenied, PermissionError):
        log.warning("Insufficient permissions to read network connections (try sudo)")
    return conns[:50]


def build_payload() -> dict:
    cpu  = collect_cpu()
    mem  = collect_memory()
    disk = collect_disk()
    return {
        "agent_id":      AGENT_ID,
        "agent_version": AGENT_VERSION,
        "hostname":      socket.gethostname(),
        "platform":      f"{platform.system()} {platform.release()}",
        "collected_at":  datetime.datetime.utcnow().isoformat(),
        **cpu,
        **mem,
        "disk_total_gb": disk["disk_total_gb"],
        "disk_used_gb":  disk["disk_used_gb"],
        "disk_percent":  disk["disk_percent"],
        "disks":         disk["disks"],
        "processes":     collect_processes(),
        "connections":   collect_connections(),
    }


# ── Auth helper ───────────────────────────────────────────

def login(email: str, password: str) -> str:
    r = requests.post(
        f"{API_BASE}/api/auth/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    r.raise_for_status()
    d = r.json()
    token = d.get("token") or d.get("access_token") or ""
    if not token:
        raise ValueError(f"Login failed: {d}")
    return token


# ── Send telemetry ────────────────────────────────────────

def send(token: str, payload: dict) -> bool:
    try:
        r = requests.post(
            f"{API_BASE}/api/agent/telemetry",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r.status_code == 200:
            snap_id = r.json().get("snapshot_id", "")
            log.info(f"Telemetry sent — snapshot {snap_id[:8]}  cpu={payload['cpu_percent']}%  mem={payload['mem_percent']}%")
            return True
        else:
            log.warning(f"Server returned {r.status_code}: {r.text[:200]}")
            return False
    except requests.RequestException as e:
        log.error(f"Send failed: {e}")
        return False


# ── Main loop ─────────────────────────────────────────────

def run(token: str):
    log.info(f"AIPET Agent {AGENT_VERSION} starting")
    log.info(f"  Agent ID : {AGENT_ID}")
    log.info(f"  Host     : {socket.gethostname()}")
    log.info(f"  Platform : {platform.system()} {platform.release()}")
    log.info(f"  API      : {API_BASE}")
    log.info(f"  Interval : {INTERVAL_SEC}s")

    consecutive_fails = 0
    while True:
        try:
            payload = build_payload()
            ok = send(token, payload)
            if ok:
                consecutive_fails = 0
            else:
                consecutive_fails += 1
                if consecutive_fails >= 5:
                    log.error("5 consecutive failures — check connectivity and token")
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            consecutive_fails += 1
        time.sleep(INTERVAL_SEC)


# ── Entry point ───────────────────────────────────────────

def main():
    global API_BASE, INTERVAL_SEC
    parser = argparse.ArgumentParser(description="AIPET X Device Agent")
    parser.add_argument("--api",      default=API_BASE,    help="AIPET API base URL")
    parser.add_argument("--token",    default=AUTH_TOKEN,  help="JWT token (or use --email/--password)")
    parser.add_argument("--email",    default="",          help="AIPET account email")
    parser.add_argument("--password", default="",          help="AIPET account password")
    parser.add_argument("--interval", type=int, default=INTERVAL_SEC, help="Send interval in seconds (default 30)")
    parser.add_argument("--daemon",   action="store_true", help="Daemonize the process")
    args = parser.parse_args()

    API_BASE     = args.api
    INTERVAL_SEC = args.interval

    token = args.token
    if not token and args.email and args.password:
        log.info(f"Logging in as {args.email}…")
        token = login(args.email, args.password)
        log.info("Login successful")
    elif not token:
        parser.error("Provide --token OR --email and --password")

    if args.daemon:
        try:
            import os
            pid = os.fork()
            if pid > 0:
                print(f"Agent daemonized — PID {pid}")
                sys.exit(0)
            os.setsid()
        except (AttributeError, OSError):
            log.warning("Daemon mode not supported on this platform — running in foreground")

    run(token)


if __name__ == "__main__":
    main()
