#!/usr/bin/env python3
# ============================================================
# AIPET X — Device Agent v1.2.0
# Collects system telemetry and sends to AIPET platform.
#
# Authentication modes:
#   Mode 1 (legacy):  --email / --password  → JWT login (15-min expiry)
#   Mode 2 (preferred): --agent-key or AIPET_AGENT_KEY env var → non-expiring key
#
# Install:   pip install psutil requests
# Configure: set AIPET_AGENT_KEY env var (or pass --agent-key)
# Run:       python3 aipet_agent.py --agent-key aipet_xxx
# Daemon:    python3 aipet_agent.py --agent-key aipet_xxx --daemon
# One-shot scan: python3 aipet_agent.py --agent-key aipet_xxx --scan 10.0.0.0/24
#
# v1.2.0 (Capability 13 Day 2):
#   * Recurring background scans driven by AIPET_SCAN_TARGET +
#     AIPET_SCAN_INTERVAL_HOURS (no --scan flag needed for service mode)
#   * Token watchdog thread re-validates the agent key every
#     AIPET_WATCHDOG_INTERVAL seconds via GET /api/agent/keys/me
#   * AIPET_AGENT_LABEL surfaced in scan_metadata.label
#   * Backward compat: every old CLI flag and env var still works
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
API_BASE          = os.environ.get("AIPET_API",       "http://localhost:5001")
AUTH_TOKEN        = os.environ.get("AIPET_TOKEN",     "")   # JWT (legacy)
AGENT_KEY         = os.environ.get("AIPET_AGENT_KEY", "")   # non-expiring agent key (preferred)
INTERVAL_SEC      = int(os.environ.get("AIPET_INTERVAL", "30"))
AGENT_LABEL       = os.environ.get("AIPET_AGENT_LABEL", "")
SCAN_TARGET       = os.environ.get("AIPET_SCAN_TARGET", "")
SCAN_INTERVAL_HRS = int(os.environ.get("AIPET_SCAN_INTERVAL_HOURS", "0"))  # 0 disables periodic scans
WATCHDOG_INTERVAL = int(os.environ.get("AIPET_WATCHDOG_INTERVAL", "300"))
AGENT_VERSION     = "1.2.0"
LOG_LEVEL         = os.environ.get("AIPET_LOG_LEVEL", "INFO")

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
                "pid":    info["pid"],
                "name":   info["name"] or "",
                "user":   info["username"] or "",
                "cpu":    round(info["cpu_percent"] or 0, 1),
                "mem":    round(info["memory_percent"] or 0, 2),
                "status": info["status"] or "",
                "cmd":    " ".join(info["cmdline"] or [])[:120],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
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


# ── Auth helpers ──────────────────────────────────────────

def login(email: str, password: str) -> str:
    """Legacy JWT login. Token expires in 15 minutes — use --agent-key instead."""
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


def _make_headers(token: str = "", agent_key: str = "") -> dict:
    """Build auth headers for a request. Agent key preferred over JWT."""
    if agent_key:
        return {"X-Agent-Key": agent_key, "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ── Send telemetry ────────────────────────────────────────

def send(token: str, payload: dict, agent_key: str = "") -> bool:
    """Send telemetry. Works with both JWT (token) and agent key."""
    try:
        headers = _make_headers(token=token, agent_key=agent_key)
        r = requests.post(
            f"{API_BASE}/api/agent/telemetry",
            json=payload,
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            snap_id = r.json().get("snapshot_id", "")
            log.info(f"Telemetry sent — snapshot {snap_id[:8]}  cpu={payload['cpu_percent']}%  mem={payload['mem_percent']}%")
            return True
        elif r.status_code == 401:
            log.error("Authentication failed (401). If using --agent-key, the key may be revoked.")
            if agent_key:
                log.error("Agent key auth: exiting — revoked or invalid key, no point retrying.")
                sys.exit(1)
            return False
        else:
            log.warning(f"Server returned {r.status_code}: {r.text[:200]}")
            return False
    except requests.RequestException as e:
        log.error(f"Send failed: {e}")
        return False


# ── Nmap scan + upload ────────────────────────────────────

def run_nmap_scan(target: str) -> dict:
    """
    Run nmap on target. Returns structured dict with hosts list.
    Uses python-nmap if available, else falls back to subprocess + XML parse.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        log.info(f"Running nmap scan on {target} ...")
        nm.scan(hosts=target, arguments="-sV -T4 --top-ports 1000", timeout=300)
        hosts = []
        for host in nm.all_hosts():
            if nm[host].state() != "up":
                continue
            open_ports = []
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    pdata = nm[host][proto][port]
                    if pdata.get("state") != "open":
                        continue
                    open_ports.append({
                        "port":    port,
                        "proto":   proto,
                        "service": pdata.get("name", "unknown"),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                    })
            hosts.append({"ip": host, "ports": open_ports})
        return {"hosts": hosts}
    except ImportError:
        pass

    # Subprocess fallback
    import subprocess
    import tempfile
    import defusedxml.ElementTree as ET

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    try:
        log.info(f"Running nmap scan on {target} (subprocess) ...")
        subprocess.run(
            ["nmap", "-sV", "-T4", "--top-ports", "1000", "-oX", xml_path, target],
            timeout=300, check=True, capture_output=True,
        )
        tree = ET.parse(xml_path)
        root = tree.getroot()
        hosts = []
        for host_el in root.findall("host"):
            state_el = host_el.find("status")
            if state_el is None or state_el.get("state") != "up":
                continue
            ip = ""
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ip = addr_el.get("addr", "")
                    break
            if not ip:
                continue
            open_ports = []
            for port_el in (host_el.find("ports") or []):
                state_p = port_el.find("state")
                if state_p is None or state_p.get("state") != "open":
                    continue
                svc = port_el.find("service")
                open_ports.append({
                    "port":    int(port_el.get("portid", "0")),
                    "proto":   port_el.get("protocol", "tcp"),
                    "service": svc.get("name", "unknown") if svc is not None else "unknown",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
            hosts.append({"ip": ip, "ports": open_ports})
        return {"hosts": hosts}
    except Exception as exc:
        log.error(f"nmap scan failed: {exc}")
        return {"hosts": []}
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def upload_scan_results(scan_data: dict, agent_key: str, target: str = "") -> bool:
    """POST scan results to /api/agent/scan-results."""
    scan_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    payload = {
        "scan_id":    scan_id,
        "agent_device_id": AGENT_ID,
        "format":     "json",
        "scan_data":  scan_data,
        "scan_metadata": {
            "target":       target,
            "scan_type":    "discovery",
            "started_at":   now,
            "completed_at": now,
            "host_count":   len(scan_data.get("hosts", [])),
            "service_count": sum(len(h.get("ports", [])) for h in scan_data.get("hosts", [])),
            "agent_label":  AGENT_LABEL,
        },
    }
    try:
        r = requests.post(
            f"{API_BASE}/api/agent/scan-results",
            json=payload,
            headers={"X-Agent-Key": agent_key, "Content-Type": "application/json"},
            timeout=30,
        )
        if r.status_code == 200:
            result = r.json()
            log.info(f"Scan uploaded — real_scan_id={result.get('real_scan_id', '')[:8]}  hosts={result.get('host_count', 0)}")
            return True
        elif r.status_code == 401:
            log.error("Scan upload 401: agent key is revoked or invalid.")
            return False
        else:
            log.warning(f"Scan upload returned {r.status_code}: {r.text[:200]}")
            return False
    except requests.RequestException as e:
        log.error(f"Scan upload failed: {e}")
        return False


# ── Main loop ─────────────────────────────────────────────

def _resolve_scan_target(raw: str) -> str:
    """Translate 'auto' to the local subnet, or pass through a CIDR/IP."""
    if not raw or raw.strip().lower() != "auto":
        return raw.strip()
    # Detect first global-scope IPv4 subnet
    try:
        import subprocess
        out = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], timeout=5).decode()
        for line in out.splitlines():
            if "scope global" in line:
                parts = line.split()
                # field 4 is "x.x.x.x/n" in `ip -o` output
                cidr = parts[3]
                if "/" in cidr:
                    return cidr
    except Exception as exc:
        log.warning(f"Auto-detect failed ({exc}). Set AIPET_SCAN_TARGET to a CIDR explicitly.")
    return ""


def run(token: str, agent_key: str = ""):
    log.info(f"AIPET Agent {AGENT_VERSION} starting")
    log.info(f"  Agent ID : {AGENT_ID}")
    log.info(f"  Host     : {socket.gethostname()}")
    log.info(f"  Label    : {AGENT_LABEL or '(none)'}")
    log.info(f"  Platform : {platform.system()} {platform.release()}")
    log.info(f"  API      : {API_BASE}")
    log.info(f"  Interval : {INTERVAL_SEC}s")
    log.info(f"  Auth     : {'agent-key' if agent_key else 'jwt'}")

    # Optional: token watchdog (only when authenticating with an agent key)
    if agent_key and WATCHDOG_INTERVAL > 0:
        try:
            from watchdog import start_watchdog_thread
        except ImportError:
            try:
                # When running from /opt/aipet-agent or the agent/ source dir
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from watchdog import start_watchdog_thread
            except ImportError:
                log.warning("watchdog module not found — running without token revocation check")
                start_watchdog_thread = None
        if start_watchdog_thread:
            start_watchdog_thread(API_BASE, agent_key, WATCHDOG_INTERVAL)
            log.info(f"  Watchdog : every {WATCHDOG_INTERVAL}s")

    # Optional: periodic background scans (driven by AIPET_SCAN_TARGET)
    next_scan_at = 0
    if agent_key and SCAN_TARGET and SCAN_INTERVAL_HRS > 0:
        target_resolved = _resolve_scan_target(SCAN_TARGET)
        if target_resolved:
            log.info(f"  Scans    : {target_resolved} every {SCAN_INTERVAL_HRS}h")
            next_scan_at = time.time()  # first scan runs immediately
        else:
            log.warning("Scan target unresolved — periodic scans disabled")

    consecutive_fails = 0
    while True:
        try:
            payload = build_payload()
            ok = send(token, payload, agent_key=agent_key)
            if ok:
                consecutive_fails = 0
            else:
                consecutive_fails += 1
                if consecutive_fails >= 5:
                    log.error("5 consecutive failures — check connectivity and credentials")

            # Periodic scan trigger
            if next_scan_at and time.time() >= next_scan_at:
                target_resolved = _resolve_scan_target(SCAN_TARGET)
                if target_resolved:
                    log.info(f"Periodic scan starting on {target_resolved}")
                    try:
                        scan_data = run_nmap_scan(target_resolved)
                        upload_scan_results(scan_data, agent_key=agent_key, target=target_resolved)
                    except Exception as scan_exc:
                        log.error(f"Scheduled scan failed: {scan_exc}")
                next_scan_at = time.time() + SCAN_INTERVAL_HRS * 3600
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            consecutive_fails += 1
        time.sleep(INTERVAL_SEC)


# ── Entry point ───────────────────────────────────────────

def main():
    global API_BASE, INTERVAL_SEC, AGENT_KEY
    parser = argparse.ArgumentParser(description=f"AIPET X Device Agent v{AGENT_VERSION}")
    parser.add_argument("--api",       default=API_BASE,    help="AIPET API base URL")
    parser.add_argument("--agent-key", default=AGENT_KEY,   dest="agent_key",
                        help="Non-expiring agent API key (preferred over --email/--password)")
    parser.add_argument("--token",     default=AUTH_TOKEN,  help="JWT token (legacy)")
    parser.add_argument("--email",     default="",          help="AIPET account email (legacy JWT)")
    parser.add_argument("--password",  default="",          help="AIPET account password (legacy JWT)")
    parser.add_argument("--interval",  type=int, default=INTERVAL_SEC, help="Send interval in seconds")
    parser.add_argument("--daemon",    action="store_true", help="Daemonize the process")
    parser.add_argument("--scan",      default="",          help="One-shot: run nmap on TARGET and upload, then exit")
    args = parser.parse_args()

    API_BASE     = args.api
    INTERVAL_SEC = args.interval

    agent_key = args.agent_key.strip() if args.agent_key else ""
    token = args.token

    # One-shot scan mode
    if args.scan:
        if not agent_key:
            parser.error("--scan requires --agent-key (or AIPET_AGENT_KEY env var)")
        log.info(f"One-shot scan mode: target={args.scan}")
        scan_data = run_nmap_scan(args.scan)
        ok = upload_scan_results(scan_data, agent_key=agent_key, target=args.scan)
        sys.exit(0 if ok else 1)

    # Agent key takes priority — no JWT needed
    if agent_key:
        log.info("Using agent API key authentication")
    elif not token and args.email and args.password:
        log.info(f"Logging in as {args.email} (JWT mode — consider --agent-key for production)…")
        token = login(args.email, args.password)
        log.info("Login successful")
    elif not token and not agent_key:
        parser.error("Provide --agent-key, --token, or --email and --password")

    if args.daemon:
        try:
            pid = os.fork()
            if pid > 0:
                print(f"Agent daemonized — PID {pid}")
                sys.exit(0)
            os.setsid()
        except (AttributeError, OSError):
            log.warning("Daemon mode not supported on this platform — running in foreground")

    run(token, agent_key=agent_key)


if __name__ == "__main__":
    main()
