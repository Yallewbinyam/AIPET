# AIPET X Agent — Windows

Lightweight network-scanning agent for Windows, run as a Windows Service via
NSSM (Non-Sucking Service Manager). Same agent code, same auth model, same
watchdog as the Linux build — just packaged for Windows.

## Requirements

* Windows 10 / 11 / Server 2016+
* **Administrator** privileges (for service install)
* **Python 3.8+** in `PATH` — install from <https://www.python.org/downloads/>
  and tick **"Add Python to PATH"**
* **nmap** in `PATH` — install from <https://nmap.org/download.html>
* Internet connectivity to the AIPET cloud (default `https://api.aipet.io`)

## Installation

1. Copy this folder to the target machine.
2. Right-click `install_windows.bat` and choose **Run as administrator**.
3. Answer 3 prompts:
   * Agent API key (`aipet_…`) from <https://app.aipet.io/settings/agents>
   * Label for this agent (defaults to `%COMPUTERNAME%`)
   * Network to scan (CIDR or `auto`)
4. The installer:
   * Verifies Python and nmap are available
   * Copies files to `C:\Program Files\AIPET\`
   * Installs Python dependencies (`psutil`, `requests`, `defusedxml`)
   * Writes a config summary to `C:\ProgramData\AIPET\agent.conf` (key
     itself is **not** written to disk — held in NSSM's environment table)
   * Registers the **AipetAgent** Windows Service (auto-start on boot)
   * Adds an entry to **Settings → Apps & Features**
   * Runs a self-test (cloud reachability + key validity + first
     telemetry round-trip)

## File locations

| Purpose                | Path                                   |
| ---------------------- | -------------------------------------- |
| Agent code             | `C:\Program Files\AIPET\aipet_agent.py` |
| Watchdog               | `C:\Program Files\AIPET\watchdog.py`   |
| NSSM (service wrapper) | `C:\Program Files\AIPET\nssm.exe`      |
| Stdout log             | `C:\ProgramData\AIPET\logs\agent.log`  |
| Stderr log             | `C:\ProgramData\AIPET\logs\agent-error.log` |
| Config summary         | `C:\ProgramData\AIPET\agent.conf`      |
| Uninstaller            | `C:\Program Files\AIPET\uninstall_windows.bat` |

## Operating the service

```cmd
sc query  AipetAgent      :: status
sc start  AipetAgent      :: start
sc stop   AipetAgent      :: stop
sc qc     AipetAgent      :: configuration
```

To change configuration (different key, label, scan target), re-run
`install_windows.bat`. It removes and reinstalls the service in place.

## Watchdog behaviour (security)

The agent calls `GET /api/agent/keys/me` every 5 minutes
(`AIPET_WATCHDOG_INTERVAL=300`). If the cloud responds 401 (key revoked),
the agent exits with code **1**. NSSM is configured with
`AppExit 1 Stop`, so the service stops and is **not** restarted. This is
the security guarantee — revoking a key in the dashboard genuinely takes
the agent off the network within the watchdog window.

Other exit codes follow `AppExit Default Restart` — process crashes are
auto-recovered after a 30-second back-off.

## Uninstall

* From **Settings → Apps & Features → AIPET X Agent → Uninstall**, **or**
* Right-click `C:\Program Files\AIPET\uninstall_windows.bat` and **Run as
  administrator**

The uninstaller:

* Stops and removes the AipetAgent service
* Deletes `C:\Program Files\AIPET\` and `C:\ProgramData\AIPET\`
* Removes the Add/Remove Programs registry entry

## Troubleshooting

* **Service won't start** — check `C:\ProgramData\AIPET\logs\agent-error.log`
  for the immediate exit reason.
* **HTTP 401 on every call** — the agent key was revoked or the configured
  `AIPET_API` URL is wrong. Re-run `install_windows.bat` with a fresh key.
* **No telemetry in dashboard** — confirm the dashboard host is reachable
  from this machine (`curl https://api.aipet.io/api/ping` or browse to it).
* **Self-signed cert (dev only)** — set `AIPET_DEV_MODE=1` in the cmd
  shell before running `install_windows.bat`. Production installs must
  use a real cert.

## Bundled NSSM

NSSM 2.24 (`nssm.exe`) is public-domain, redistributed verbatim from
<https://nssm.cc/>. NSSM's role here is purely to register and supervise
the agent process — Microsoft's `sc.exe` cannot run a Python script
directly as a service.
