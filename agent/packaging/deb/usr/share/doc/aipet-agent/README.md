# AIPET X Agent

A lightweight network-scanning agent that reports findings to the AIPET X
cloud dashboard.

## Quick start

```bash
sudo aipet-agent setup
```

The setup wizard asks three questions:

1. Your agent API key (from https://app.aipet.io/settings/agents)
2. A label for this agent
3. The network to scan (CIDR or `auto`)

It then writes `/etc/aipet-agent/agent.conf`, enables the
`aipet-agent.service` systemd unit, and runs a self-test against the cloud.

## What it does

* Runs as a hardened systemd service under a dedicated unprivileged user
  (`aipet-agent`).
* Performs nmap scans of the configured subnet on a schedule.
* Sends scan results to `POST /api/agent/scan-results` using the per-device
  API key (`X-Agent-Key` header).
* A built-in watchdog re-validates the API key every 5 minutes; if the key
  has been revoked from the dashboard, the agent shuts down cleanly with a
  plain-English log message and **does not** restart.

## File locations

| Purpose                     | Path                                       |
|-----------------------------|--------------------------------------------|
| Agent code                  | `/opt/aipet-agent/aipet_agent.py`          |
| Watchdog                    | `/opt/aipet-agent/watchdog.py`             |
| Isolated venv               | `/opt/aipet-agent/venv/`                   |
| Configuration               | `/etc/aipet-agent/agent.conf`              |
| Example config              | `/etc/aipet-agent/agent.conf.example`      |
| Persistent state            | `/var/lib/aipet-agent/`                    |
| Stdout / stderr logs        | `/var/log/aipet-agent/agent.log`           |
| Systemd unit                | `/etc/systemd/system/aipet-agent.service`  |

## Required Linux capabilities

The agent needs `CAP_NET_RAW` and `CAP_NET_ADMIN` for nmap raw-socket
scanning. The systemd unit grants exactly those two and drops everything
else (`NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`).

## Useful commands

```bash
sudo systemctl status aipet-agent    # Is it running?
sudo journalctl -u aipet-agent -f    # Live logs
sudo systemctl restart aipet-agent   # Restart after config change
sudo aipet-agent test                # Re-run the self-test
```

## Uninstall

```bash
sudo apt-get remove aipet-agent           # Stop service + remove binaries
sudo apt-get purge  aipet-agent           # Also remove config, logs, user
```

`remove` keeps your config and logs (useful for reinstall); `purge` wipes
everything including the `aipet-agent` system user.

## Manual mode (advanced)

The underlying script still works as a standalone:

```bash
python3 /opt/aipet-agent/aipet_agent.py --agent-key aipet_xxxx --scan 10.0.0.0/24
```

Backward-compatible with the previous standalone agent — env vars and CLI
flags are unchanged.

## Documentation

Full docs: https://docs.aipet.io/agent
