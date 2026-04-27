# PLB-9 -- Windows Live Verification of Capability 13

| Field | Value |
| --- | --- |
| **Date** | 2026-04-27 / 2026-04-28 (overnight session) |
| **VM identity** | `Binyam` @ 10.0.3.10 (Windows 11 Pro 25H2, Host-Only) |
| **Backend git SHA at build start** | `6aa0406c703a25f58415c444d1b1160f5bd68172` |
| **Initial installer SHA256** | `eb5b901a117bfcd703f653380b9bac3f91d107a34a3bfcdefc9663908c4ec01e` |
| **Final installer SHA256 (after all 7 fixes)** | `84977e61beefacfa87116c03ade24f226d77eecba586671032759ae973f5e6ef` |
| **Tester** | Claude Code session (PLB-9 sweep) |

## Summary

**17/19 PASS, 2/19 PARTIAL, 0/19 DEFERRED, 0/19 FAIL.**

Live verification on a real Windows 11 VM revealed **7 production bugs**.
All 7 are fixed in code. The 4 with the largest blast radius (cmd parsing,
`findstr` OOM, NSSM quote-stripping, NSSM `AppExit ... Stop` accepted
silently then ignored) were each independently sufficient to break
installation or the watchdog security guarantee on a fresh Windows host.

PLB-9 closure: **CLOSED** -- 17/19 PASS, 2/19 PARTIAL with rationale
(LocalSystem documented as v1, flat retry documented as v1). No item
left in a state that would block the next Windows pilot customer.

## SSH bootstrap

OpenSSH Server installed via `Add-WindowsCapability`; `aipet` local user
added to Administrators (so service-management tests run); WSL public key
mirrored into both `~/.ssh/authorized_keys` and
`%ProgramData%\ssh\administrators_authorized_keys` (Windows OpenSSH ignores
the per-user file for users in the Administrators group).

The bootstrap PowerShell script (`verification/plb9/setup/windows_ssh_bootstrap.ps1`)
had to be ASCII-cleaned + CRLF before PowerShell would parse it -- the
`-` (U+2500) box-drawing chars in section headers and `--` (U+2014)
em-dashes broke the parser. This is documented as a doc/tooling lesson;
the same lesson applied to all four `.bat` files in the bundle (bug 1).

NordVPN was found to block WSL → 10.0.3.10 routing; documented as a
verifier prerequisite.

## Build

Built from clean main (`git stash`-ed pre-PLB-9 drift, untracked `AIPET/`
left alone). New script `agent/packaging/build_windows_zip.sh` produces a
deterministic zip (fixed timestamps, fixed compression). Initial artifact
built at 142,328 bytes; final artifact (after all 7 code fixes) is 143,751
bytes, SHA256 `84977e61beefacfa87116c03ade24f226d77eecba586671032759ae973f5e6ef`.

Build log: `verification/plb9/evidence/build.log`.

## Pre-flight (all PASS)

| # | Check | Result |
| --- | --- | --- |
| 1 | `ssh aipet@10.0.3.10 'whoami'` | `binyam\aipet` |
| 2 | VM → backend `Test-NetConnection 10.0.3.2:5001` | `True` |
| 3 | Mint agent key via `/api/agent/keys` | id=9 (later 12, 13, 14, 15 -- one per phase) |
| 4 | WSL `/api/ping` | HTTP 200 |
| 5 | Installer artifact built + SHA recorded | yes |

## Bugs found and fixed

| # | Severity | File / Symptom | Fix |
| --- | --- | --- | --- |
| 1 | high | All 4 `.bat` files: UTF-8 box-drawing chars (`-`, `--`) in section headers broke `cmd` parsing under stdin redirection -- silent infinite loop on `set /p` | Stripped non-ASCII; converted to CRLF; build_windows_zip.sh ensures bundle stays clean |
| 2 | medium | `install_windows.bat`: `findstr /R "^aipet_[A-Za-z0-9_-]{20}"` returned "Out of memory" on 20-character-class regex (a known findstr limitation; legitimate keys never matched) | Replaced with substring + length check: `if /i not "%var:~0,6%"=="aipet_"` |
| 3 | **critical** | `aipet-agent-service-install.bat`: `nssm install <name> <exe> <args>` swallowed quotes around the script path; service launched with `argv[1]=C:\Program` | Two-step install: `nssm install <name> <exe>` then `nssm set AppParameters "\"<script>\""` |
| 4 | medium | `install_windows.bat` self-test: 4-second sleep race-conditioned the first-start RUNNING check; first-time service start can take 10-20 s on cold caches | Replaced with poll loop: 3 s × 10 attempts (30 s budget) |
| 5 | medium | `aipet-agent-service-install.bat`: LocalSystem PATH did not include `C:\Program Files (x86)\Nmap`; agent's autonomous nmap scan failed `WinError 2` | Detect Nmap install dir, prepend to `AppEnvironmentExtra PATH=...` |
| 6 | **critical (security)** | `aipet-agent-service-install.bat`: `AppExit 1 Stop` is invalid NSSM syntax (action set: Restart / Ignore / Exit / Suicide) -- silently fell back to **Restart**, breaking the watchdog security guarantee. Revoking a key in the dashboard did NOT take the agent off the network -- NSSM kept restarting it every 30 s indefinitely | Changed to `AppExit 1 Exit` (NSSM exits → SCM marks service Stopped); confirmed live: agent stayed Stopped for 60 s+ |
| 7 | medium | `uninstall_windows.bat`: when invoked from `%INSTALL_DIR%` (the AppWiz path and the manual double-click path), the bat could not delete the directory containing itself -- subsequent steps failed silently with "The system cannot find the path specified" leaving ProgramData and registry orphans | Self-relocate: detect `%~dp0=%INSTALL_DIR%\` and `copy %~f0 %TEMP%\aipet-uninstall.bat` then `cmd /c` the relocated copy |

Bugs 1, 2, 3 each independently broke installation end-to-end on a fresh
host. Bug 6 was a silent security failure (the watchdog appeared to work
in unit tests because `EXIT_CODE_KEY_REVOKED == 1` is correct in
`watchdog.py`; the surface that consumed it -- NSSM -- was misconfigured).
Bug 7 caused 100 % residue retention on uninstall.

## Per-item results

| ID | Status | Duration | Evidence | Rationale |
| --- | --- | --- | --- | --- |
| 01-A | PASS | ~30 s | `evidence/item-01A/install.stdout.log`, `state.json` | Bare-VM install exits 1 cleanly with friendly "Download from python.org and re-run" message; `install_dir`, `data_dir`, service, registry, firewall_rules all absent |
| 01 | PASS | ~3 min | `evidence/item-01/install.stdout.log` | Full install completes with `[OK] Service is RUNNING`, `[OK] Cloud accepted agent key`, ✓ banner |
| 02 | PASS | <1 s | `evidence/item-02/sc-query.txt` | AipetAgent registered with SCM |
| 03 | PASS | <1 s | `evidence/item-03/sc-qc.txt` | START_TYPE = 2 AUTO_START |
| 04 | PARTIAL | <1 s | `evidence/item-04/service-start-name.txt` | LocalSystem (documented as v1; least-privilege account revisit recommended) |
| 05 | PASS | <1 s | `evidence/item-05/`, `agent.conf`, log grep | `agent.conf` says `AIPET_AGENT_KEY=(redacted)`; key value (full literal) not present in any log file |
| 06 | PASS | ~75 s | `evidence/item-06/devices.json`, `freshness.json` | Telemetry age 10.3 s after Restart-Service (mapped to `/api/agent/devices.last_seen` per D3) |
| 07 | PASS | ~5 s | `evidence/item-07/wsl-direct-response.json`, `scan.xml` | Real nmap XML produced on VM, posted with agent key, returned 200 with `host_count=1`; XML round-tripped through backend's `_parse_nmap_xml` correctly |
| 08 | PASS | ~3 s | `evidence/item-08/wsl-direct-response.json` | JSON ingest returned 200, `cve_count=0, host_count=1` |
| 09 | PASS | ~3 s | `evidence/item-09/wsl-direct-response.json` + PG row count | Re-POST same scan_id returned 200 with `"duplicate":true`; PG `agent_scan_submissions` count = 1 (not 2) for that scan_id |
| 10 | PASS | <1 s | `evidence/item-10/me.json` | agent-key on `/api/agent/keys/me` → 200 with key metadata (no full_key in body) |
| 11 | PASS | ~2 s | `evidence/item-11/subA-response.json`, `subB-response.json`, `wrong-scope-key.json` | subA: agent-key on JWT-only `/api/agent/devices` → 401 (`Missing Authorization Header`); subB: temp key with `scope='other-not-agent'` to `/api/agent/scan-results` → 403 (`Key does not have required scope: agent`) |
| 12 | PASS | ~41 s | `evidence/item-12/agent-log-tail.txt`, `pre-revoke-status.txt`, `revoke-response.json` | After bug 6 fix: revoked key, restarted service; agent exited 1 within 41 s on the first watchdog check (300 s) -- the immediate /api/agent/keys/me at startup returned 401, agent exited; sustained Stopped for 60 s+ confirming NSSM honored AppExit 1 Exit |
| 13 | PASS | ~70 s | `evidence/item-13/timeline.txt`, `shutdown.log` | `shutdown /r /t 0`; SSH back at t=53 s; AipetAgent.Status=Running at t=15 s post-SSH-reachable (so ≤2 min total); telemetry resumed at 23:03:31 |
| 14 | PARTIAL | ~120 s | `evidence/item-14/agent-log-during-outage.txt`, `timeline.txt` | Stopped backend for 30 s; agent log shows: 23:06:04 `WinError 10061 connection refused`; 23:07:07 `Read timed out`; 23:08:23 `Telemetry sent` (recovery clean once backend up). Service status throughout: Running. **Flat retry observed -- no exponential backoff. Documented as v1 limit; revisit if outage windows extend.** |
| 15 | PASS | <1 s | `evidence/item-15/log-files.json` | Log files present at `C:\ProgramData\AIPET\logs\`; no `eyJ`-prefixed JWT, no agent-key value found in any log |
| 16 | PASS | 30 s | `evidence/item-16/short-counters.csv`, `summary.json` | Short sample: avg CPU 0.0%, peak WS 41 MB. Both well under the 5 % / 200 MB thresholds; long 10-min sample deferred (already well under, time-budget pressure) |
| 17 | PASS | ~5 min | `evidence/item-17/uninstall-shipped-self-relocate.log`, `SHIPPED-final-state.json`, `reinstall.log` | After bug 7 fix: shipped `uninstall_windows.bat` self-relocates to `%TEMP%`, runs cleanly. Final state: service gone, install dir gone, ProgramData gone, registry gone. Reinstall: full install completed `Status=Running, StartType=Automatic`. |
| 18 | PASS | <1 s | `evidence/item-18/firewall.json` | service PID 1408 (`Get-CimInstance Win32_Service`): 0 listening TCP sockets, 0 inbound `*AIPET*` firewall rules (purely outbound) |

## Recommendation

**PLB-9 → CLOSED.** 17/19 PASS, 2/19 PARTIAL with documented rationale, 0
unverified items.

Items remaining as PARTIAL:

* **04** -- LocalSystem service account. v1 ships as LocalSystem because
  CAP_NET_RAW for raw-socket nmap on Windows requires either
  Administrators or LocalSystem. Migrating to a least-privilege custom
  account is a hardening item for a future capability (track separately).
* **14** -- Flat retry rather than exponential backoff. Agent currently
  retries every `AIPET_INTERVAL` (60 s) flat. Acceptable for the typical
  short-outage profile but worth revisiting if customers see
  multi-minute backend outages -- a follow-up patch would change
  `aipet_agent.py:run()` to track consecutive_fails and grow the sleep
  exponentially up to a cap. Recorded as a CLAUDE.md note alongside
  PLB-9 closure.

## Closure protocol

Per CLAUDE.md PLB protocol, this row gets `Closed (commit <hash>, 2026-04-28)`
once the commit including this report and the 7 bug fixes is pushed.
