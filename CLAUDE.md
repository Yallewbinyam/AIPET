# AIPET X — Claude Code Reference

Everything a new Claude Code session needs to understand this project instantly.

---

## 1. What Is AIPET X

AIPET X is an autonomous cybersecurity platform focused on IoT pentesting and enterprise security monitoring. It is a full-stack SaaS product with 93+ modules covering threat intelligence, compliance automation, vulnerability scanning, red team tooling, digital twin modelling, SIEM, SOC automation, identity security, cloud security, and much more. It is built for security professionals and enterprises and monetised via Stripe subscriptions (Free / Professional / Enterprise).

---

## 2. Stack

| Layer | Detail |
|---|---|
| Backend | Flask, running on **port 5001**, entry point: `dashboard/backend/app_cloud.py` |
| Frontend | React (Create React App), running on **port 3000**, entry point: `dashboard/frontend/aipet-dashboard/src/App.js` |
| Database | PostgreSQL — **port 5433**, db: `aipet_db`, user: `aipet_user`, password: `aipet_password` |
| ORM | SQLAlchemy via Flask-SQLAlchemy. Config: `dashboard/backend/config.py`. Models: `dashboard/backend/models.py` |
| Auth | JWT (flask-jwt-extended) + Google OAuth |
| Payments | Stripe (Free / Professional / Enterprise plans) |
| Task queue | Celery — `dashboard/backend/celery_app.py` |
| API base | `http://localhost:5001/api` |

---

## 3. Critical Rules — Never Break These

1. **Never use `metadata` as a SQLAlchemy column name.** SQLAlchemy reserves `metadata` internally. Use `node_meta` or any other name instead. Violating this silently corrupts model definitions.

2. **Never mention competitor names in the UI.** No competitor product or company names should appear in any React component, label, tooltip, or placeholder.

3. **All JSX placeholder attributes must be single-line strings.** No multiline template literals inside JSX props (e.g. `placeholder={...}`). This breaks the JSX parser silently in some builds.

---

## 4. Current State

- **93+ modules complete** — all backend blueprints registered and functional
- **Production hardening done** — Flask-Talisman CSP/HSTS, per-user rate limiting (100 req/min), input validation on all POST endpoints
- **Real Nmap scanner** integrated with NVD CVE matching
- **Celery worker + Beat running** via `start_cloud.sh` (as of D3 / 2026-04-24). NVD sync schedule first observed firing on 2026-04-24, adding 474 CVEs to `live_cves`. Previously Celery was wired but never launched.
- **Automated ML retrain** — `retrain_anomaly_model` task runs every 24 h via Beat; manual trigger via `POST /api/ml/anomaly/retrain_now`; skips gracefully when <20 unique feature vectors available
- **AlienVault OTX** — `sync_otx_threat_intel` runs every 6 h via Beat; first full sync produced 45,750 IOCs from 1,000 pulses (218s). `app_cloud.py` and `tasks.py` both load `.env` via explicit `pathlib.Path(__file__).parents[n]` so the API key reaches the Gunicorn and Celery worker processes regardless of CWD.
- **Stripe payments** — Free (5 scans), Professional (unlimited), Enterprise (unlimited + API access)
- **PDF report export** via WeasyPrint (A4, page breaks, email delivery)
- **Google OAuth** login
- **User onboarding wizard** and password reset flow
- **Python device agent** — live CPU/mem/disk/process/network telemetry every 30 s
- **Load tested** — Locust, 100 concurrent virtual users, 4 task types
- **Sentry error monitoring** wired (DSN not yet set — see PLB-5)
- **UptimeRobot** `/api/ping` endpoint in place (monitor not yet configured — see PLB-6)
- **Last commit tag:** `Pre-Month1: all fixes complete, ready for depth phase`

---

## Pre-Launch Blockers

These items must all be resolved before aipet.io accepts real customer traffic. Each task that closes a blocker **MUST** update this table — change Status to `Closed (commit <hash>, <date>)`. Each task that discovers a new blocker **MUST** add a row. This table is the source of truth — not memory, not other documents. Do not let a session end without updating this table if relevant work was done.

| ID | Blocker | Discovered | Effort | Status | Fix-When |
|---|---|---|---|---|---|
| PLB-1 | Alembic migrations — no baseline migration exists for any of the 100+ tables; project is entirely on db.create_all() | Day 1.5 recon | Half day, risky (full DB backup required first) | Open | Dedicated day (Day 6 of Month 1, after capability 1 finishes) |
| PLB-2 | Flask-Limiter view_functions reassignment pattern not applied to auth/login/register — those rate limits are silent no-ops in Flask-Limiter 4.x | Day 1.5 | 30 min | Closed (commit 915e86c9, 2026-04-25) | Pre-launch hardening sprint |
| PLB-3 | Flask-Limiter storage backend is memory:// per-worker — with 10 Gunicorn workers, effective rate limits are ~10x looser than configured | Day 3 verification (Step 6f) | 5 min | Closed (commit 138f8269, 2026-04-25) | Pre-launch hardening sprint |
| PLB-4 | Gmail SMTP credentials not set in production .env — Flask-Mail wired but cannot send | Day 1 | 5 min config + you must create Gmail App Password | Open | Launch week (you create Gmail App Password) |
| PLB-5 | Sentry DSN not set in production .env — Sentry wired in app_cloud.py but no real DSN | Day 1 | 5 min config + you must create Sentry account | Open | Launch week (you sign up at sentry.io) |
| PLB-6 | UptimeRobot monitor not yet configured — /api/ping endpoint exists but no monitor pointing at aipet.io | Day 1 | 10 min + aipet.io must be live | Open | Launch day (after aipet.io is deployed) |
| PLB-7 | Celery worker + Beat launched via start_cloud.sh (nohup) — production needs systemd services for restart-on-reboot and proper process management | Day 3 | 30 min | Closed (commit 1ec88357, 2026-04-25) — systemd units are templates in deploy/systemd/; not installed on dev. Production deploy task installs them (see deploy/systemd/INSTALL.md). | Production deployment task (alongside DigitalOcean deploy) |
| PLB-8 | Watch agent instrumentation gaps — 9 of 12 ml_anomaly features cannot be computed from real data because watch agent does not collect: TCP flag counts, directional bytes, per-protocol packet counts. Also: dest_ips list is hard-capped at 10, breaking detection of port scans to many destinations | Day 2 recon | Half day | Open | Month 2, alongside watch agent improvements |

### Closing Protocol

- When a blocker is fixed: change Status from `Open` to `Closed (commit <commit_hash>, YYYY-MM-DD)`
- Do NOT delete closed rows for at least 30 days — keep them for audit
- When a new blocker is found: add a new row with the next PLB-N ID

---

## 5. What Is Built — Major Capabilities

All modules live under `dashboard/backend/<module_name>/` as a Blueprint with `__init__.py` + `routes.py` (and usually `models.py`). All are registered in `app_cloud.py`.

| Module | Capability |
|---|---|
| `auth` | JWT login, registration, Google OAuth, password reset |
| `payments` | Stripe subscriptions, webhooks, billing portal |
| `real_scanner` | Nmap host/service/OS scan, NVD CVE matching |
| `live_cves` | Hourly NVD sync, auto-rematch scans. CISA KEV catalog (1,583 actively-exploited CVEs, daily Celery sync, unauthenticated public feed); `/predict_real` now returns four independent verdicts (Isolation Forest + Behavioral + OTX + KEV). `kev_catalog` table: PK=cve_id, includes ransomware flag, vendor, due_date. |
| `siem` / `cloud_siem` | SIEM event ingestion and dashboards |
| `threatintel` / `threat_intel_ingest` / `threat_radar` | Threat intelligence feeds, IOC tracking. AlienVault OTX integration (96-line client, 6-hour Celery sync, locally cached IOCs — 45,750 indicators after first full sync); `/predict_real` now returns threat intel as a third independent verdict alongside Isolation Forest + behavioral baseline. |
| `aisoc` / `soc_twin` | AI-assisted SOC automation and digital twin |
| `adversary_profiling` | Attacker profiling and TTP mapping |
| `attackpath` | Attack path analysis and visualisation |
| `redteam` | Red team tooling and simulation |
| `forensics` | Digital forensics investigation |
| `malware_sandbox` | Malware sandboxing and analysis |
| `behavioral` | Per-device behavioural baseline (Z-score across 12-feature FEATURE_ORDER vocabulary), 12-hour Celery rebuild, integrated into /predict_real |
| `incidents` | Incident management and response |
| `remediation` | Guided remediation workflows |
| `defense` / `defense_mesh` | Defensive controls and mesh policy |
| `zerotrust` | Zero Trust architecture enforcement |
| `identity_guardian` / `iam` / `iam_exposure` / `identitygraph` | Identity security, IAM risk, graph mapping |
| `itdr` | Identity Threat Detection and Response |
| `compliance` / `complianceauto` / `compliance_automation` / `compliance_fabric` | Compliance frameworks, auto-assessment |
| `dspm` | Data Security Posture Management |
| `cloud_hardener` / `cloud_runtime` / `cloud_dashboard` | Cloud security posture and runtime |
| `multicloud` / `multicloud_scale` | Multi-cloud visibility |
| `costsecurity` | Cloud cost and security correlation |
| `k8s_analyzer` | Kubernetes security analysis |
| `apisecurity` | API security scanning |
| `code_security` | SAST / code security review |
| `supplychain` | Supply chain risk analysis |
| `endpoint_agent` / `agent_monitor` | Endpoint telemetry agent and monitor |
| `runtime_protection` | Runtime application/host protection |
| `network_exposure` / `netvisualizer` | Network exposure map and visualiser |
| `digitaltwin` / `digital_twin_v2` | Digital twin modelling |
| `driftdetector` | Configuration drift detection |
| `patch_brain` | AI-assisted patch prioritisation |
| `predict` | Predictive risk scoring |
| `score` | Security posture scoring |
| `apm_engine` | Application Performance Monitoring |
| `metrics_traces` | Metrics and distributed tracing |
| `log_analytics` | Log aggregation and analytics |
| `realtime_dashboards` | Real-time live dashboards |
| `monitoring` / `synthetic_monitoring` | Uptime and synthetic monitoring |
| `arch_builder` | Architecture diagram builder |
| `map` | Asset and topology map |
| `timeline` / `timeline_enhanced` | Event timeline views |
| `narrative` | AI-generated security narrative reports |
| `explain` | AI explanation of findings |
| `ask` | Natural language security Q&A |
| `policy_brain` | AI policy generation |
| `otics` | OT/ICS security |
| `protocols` | Protocol analysis (MQTT, CoAP, HTTP) |
| `enterprise_rbac` | Role-based access control |
| `enterprise_reporting` | Enterprise PDF reports with email delivery |
| `multi_tenant` | Multi-tenancy support |
| `marketplace` | Plugin/integration marketplace |
| `api_keys` | API key management (Enterprise) |
| `settings` | User and organisation settings |
| `calendar` | Security calendar and scheduling |
| `resilience` | Resilience scoring and DR |
| `watch` | Watchlist / continuous monitoring |
| `terminal` | In-browser terminal |
| `public_scan` | Unauthenticated demo scan |
| `modules` | Module registry |

---

## 6. Capability Roadmap — 32 Capabilities

**Current status:** Capabilities 1, 2, 3, 4, 5 ✅ Complete. 27 remaining.

### Month 1 — Intelligence Core (Capabilities 1–12)

| # | Capability | Status |
|---|---|---|
| 1 | Isolation Forest ML anomaly detection + SHAP explainability | ✅ **COMPLETE** (Days 1–5). Full React panel: ModelStatusBar, ScanHostForm, DetectionsTable, DetectionDetailModal with 12-feature SHAP bars, ModelVersionsTable. SHAP via TreeExplainer (0.2ms/call). |
| 2 | Per-device behavioural baseline (mean/std/Z-score) | ✅ **COMPLETE** — `device_baseline_builder.py` builds baselines from real scan data using FEATURE_ORDER vocabulary; `device_deviation_detector.py` computes Z-scores per feature; /predict_real returns both Isolation Forest + behavioral results; 12h Celery Beat rebuild; `BehavioralAIPage` extended with Device Baselines tab + 12-feature breakdown; AnomalyResultCard shows behavioral deviation inline. |
| 3 | Automated ML pipeline (Celery retrain every 24 h) | ✅ **COMPLETE** (D3) |
| 4 | AlienVault OTX threat intelligence integration | ✅ **COMPLETE** — `otx_client.py` (96 lines, key never logged), `cross_reference.py` (119 lines, DB-local <1ms lookup), `sync_otx_threat_intel` Celery task (6h Beat schedule), 45,750 IOCs from 1,000 pulses on first sync; `/predict_real` returns three independent verdicts (Isolation Forest + behavioral + threat intel); standalone `ThreatIntelPanel` React component (SyncControlBar, CheckHostForm, RecentIOCsTable); 17 backend tests. |
| 5 | CISA KEV exploit validation (actively exploited CVEs) | ✅ **COMPLETE** — `kev_catalog` table (PK=cve_id, 1,583 entries), `kev_client.py` (no API key — CISA is public), `kev_cross_reference.py` (local DB IN-query, <1ms), `sync_cisa_kev` Celery task (daily Beat), 5 new endpoints, `/predict_real` now returns four independent verdicts (adds KEV as 4th); `KevPanel` React component (KevSyncBar, KevCheckHostForm, KevCatalogTable, KevDetailModal); 21 backend tests. |
| 6 | MITRE ATT&CK live mapping | Pending |
| 7 | Central event pipeline (all 93 modules feed one brain) | Pending |
| 8 | Automated response chain (scanner → SIEM → compliance → report) | Pending |
| 9 | Unified real-time risk score (all modules contribute) | Pending |
| 10 | Claude API powered Ask AIPET (answers about YOUR environment) | Pending |
| 11 | Predictive risk engine (90-day breach probability forecast) | Pending |
| 12 | AI-written weekly security briefings | Pending |

### Month 2 — Deep Scanner + Firmware (Capabilities 13–16)

| # | Capability |
|---|---|
| 13 | Firmware analysis engine (binwalk — extract, analyse, find hardcoded passwords) |
| 14 | Exploit path mapping (attack chain visualisation) |
| 15 | Real network topology graph (from Nmap data — interactive) |
| 16 | Shodan API integration (internet exposure check) |

### Month 3 — Autonomous Platform (Capabilities 17–20)

| # | Capability |
|---|---|
| 17 | Automated response playbooks (isolate, snapshot, rotate credentials) |
| 18 | Digital twin simulator (attack scenario modelling) |
| 19 | Zero trust engine (continuous device trust scoring) |
| 20 | File integrity monitor (hash critical files, alert on change) |

### Month 4 — Global + Mobile (Capabilities 21–24)

| # | Capability |
|---|---|
| 21 | Dark web monitor (HaveIBeenPwned + paste site monitoring) |
| 22 | React Native mobile app (iOS and Android) |
| 23 | Next 11 languages (Hindi, Turkish, Indonesian, Thai, Vietnamese, Polish, Swedish, Norwegian, Danish, Finnish, Hebrew) |
| 24 | Executive war room (full-screen mission control view) |

### Month 5 — Academic Rigour (Capability 25)

| # | Capability |
|---|---|
| 25 | ML benchmarking and evaluation (compare ML vs rule-based, measure accuracy, precision, recall, F1) |

### Cross-Month — Evidence & Executive (Capabilities 26–32)

| # | Capability |
|---|---|
| 26 | Automated screenshot evidence collection (pentest-style, embedded in PDF reports) |
| 27 | Video evidence recording (30-second capture when threat detected) |
| 28 | Digital signature + timestamp on reports (tamper-proof) |
| 29 | Executive one-page summary (CEO-readable in 60 seconds) |
| 30 | Remediation ticket export to Jira/ServiceNow (one-click with evidence) |
| 31 | Board presentation mode (auto-generated PowerPoint from scan results) |
| 32 | Regulatory notification draft (Claude API writes NIS2/GDPR breach letter) |

---

## 7. Startup Command

```bash
sudo pg_ctlcluster 17 main start && cd /home/binyam/AIPET && source venv/bin/activate && bash start_cloud.sh
```

- Frontend dev server: `cd dashboard/frontend/aipet-dashboard && npm start`
- Stop services: `bash stop_cloud.sh`

---

## 8. GitHub

```
https://github.com/Yallewbinyam/AIPET
```

---

## 9. Test Account

| Field | Value |
|---|---|
| Email | `test@aipet.io` |
| Password | `Test1234!` |

---

## 10. SSH Push Command

```bash
eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_aipet && git push origin main
```

---

## 11. Pending Fixes

Gmail SMTP, Sentry DSN, and UptimeRobot tracking moved to the **Pre-Launch Blockers** section above (PLB-4, PLB-5, PLB-6). That table is the single source of truth for all production-blocking items.

---

## 12. Architecture

- **Blueprint pattern** — every module is its own Python package under `dashboard/backend/<module_name>/` containing `__init__.py`, `routes.py`, and (usually) `models.py`
- All blueprints are registered in `dashboard/backend/app_cloud.py`
- **Frontend** is a single-page React app; all routes/views are components in `App.js` (large file — use search)
- **Database migrations** are run manually with Flask-Migrate (`flask db upgrade`)
- **Celery worker + Celery Beat** both started by `start_cloud.sh` (D3). Beat schedule: `sync-nvd-cves-hourly` (3600s) + `retrain-anomaly-model-daily` (86400s) + `sync-otx-threat-intel-every-6-hours` (21600s). PIDs under `pids/`, logs under `logs/`. Redis required before Celery starts (script checks with `redis-cli ping`).
- **OTX_API_KEY required in .env** — get a free key at https://otx.alienvault.com → Settings → API Integration. Without it, the 6-hour OTX sync task returns `{"status": "error"}` silently (non-fatal).
- **CISA KEV is unauthenticated** — no API key needed. Daily sync downloads all 1,583+ entries in one GET request (~2MB JSON). Re-running the sync is safe: `session.merge()` upserts by cve_id PK, producing zero duplicates.
- **Celery systemd templates** at `deploy/systemd/` (PLB-7 closed). `start_cloud.sh` detects if `aipet-celery-worker.service` / `aipet-celery-beat.service` are active; if so, it skips nohup launch (systemd owns those processes). On dev, nohup fallback runs as before. See `deploy/systemd/INSTALL.md` for production install instructions.
- **Gunicorn** serves Flask in production (`gunicorn_config.py`)
- **Nginx** reverse-proxies to Gunicorn (port 5001) and serves the React build

---

## File Quick-Reference

| Purpose | Path |
|---|---|
| Flask entry point | `dashboard/backend/app_cloud.py` |
| DB config + URI | `dashboard/backend/config.py` |
| Shared models | `dashboard/backend/models.py` |
| React app | `dashboard/frontend/aipet-dashboard/src/App.js` |
| i18n setup | `dashboard/frontend/aipet-dashboard/src/i18n.js` |
| Celery app | `dashboard/backend/celery_app.py` |
| Start script | `start_cloud.sh` |
| Stop script | `stop_cloud.sh` |
| Load test | `locustfile.py` |
| Security audit | `scripts/security_audit.sh` |
| Launch checklist | `LAUNCH_CHECKLIST.md` |
| Test suite | `tests/` |
| Pytest config | `pytest.ini` |

---

## Testing

**Framework:** pytest 9.0.2 + pytest-flask 1.3.0

**Location:** `tests/`

**How to run:**
```bash
cd /home/binyam/AIPET && source venv/bin/activate && pytest
```

**Fixtures (defined in `tests/conftest.py`):**

| Fixture | Scope | Description |
|---|---|---|
| `flask_app` | session | App instance with in-memory SQLite, DEBUG=True (bypasses force_https), RATELIMIT_ENABLED=False, JWT tokens never expire |
| `client` | session | Flask test client reused for the whole session |
| `test_user` | session | User row: `test-pytest@aipet.io`, plan=enterprise |
| `auth_headers` | session | `{"Authorization": "Bearer <token>", "Content-Type": "application/json"}` for test_user |

**Test files:**
- `tests/test_ml_anomaly.py` — ml_anomaly blueprint (41 tests: 6 D3 retrain + 10 D4 SHAP). Use as template for every new module.
- `src/components/ml_anomaly/__tests__/` — React component tests (27 frontend tests via @testing-library/react + Jest)
- `tests/test_real_scanner.py` — real_scanner blueprint (1 test: zero-open-ports host persistence with `node_meta.no_open_ports=True`)
- `tests/test_recon.py` — recon/fingerprint blueprint (30 tests)

**Pattern established by:** `tests/test_ml_anomaly.py` — use this as the template for every new module's test file.

Key patterns to copy:
- Declare tests that need NO model first, tests that need a trained model last
- Use a session-scoped `trained_model` fixture with `unittest.mock.patch` on `generate_synthetic` for speed
- Use `db.session.get(Model, id)` not the deprecated `Model.query.get(id)`
- Set env vars in `conftest.py` before any project import (not in pytest.ini)

---

## Lab Environment

The following VMs are used for real-data scanning and anomaly detection testing. All are on a VirtualBox Host-Only network. Kali (the AIPET host) may have its Host-Only IP as `10.0.3.4` or `10.0.3.8` depending on DHCP lease state — verify with `ip addr show eth1` before scanning.

| VM | IP | Role |
|---|---|---|
| Kali (AIPET host) | 10.0.3.4 or 10.0.3.8 | Host running the AIPET backend; also has NAT (eth0 / 10.0.2.15) for internet |
| Metasploitable2 | 10.0.3.11 | Deliberately vulnerable target — used as the anomaly **positive case** for ml_anomaly training. Must be powered on before scanning. |
| xubuntu | 10.0.3.9 | Normal-profile Linux device — intended anomaly **negative case**. Has no open ports by default. After Day 2.5 fix (removed `--open` nmap flag), it appears in scan results with `port_count=0` and `node_meta.no_open_ports=True`. |
| Windows 11 | 10.0.3.10 | Mixed-profile Windows device. Confirmed reachable and scannable. |

Network: Host-Only adapter uses `10.0.3.0/24` subnet. All VMs must have their Host-Only adapter enabled and the VirtualBox Host-Only network active for cross-VM connectivity.

**ml_anomaly scan data status (as of Month 1 W1 D2.6 — 2026-04-24):**

D2.5 corrected the scan data. D2.6 fixed the ML false-positive by replacing zero-fill placeholders with class-mean imputation (see `feature_extraction.py`).

| VM | IP | Ports | CVEs | risk_score | predict_real result (D2.6) |
|---|---|---|---|---|---|
| Metasploitable2 | 10.0.3.11 | **23** (FTP, SSH, Telnet, SMTP, HTTP, MySQL, PostgreSQL, VNC, X11, etc.) | 14 | 100 | `is_anomaly=True`, `severity=high`, score=0.714 ✓ |
| xubuntu | 10.0.3.9 | 0 (`no_open_ports=True`) | 0 | 0 | `is_anomaly=False`, `severity=low`, score=0.355 ✓ |
| Windows 11 | 10.0.3.10 | 1 (TCP 7070) | 5 | 100 | `is_anomaly=True`, `severity=high`, score=0.704 (5 CVEs ≥ threshold) |

**ML placeholder strategy (D2.6):**
- Hosts with `open_port_count >= 5` OR `cve_count >= 5` → placeholder features use **anomaly-class synthetic means** (port-scan / exfiltration pattern)
- All other hosts → placeholder features use **normal-class synthetic means**
- Thresholds sit just above the synthetic normal class maxima (normal: ports ∈ [1,3], CVEs ∈ [0,2])
- Implemented in `dashboard/backend/ml_anomaly/feature_extraction.py` as module-level constants `_NORMAL_MEANS`, `_ANOMALY_MEANS` (computed once from `generate_synthetic(seed=42)`)
- Every prediction response includes `_placeholder_values` dict and `_placeholder_strategy` string for audit

**Sanity check (D2.6 — ALL PASS):** Metasploitable2 → anomaly ✓ | xubuntu → normal ✓ | infrastructure (port count ordering, CVE count) ✓

---

## Deferred Production Tasks

Pre-launch blocker tracking moved to the **Pre-Launch Blockers** section above (PLB-1 through PLB-8). This section now tracks only non-launch deferrals (e.g. Month 2+ feature work and code quality improvements).

| Task | Notes |
|---|---|
| **Replace conditional-mean placeholders with real watch-agent telemetry** | The D2.6 fix uses conditional synthetic class means as placeholders for 9 unobserved ml_anomaly features. Once the watch agent is instrumented (see PLB-8), replace the placeholder logic in `feature_extraction.py` with real measured values and enable `training_mode=real_scans`. Month 2 work. |
| **Polish Pass 1 — World-class UI/UX** | Dedicated 1–2 day session at end of Month 1 (after capability 12 ships). Scope: smooth transitions, skeleton loaders, designed empty/error states, typographic hierarchy, mobile responsiveness verification, accessibility audit, consistent design tokens across all panels. NOT a launch blocker but flagged as a quality concern. |

---

## Standing Reminders for Claude Code

Every Claude Code task that fixes a Pre-Launch Blocker MUST update the table in the Pre-Launch Blockers section to mark the relevant PLB row as Closed with the commit hash and date. Every task that discovers a new blocker MUST add a new PLB-N row. Do not trust memory across sessions — trust this file.
