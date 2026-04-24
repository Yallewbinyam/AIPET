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
- **Hourly NVD CVE sync** via Celery Beat
- **Stripe payments** — Free (5 scans), Professional (unlimited), Enterprise (unlimited + API access)
- **PDF report export** via WeasyPrint (A4, page breaks, email delivery)
- **Google OAuth** login
- **User onboarding wizard** and password reset flow
- **Python device agent** — live CPU/mem/disk/process/network telemetry every 30 s
- **Load tested** — Locust, 100 concurrent virtual users, 4 task types
- **Sentry error monitoring** wired (DSN pending — see Pending Fixes)
- **UptimeRobot** `/api/ping` endpoint in place (configuration pending)
- **Last commit tag:** `Pre-Month1: all fixes complete, ready for depth phase`

---

## 5. What Is Built — Major Capabilities

All modules live under `dashboard/backend/<module_name>/` as a Blueprint with `__init__.py` + `routes.py` (and usually `models.py`). All are registered in `app_cloud.py`.

| Module | Capability |
|---|---|
| `auth` | JWT login, registration, Google OAuth, password reset |
| `payments` | Stripe subscriptions, webhooks, billing portal |
| `real_scanner` | Nmap host/service/OS scan, NVD CVE matching |
| `live_cves` | Hourly NVD sync, auto-rematch scans |
| `siem` / `cloud_siem` | SIEM event ingestion and dashboards |
| `threatintel` / `threat_intel_ingest` / `threat_radar` | Threat intelligence feeds, IOC tracking |
| `aisoc` / `soc_twin` | AI-assisted SOC automation and digital twin |
| `adversary_profiling` | Attacker profiling and TTP mapping |
| `attackpath` | Attack path analysis and visualisation |
| `redteam` | Red team tooling and simulation |
| `forensics` | Digital forensics investigation |
| `malware_sandbox` | Malware sandboxing and analysis |
| `behavioral` | Behavioural anomaly detection |
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

## 6. Month 1 Plan — 12 New Capabilities to Build

The platform is now in the **depth phase**. These 12 capabilities are next:

1. **AI Threat Briefing** — daily AI-generated threat briefing email/dashboard panel
2. **Attack Surface Management (ASM)** — continuous external asset discovery and exposure scoring
3. **Deception / Honeypots** — deploy decoy assets, alert on interaction
4. **Automated Pen Test Reports** — full narrative pentest report generation from scan data
5. **Policy-as-Code** — export compliance policies as Terraform/OPA/YAML
6. **Vulnerability Prioritisation (EPSS + CVSS)** — rank CVEs by exploit probability, not just severity
7. **Secrets Scanning** — detect hardcoded credentials in code repositories
8. **Cloud Misconfig Remediation** — one-click fix for detected cloud misconfigurations
9. **Purple Team Playbooks** — structured blue/red exercise playbooks
10. **SLA / Breach Tracking** — track remediation SLAs, alert on breach
11. **Executive Dashboard** — board-level KPI view (risk trend, open criticals, compliance %)
12. **Integrations Hub** — outbound webhooks to Slack, Jira, PagerDuty, ServiceNow

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

| Item | Status | Notes |
|---|---|---|
| **Gmail SMTP** | Pending | Flask-Mail configured; live SMTP credentials not set in production `.env` |
| **Sentry DSN** | Pending | Sentry wired in code (`app_cloud.py`); real DSN not set in production `.env` |
| **UptimeRobot** | Pending | `/api/ping` endpoint live; UptimeRobot monitor not yet created in their dashboard |

All three require adding real values to the production `.env` — no code changes needed.

---

## 12. Architecture

- **Blueprint pattern** — every module is its own Python package under `dashboard/backend/<module_name>/` containing `__init__.py`, `routes.py`, and (usually) `models.py`
- All blueprints are registered in `dashboard/backend/app_cloud.py`
- **Frontend** is a single-page React app; all routes/views are components in `App.js` (large file — use search)
- **Database migrations** are run manually with Flask-Migrate (`flask db upgrade`)
- **Celery Beat** handles scheduled tasks (NVD sync, etc.) — worker and beat process both started by `start_cloud.sh`
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
- `tests/test_ml_anomaly.py` — ml_anomaly blueprint (25 tests). Use as template for every new module.
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

These must be done before the first production deploy to `aipet.io`. Do NOT start these until explicitly tasked.

| Task | Notes |
|---|---|
| **Initialise Alembic and stamp baseline migration** | Flask-Migrate 4.1.0 is installed but `flask db init` has never been run. All 100+ existing tables were created via `db.create_all()`. A baseline migration must be generated and stamped before any future `flask db upgrade` can run in production. |
| **Set Gmail SMTP credentials** | Flask-Mail is wired. Set `SMTP_USER` and `SMTP_PASSWORD` in production `.env`. No code change needed. |
| **Set Sentry DSN** | `sentry_sdk.init()` is guarded by `if _sentry_dsn`. Set `SENTRY_DSN` in production `.env`. No code change needed. |
| **Create UptimeRobot monitor** | `/api/ping` endpoint is live. Create monitor pointing at `https://aipet.io/api/ping` in the UptimeRobot dashboard. |
| **Instrument watch agent for full 12-feature ml_anomaly training** | The endpoint agent currently collects CPU/mem/disk/process/network telemetry but does NOT collect TCP flag counts (SYN, RST), directional byte counts (inbound/outbound split), per-protocol packet counts, or unique destination IP/port counts. These are prerequisites for training ml_anomaly on all 12 FEATURE_ORDER features from real data. The current implementation uses placeholder zeros for 9 of 12 features. This must be completed before `training_mode=real_scans` produces a meaningful model. |
| **Replace conditional-mean placeholders with real watch-agent telemetry** | The D2.6 fix uses conditional synthetic class means as placeholders for the 9 unobserved network features. This heuristic is pragmatically correct but not a permanent solution — when the watch agent is instrumented to collect packet_rate, syn_ratio, rst_ratio, etc., replace the placeholder logic in `feature_extraction.py` with real measured values. At that point, `training_mode=real_scans` can also be enabled once ≥20 completed scans exist. |
