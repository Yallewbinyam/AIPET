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
| `mitre_attack` | MITRE ATT&CK live mapping — 40-technique curated catalog (`catalog.py`), central `mitre_mapper.py` with source-aware functions (ML features → T1110/T1190/T1046, behavioral anomaly_type, KEV CWEs, OTX indicator types), `/predict_real` now returns five independent verdicts. `mitre_techniques` table seeded on startup. |
| `central_events` | Unified event pipeline (Capabilities 7a + 7b). `emit_event()` adapter — non-raising, one INSERT per call, user-scoped, <10ms. **15 modules wired** (5 from 7a + 10 from 7b: real_scanner, identity_guardian, auth, digitaltwin, otics, redteam, siem, defense, multicloud, zerotrust). siem ingest includes cycle-prevention via `node_meta.from_central_emit` flag. 8 modules dual-write (siem_events + central_events). Cross-module event feed at `/api/events/feed` with severity/module/entity filters, `/api/events/stats`, `/api/events/<id>`, `/api/events/entity/<name>`. `EventsFeedPanel` + `EventDetailModal` React UI. |
| `risk_engine` | Unified real-time risk score per device (Capability 9). Reads from `central_events` with 8-hour half-life exponential decay (formula: score = min(100, Σ[base × source_mult × 2^(-age/8h)])). Weighted by severity + source module. Celery Beat recompute every 5 minutes. `/predict_real` returns it as 6th verdict. 5 REST endpoints. `RiskScoreDashboard` React panel with `RiskTopBar`, `RiskScoreTable`, `RiskBreakdownModal`. |
| `risk_forecast` | ARIMA-based predictive risk forecasting (Capability 11). `DeviceRiskScoreHistory` table snapshotted on every Cap 9 5-min recompute. Three-tier model: insufficient_data (<10 pts) / low_confidence linear (10–29 pts) / ok ARIMA(1,1,1) (30+ pts). `ForecastAlert` table for predicted crossings within 48h. Hourly Celery task + weekly 30-day prune. Does NOT trigger Cap 8 — analyst alerts only. `RiskForecastPanel` React UI with recharts confidence interval chart. |
| `automated_response` | Automated response chain (Capability 8). Watches `device_risk_scores` after each 5-min recompute. Per-user thresholds: notify ≥60, high_alert ≥80, emergency ≥95. Per-entity 4-hour cooldown tracked in `response_history` table (NOT `DefensePlaybook.last_triggered` which stays for the manual path). `send_alert` action now calls `settings/routes.send_slack_alert()` + `send_teams_alert()` when webhooks configured (was previously a silent DB-only write). Emits `automated_response_triggered` to `central_events` after each fire. 6 REST endpoints. `AutomatedResponsePanel` React panel with threshold editing, history table, stats bar. |
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

## 6. Capability Roadmap — 33 Capabilities

**Current status:** Capabilities 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 ✅ Complete. 22 remaining (12–32).

### Month 1 — Intelligence Core (Capabilities 1–12)

| # | Capability | Status |
|---|---|---|
| 1 | Isolation Forest ML anomaly detection + SHAP explainability | ✅ **COMPLETE** (Days 1–5). Full React panel: ModelStatusBar, ScanHostForm, DetectionsTable, DetectionDetailModal with 12-feature SHAP bars, ModelVersionsTable. SHAP via TreeExplainer (0.2ms/call). |
| 2 | Per-device behavioural baseline (mean/std/Z-score) | ✅ **COMPLETE** — `device_baseline_builder.py` builds baselines from real scan data using FEATURE_ORDER vocabulary; `device_deviation_detector.py` computes Z-scores per feature; /predict_real returns both Isolation Forest + behavioral results; 12h Celery Beat rebuild; `BehavioralAIPage` extended with Device Baselines tab + 12-feature breakdown; AnomalyResultCard shows behavioral deviation inline. |
| 3 | Automated ML pipeline (Celery retrain every 24 h) | ✅ **COMPLETE** (D3) |
| 4 | AlienVault OTX threat intelligence integration | ✅ **COMPLETE** — `otx_client.py` (96 lines, key never logged), `cross_reference.py` (119 lines, DB-local <1ms lookup), `sync_otx_threat_intel` Celery task (6h Beat schedule), 45,750 IOCs from 1,000 pulses on first sync; `/predict_real` returns three independent verdicts (Isolation Forest + behavioral + threat intel); standalone `ThreatIntelPanel` React component (SyncControlBar, CheckHostForm, RecentIOCsTable); 17 backend tests. |
| 5 | CISA KEV exploit validation (actively exploited CVEs) | ✅ **COMPLETE** — `kev_catalog` table (PK=cve_id, 1,583 entries), `kev_client.py` (no API key — CISA is public), `kev_cross_reference.py` (local DB IN-query, <1ms), `sync_cisa_kev` Celery task (daily Beat), 5 new endpoints, `/predict_real` now returns four independent verdicts (adds KEV as 4th); `KevPanel` React component (KevSyncBar, KevCheckHostForm, KevCatalogTable, KevDetailModal); 21 backend tests. |
| 6 | MITRE ATT&CK live mapping | ✅ **COMPLETE** — `mitre_attack/` module: 40-technique `TECHNIQUE_CATALOG`, `mitre_mapper.py` (5 source-aware functions), `mitre_techniques` DB table (seeded on startup); `/predict_real` returns five independent verdicts with ATT&CK aggregation; T1071 hardcoding bug fixed in `device_deviation_detector.py`; `MitrePanel` React component (catalog browser + tactic filter + detail modal); 23 backend tests. |
| 7a | Central event pipeline — foundation + 5 modules wired | ✅ **COMPLETE** — `central_events/` module: `CentralEvent` model (16 columns, 11 indexes), `emit_event()` adapter (non-raising, <10ms, user-scoped), 4 REST endpoints (`/api/events/feed`, `/api/events/stats`, `/api/events/<id>`, `/api/events/entity/<name>`); wired into ml_anomaly, behavioral, threatintel (OTX), live_cves (KEV), mitre_attack; `EventsFeedPanel` + `EventDetailModal` React components, "Security Events" nav entry; 19 backend tests (includes resilience test: parent route returns 200 when emit_event raises). Fixes: `BigInteger→Integer` for SQLite compat, lazy→module-level imports in adapter. |
| 7b | Central event pipeline — 10 additional modules wired | ✅ **COMPLETE** — Group A: real_scanner (scan_completed), identity_guardian (identity_guardian_alert), auth (user_login, user_login_failed, user_registered). Group B: digitaltwin (twin_divergence loop + twin_simulation), otics (ot_ics_finding per critical), redteam (redteam_finding per success) — all dual-write (siem_events retained). Group C: siem (with cycle-prevention via `node_meta.from_central_emit`), defense (_execute_action returns Optional[SiemEvent], both callers emit after commit), multicloud (cloud_finding per critical), zerotrust (_ingest_siem_zt returns Optional[SiemEvent], 4 callers updated). 15 modules wired total. |
| 7 (merged) | Central event pipeline (all 93 modules feed one brain) | ✅ Split into 7a + 7b, both complete. 15 of ~93 modules wired. |
| 8 | Automated response chain (scanner → SIEM → compliance → report) | ✅ **COMPLETE** — `automated_response/` module: `ResponseThreshold` (per-user, seeded with 3 defaults: notify≥60, high_alert≥80, emergency≥95) + `ResponseHistory` (per-entity-per-playbook cooldown, 4h default). `check_thresholds_and_respond()` runs inside `recompute_device_risk_scores` Celery task. `send_alert` action wired to `settings.send_slack_alert()` + `send_teams_alert()` (was previously silent). Emits `automated_response_triggered` to central_events. 6 REST endpoints. `AutomatedResponsePanel` React UI. 29 backend tests. |
| 9 | Unified real-time risk score (all modules contribute) | ✅ **COMPLETE** — `risk_engine/` module: `DeviceRiskScore` model (11 columns, 6 indexes incl. `(user_id, score)` for C8 queries), `engine.py` (formula: `min(100, Σ[base × SOURCE_MULTIPLIERS × 2^(-age/8h)])`, SEVERITY_POINTS dict, 24h lookback), `recompute_all_scores()` (idempotent UPSERT), Celery Beat 5-min recompute, 5 REST endpoints, `RiskScoreDashboard` React panel; `/predict_real` returns score as 6th verdict (live compute + stored comparison); 29 backend tests including clamp-at-100 and time-decay verification. |
| 10 | Claude API powered Ask AIPET (answers about YOUR environment) | ✅ **COMPLETE** — `ask/` module upgraded: `explain/claude_client.py` migrated to `anthropic` SDK 0.97.0 (was raw `urllib`), now uses proper `system` parameter and returns `input_tokens` for cost tracking. `ask/context.py` extended with 9 new sections (device_risk_scores, central_events, ml_anomaly_detections, kev_catalog, ioc_entries, mitre_techniques, ba_anomalies, response_history, real_scan_results); total context ~4.5KB. `ask/usage.py`: `AskUsageLog` table (unique on user_id+date), `check_daily_limit()`, `check_and_record_usage()`. Limits: Professional 50/day, Enterprise 500/day. 3 endpoints: `POST /api/ask` (with 429 enforcement), `GET /api/ask/context`, `GET /api/ask/usage`. Rate limit: 20 req/min via view_functions. 24 backend tests. Live test: Claude answered Capability 8-aware question (device 10.0.255.1, risk score 100, emergency threshold) in 13.7s. |
| 11 | Predictive risk engine (90-day breach probability forecast) | ✅ **COMPLETE** — `risk_forecast/` module: `DeviceRiskScoreHistory` (snapshotted every 5-min by Cap 9 Celery task, composite index `(user_id,entity,entity_type,snapshot_at)`), `ForecastAlert` (unique on `(user_id,entity,threshold_name,status)`, 48h-horizon only). Engine: 3-tier confidence (insufficient_data <10 pts / low_confidence linear 10-29 pts / ok ARIMA(1,1,1) 30+ pts). statsmodels 0.14.6. Hourly Celery Beat + weekly prune task (30-day retention). 7 REST endpoints. `RiskForecastPanel` React UI with recharts confidence interval shading. Cap 11 raises analyst alerts ONLY — does NOT trigger Cap 8 automated responses (design decision). 28 backend tests. Live: 35-pt trending entity → ok/linear forecast, emergency alert created, response_history unchanged. |
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
- **Risk forecast engine** (`risk_forecast/`) — forecasting pipeline is decoupled from automated response. `DeviceRiskScoreHistory` accumulates snapshots every 5 min; `forecast_all_entities()` runs hourly. ARIMA(1,1,1) requires ≥30 daily observations; falls back to `numpy.polyfit` linear when resampling produces <2 daily points (e.g. first hour of operation). `ForecastAlert` unique constraint `(user_id, entity, threshold_name, status='active')` prevents duplicate active alerts per entity per threshold. Cap 11 alerts are READ ONLY from Cap 8's perspective — no join to `response_history`.
- **Risk score engine** (`risk_engine/`) — formula constants at module level in `engine.py`, reviewable without reading computation logic: `SEVERITY_POINTS = {critical:60, high:35, medium:15, low:8, info:2}`, `SOURCE_MULTIPLIERS = {ml_anomaly:1.0, live_cves:1.2, threatintel:1.1, behavioral:0.9, mitre_attack:0.7, real_scanner:0.8, redteam:1.0, defense:0.6, auth:0.6, siem:0.7, multicloud:0.9, otics:1.0, zerotrust:0.9, identity_guardian:1.0, digitaltwin:0.5}`, `HALF_LIFE_HOURS=8`, `LOOKBACK_HOURS=24`. Capability 8 queries `device_risk_scores` via `filter(user_id==uid, score>=threshold)` using the `ix_device_risk_user_score` composite index.
- **Automated response** (`automated_response/`) — runs inside `recompute_device_risk_scores` Celery task after scores refresh. Per-entity cooldown tracked in `response_history.fired_at` (NOT `DefensePlaybook.last_triggered` — that stays for the manual path). Default thresholds seeded lazily (idempotent) on first API call. `send_alert` action now calls `settings.send_slack_alert()` + `send_teams_alert()` when webhooks configured; failure is non-fatal (logged, slack_sent=False, status still "executed"). `_execute_action` now returns 3-tuple `(log, siem_ev, notif_meta)` — existing manual callers use `_`.
- **Central event pipeline** (`central_events/`) — synchronous `emit_event()` call inserted after each module commits its domain row. Failures are always silent (try/except + rollback in adapter; belt-and-suspenders try/except at each call site). Every event carries `user_id` for per-user scoping. 8 modules dual-write (siem_events + central_events); refactor to single-source is a future task. Cycle prevention in siem/ingest: if incoming event has `node_meta.from_central_emit=True`, the emit is skipped to break re-ingest loops. The `_execute_action` helper in defense returns `(log, Optional[SiemEvent])`; `_ingest_siem_zt` in zerotrust returns `Optional[SiemEvent]` — callers emit after their respective commits.
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
| **T1071 hardcoding bug (FIXED in Capability 6)** | Introduced in Capability 2 (`device_deviation_detector.py` line 172 — `mitre_id = "T1071"` unconditionally). Found during Capability 6 recon — 10 of 17 ba_anomalies rows were mislabelled T1071 regardless of actual detected behaviour. Fixed in commit 83b41bf3+: now calls `from_behavioral_deviations(top5)` to derive the correct technique from the top-deviating feature. Historical rows left intact per backward-compat policy. |
| **Polish Pass 1 — World-class UI/UX** | Dedicated 1–2 day session at end of Month 1 (after capability 12 ships). Scope: smooth transitions, skeleton loaders, designed empty/error states, typographic hierarchy, mobile responsiveness verification, accessibility audit, consistent design tokens across all panels. NOT a launch blocker but flagged as a quality concern. |

---

## Standing Reminders for Claude Code

Every Claude Code task that fixes a Pre-Launch Blocker MUST update the table in the Pre-Launch Blockers section to mark the relevant PLB row as Closed with the commit hash and date. Every task that discovers a new blocker MUST add a new PLB-N row. Do not trust memory across sessions — trust this file.
