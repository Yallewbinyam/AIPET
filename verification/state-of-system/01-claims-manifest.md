# State-of-System Audit — Phase 1: Claims Manifest

**Date:** 2026-04-28
**Author:** Claude Code (Opus 4.7) under user-supervised audit
**Phase:** 1 of 4 — enumeration only, no verification yet
**HEAD at start:** `f7b42659`
**HEAD after rule adoption (Phase 0):** `d0d3bd81`

---

## Sources audited

- `CLAUDE.md` — sections 4 (Current State), Pre-Launch Blockers, 5 (What Is Built), 6 (Capability Roadmap), 12 (Architecture)
- `git log --all --oneline` — every commit message containing `complete`, `shipped`, `done`, numbered `Capability`, numbered `Prompt`, numbered `Phase`, numbered `Module`
- `~/.claude/projects/.../memory/` — **EMPTY** (no user-level memories captured yet)
- `verification/` — closure reports for PLB-1, PLB-4, PLB-5/6, PLB-9, soft-delete (these are evidence FOR the audit, not new claims)

---

## A. Capability Roadmap (CLAUDE.md § 6 — "33 Capabilities")

CLAUDE.md current banner: **"Capabilities 1–12 ✅ + Capability 13 (Days 1+2+3) ✅. 13 of 33 capabilities (39%)."**

| # | Claim | Stated date | Backend module expected | Frontend component expected | Endpoints expected |
|---|---|---|---|---|---|
| 1 | Isolation Forest ML + SHAP | Days 1-5 (W1) | `ml_anomaly/` | ModelStatusBar / ScanHostForm / DetectionsTable / DetectionDetailModal / ModelVersionsTable | `/api/ml/anomaly/predict_real` (+ versions, retrain) |
| 2 | Behavioral baseline | unstated | `behavioral/` (`device_baseline_builder.py`, `device_deviation_detector.py`) | BehavioralAIPage + Device Baselines tab | within `/predict_real` |
| 3 | Automated ML pipeline (Celery 24h retrain) | D3 (2026-04-24) | `tasks.py:retrain_anomaly_model` + Beat | none required | `POST /api/ml/anomaly/retrain_now` |
| 4 | AlienVault OTX integration | unstated | `threatintel/` (`otx_client.py`, `cross_reference.py`) + `tasks.py:sync_otx_threat_intel` | `ThreatIntelPanel` (SyncControlBar / CheckHostForm / RecentIOCsTable) | OTX endpoints |
| 5 | CISA KEV exploit validation | unstated | `live_cves/kev_*` + `tasks.py:sync_cisa_kev` | `KevPanel` (KevSyncBar / KevCheckHostForm / KevCatalogTable / KevDetailModal) | 5 KEV endpoints |
| 6 | MITRE ATT&CK live mapping | unstated | `mitre_attack/` (catalog.py, mitre_mapper.py) | `MitrePanel` (catalog + tactic filter + detail modal) | mitre endpoints |
| 7a | Central event pipeline foundation | unstated | `central_events/` (CentralEvent model, emit_event) | `EventsFeedPanel` + `EventDetailModal` + nav entry | `/api/events/feed`, `/api/events/stats`, `/api/events/<id>`, `/api/events/entity/<name>` |
| 7b | Central event pipeline 10 more modules | unstated | wiring across 10 modules (real_scanner, identity_guardian, auth, digitaltwin, otics, redteam, siem, defense, multicloud, zerotrust) | none required | none new |
| 8 | Automated response chain | unstated | `automated_response/` (ResponseThreshold, ResponseHistory, engine.py) | `AutomatedResponsePanel` | 6 endpoints |
| 9 | Unified real-time risk score | unstated | `risk_engine/` (DeviceRiskScore, engine.py) + Beat 5-min | `RiskScoreDashboard` | 5 endpoints, `/predict_real` 6th verdict |
| 10 | Claude Ask AIPET | unstated | `ask/` (context.py, usage.py, AskUsageLog) | `AskPanel` | `POST /api/ask`, `/api/ask/context`, `/api/ask/usage` |
| 11 | Predictive risk engine (ARIMA) | unstated | `risk_forecast/` (DeviceRiskScoreHistory, ForecastAlert) + Beat hourly | `RiskForecastPanel` (recharts) | 7 endpoints |
| 12 | Production-ready PWA + Web Push | unstated | `push_notifications/` (PushSubscription, dispatcher) | `PushNotificationPanel` in Settings + manifest.json + sw.js v4 | 5 push endpoints |
| 12b | AI weekly briefings | — | — | — | Pending (declared so) |
| 13 D1 | Agent API keys + scan ingest | unstated | `agent_keys/` + `agent_scan_ingest/` | `AgentKeysPanel` in Settings | 5 + 1 endpoints |
| 13 D2 | Agent .deb + systemd + watchdog | unstated | `agent/packaging/deb/` + `agent/watchdog.py` | none required | `GET /api/agent/keys/me` |
| 13 D3 | Windows service + installer | 2026-04-28 | `agent/packaging/windows/` + `aipet_agent.py` v1.2.0 | none required | none new |
| 14-33 | (20 remaining capabilities) | not built | — | — | — |

**Banner-vs-row reconciliation:** banner says "13 of 33 (39%)" yet rows 1, 2, 3, 4, 5, 6, 7a, 7b, 8, 9, 10, 11, 12, 13 D1, 13 D2, 13 D3 = 16 ✅ rows. Counting "13" as one capability (3 days), the count is 13 — banner is internally consistent IF you collapse 7a+7b into 7 and the 13 days into 13. Note 7a/7b are claimed separately as ✅ but the merged "7" row also says ✅ — this is rhetorical double-counting in the source document.

**Roadmap formatting bug:** capability 14 appears twice (line 184 has `| 14 | Exploit path mapping... | Pending |` and line 185 has `| 14 | Exploit path mapping... |` with no status column). Capability 15 and 16 are likewise truncated. This is presentation-only but worth flagging.

---

## B. Pre-Launch Blockers (CLAUDE.md § Pre-Launch Blockers)

| ID | Claim | SHA cited in CLAUDE.md | Status claim |
|---|---|---|---|
| PLB-1 | Alembic baseline + backup/restore | `d2fa1b1b` | Closed 2026-04-28 |
| PLB-2 | Flask-Limiter view_functions reassignment | `915e86c9` | Closed 2026-04-25 |
| PLB-3 | Flask-Limiter storage backend | `138f8269` | Closed 2026-04-25 |
| PLB-4 | Gmail SMTP wiring | `3b520bff` | Closed 2026-04-28 (this session) |
| PLB-5 | Sentry DSN + scrubber | `5234bcbf` | Closed 2026-04-28 |
| PLB-6 | UptimeRobot monitor | — | Open (PARTIAL — runbook ready, monitor deferred to launch day) |
| PLB-7 | Celery systemd templates | `1ec88357` | Closed 2026-04-25 |
| PLB-8 | Watch agent instrumentation gaps | — | Open (Month 2) |
| PLB-9 | Capability 13 Windows live verify | `1410fd01` | Closed 2026-04-28 |

---

## C. Numbered Prompts (git log only — NOT in CLAUDE.md roadmap)

| Prompt | Claim | Commit | Backend module expected | Frontend component expected |
|---|---|---|---|---|
| 1 | **NOT FOUND** in git log | — | — | — |
| 2 (a) | IAM + RBAC backend | `25683397` | `iam/` | — |
| 2 (b) | Team & Access UI | `4ebecdcf` | — | `TeamAccessPage` (**known broken — file missing**) |
| 3 | SIEM — events, incidents, rules | `e8f6fc83` | `siem/` or `cloud_siem/` | SIEM React components |
| 4 | Threat Intel — IOC + AbuseIPDB | `d779172c` | `threatintel/` | ThreatIntel React components |
| 5 | **NOT FOUND** in git log | — | — | — |
| 6 | Autonomous Defense — playbooks | `5a22e1ce` | `defense/` or `defense_mesh/` | Defense React components |
| 7 | AI SOC — Claude analyst | `f40bd01e` | `aisoc/` | AI SOC React components |
| 8 | OT/ICS — Modbus/DNP3/IEC61850/EtherNet IP/BACnet | `d4a5356c` | `otics/` + `protocols/` | OTICS React components |
| 9 | Multi-Cloud — AWS/Azure/GCP/OnPrem | `1ad5fd0f` | `multicloud/` or `multicloud_scale/` | MultiCloud components |
| 10 | Digital Twin — graph, divergence, simulation, snapshots | `d11d59f8` | `digitaltwin/` or `digital_twin_v2/` | DigitalTwin components |
| 11 | AI Red Team — campaigns, simulation, defence scoring | `24a61e02` | `redteam/` | RedTeam components |
| 12 | Marketplace — 15 plugins | `4078bf44` | `marketplace/` | Marketplace components |

---

## D. Numbered "Capability #N" commits (legacy Phase 5 numbering — DIFFERENT from 33-capability roadmap)

| # | Claim | Commit | Note |
|---|---|---|---|
| #8 | ITDR | `ddef208a` | maps to `itdr/` blueprint |
| #9 | Runtime Workload Protection | `18a8af08` | maps to `runtime_protection/` |
| #10 | Threat Intel Ingestion | `b5ad58a6` (also `a37ee8c2`) | TWO commits for same number |
| #11 | Adversary Profiling Engine | `3cd8643e` | `adversary_profiling/` |
| #12 | Malware Analysis Sandbox | `eac79361` | `malware_sandbox/` |
| #13 | APM Engine | `37dcd231` | `apm_engine/` |
| #14 | Log Ingestion + Analytics | `a6ba69bc` | `log_analytics/` |
| #15 | Metrics + Traces Pipeline | `73a991f0` | `metrics_traces/` |
| #16 | Cloud SIEM Correlation Engine | `f7bdab15` | `cloud_siem/` |
| #17 | Real-Time Dashboards | `ba9f03b3` | `realtime_dashboards/` |
| #18 | Synthetic Monitoring | `1d6d663a` | `synthetic_monitoring/` |
| #29 | Compliance Automation Engine | `ed111941` | `compliance_automation/` |
| #30 | Enterprise RBAC + SSO | `ceed5759` | `enterprise_rbac/` |
| #31 | Multi-Tenant Architecture | `ad45d56a` | `multi_tenant/` |
| #32 | Enterprise Reporting | `40d8a4c3` | `enterprise_reporting/` |

**Numbering conflict:** these "Capability #N" commits use a different numbering than the current 33-capability roadmap. e.g. legacy #30 (Enterprise RBAC + SSO) is not in the 33-capability list at all, but blueprint `enterprise_rbac/` exists. Roadmap was rewritten 2026-04-24 (commit `2e6281d6`). Legacy numbering is a separate axis — what was historically "#1-#32" is mostly merged into the 93-blueprint count in CLAUDE.md § 5.

---

## E. Numbered "Module #N" commits (Phase 5C wave — Apr 2026)

| # | Claim | Commit |
|---|---|---|
| #36 | AI Forensics Engine | `8c01e371` |
| #37 | Autonomous Compliance Fabric | `199a8e93` |
| #38 | AI Identity Guardian | `78b3ec4b` |
| #39 | Cognitive SOC Twin | `527dff2a` |
| #40 | AI Policy Brain | `9175e642` |
| #41 | Global Threat Radar | `518a5d93` |
| #42 | Autonomous Cloud Hardener | `b1a2e93c` |
| #43 | Autonomous Patch Brain | `56ad3426` |
| #44 | Autonomous Architecture Builder | `5d87ce2f` |
| #45 | Cognitive Digital Twin v2 | `eb327b7` |
| #46 | Global Defense Mesh | `4b67b6f0` |
| #47 | Code Security Engine | `965fb8c9` (also `317333df` frontend) |

Each commit message claims "complete (backend, DB, frontend)". Modules #1-#35 not in the searched commit window (or numbered differently in earlier commits).

---

## F. "Wiz Gap" / "CrowdStrike Gap" commits

| Claim | Commit |
|---|---|
| Cloud Runtime Scanner | `0ec14a62` |
| Kubernetes Runtime Analyzer | `f8989f37` |
| Cloud Network Exposure Graph | `4c8e8449` |
| IAM Exposure Analyzer | `37b82e30` |
| Enterprise Cloud Dashboards | `d476b02a` |
| Multi-Cloud Scale Engine | `1141e4b7` |
| Endpoint Agent (CrowdStrike Gap) | `c44dd81d` |

---

## G. The "10 new modules" commit (`89662f40`)

Title: `feat: add 10 new modules — Issue Tracking, PRD Generator, Sprint Planner, Dev Workflow, Team Collab, Edge Deployment, AI SDK, Zero-Config Deploy, AI UI Generator, CDN+Edge`

Diff shape: **`dashboard/frontend/aipet-dashboard/src/App.js | 1364 ++++++++++++++`** — frontend-only, no backend, no models, no tests. 1,364 lines added to App.js.

**These ten "modules" are not security capabilities** — they are SaaS-platform/devtooling features. None appear in the 33-capability roadmap. None appear in CLAUDE.md § 5 ("What Is Built — Major Capabilities"). They occupy nav real estate but their backend status is unverified.

10 names to verify in Phase 2:
- Issue Tracking
- PRD Generator
- Sprint Planner
- Dev Workflow
- Team Collab
- Edge Deployment
- AI SDK
- Zero-Config Deploy
- AI UI Generator
- CDN+Edge

---

## H. Three IAM directories (CLAUDE.md § 5)

| Directory | Origin commit | Purpose claimed | Overlap |
|---|---|---|---|
| `dashboard/backend/iam/` | `25683397` (Prompt 2 backend) | IAM + RBAC backend (roles, permissions, audit log, SSO) | base layer |
| `dashboard/backend/enterprise_rbac/` | `ceed5759` (Capability #30) | Enterprise RBAC + SSO | overlaps with `iam/`? |
| `dashboard/backend/iam_exposure/` | `37b82e30` (Wiz Gap) | IAM Exposure Analyzer | distinct (cloud IAM exposure findings, not auth) |

Relationship/overlap to be resolved in Phase 2.

---

## I. CLAUDE.md § 5 ("What Is Built — Major Capabilities") — full blueprint list

The doc lists ~58 distinct blueprint names with one-line capability descriptions. Each is implicitly claimed VERIFIED. Subset:

`auth`, `payments`, `real_scanner`, `live_cves`, `mitre_attack`, `central_events`, `risk_engine`, `risk_forecast`, `automated_response`, `push_notifications`, `siem`/`cloud_siem`, `threatintel`/`threat_intel_ingest`/`threat_radar`, `aisoc`/`soc_twin`, `adversary_profiling`, `attackpath`, `redteam`, `forensics`, `malware_sandbox`, `behavioral`, `incidents`, `remediation`, `defense`/`defense_mesh`, `zerotrust`, `identity_guardian`/`iam`/`iam_exposure`/`identitygraph`, `itdr`, `compliance`/`complianceauto`/`compliance_automation`/`compliance_fabric`, `dspm`, `cloud_hardener`/`cloud_runtime`/`cloud_dashboard`, `multicloud`/`multicloud_scale`, `costsecurity`, `k8s_analyzer`, `apisecurity`, `code_security`, `supplychain`, `endpoint_agent`/`agent_monitor`, `agent_keys`, `agent_scan_ingest`, `runtime_protection`, `network_exposure`/`netvisualizer`, `digitaltwin`/`digital_twin_v2`, `driftdetector`, `patch_brain`, `predict`, `score`, `apm_engine`, `metrics_traces`, `log_analytics`, `realtime_dashboards`, `monitoring`/`synthetic_monitoring`, `arch_builder`, `map`, `timeline`/`timeline_enhanced`, `narrative`, `explain`, `ask`, `policy_brain`, `otics`, `protocols`, `enterprise_rbac`, `enterprise_reporting`, `multi_tenant`, `marketplace`, `api_keys`, `settings`, `calendar`, `resilience`, `watch`, `terminal`, `public_scan`, `modules`.

---

## J. Cross-reference: claims with no commit / commits with no manifest entry

To be done in Phase 2. Some flags noticed in Phase 1:

- **Prompt 1** and **Prompt 5**: no commit found. Either deferred without note, absorbed into Phase 5C work, or never attempted.
- **`9c1a52e8 AIPET X production ready — all systems complete`**: aspirational claim made early; not a verified state, not a separable capability.
- **`40d8a4c3 Capability #32: ALL 32 CAPABILITIES COMPLETE v6.3.0`**: a "we're done" marker that predates the current 33-capability roadmap; the numbering it claims to complete is the legacy "Capability #N" series, not the current roadmap's "Capability 1-33" series.

---

## Phase 1 deliverable summary

**Total claims to verify in Phase 2:**

| Category | Count |
|---|---|
| Capability roadmap (33 + 12b + 13 D1/D2/D3) | 17 explicit ✅ rows |
| Pre-Launch Blockers | 9 (7 Closed, 2 Open) |
| Numbered Prompts | 11 (1 + 12 minus 1 and 5 missing) |
| Legacy "Capability #N" commits | 15 |
| Phase 5C "Module #N" commits | 12 |
| Wiz Gap / CrowdStrike Gap | 7 |
| "10 new modules" frontend-only commit | 10 |
| Three IAM directories | 3 |
| **Total distinct claims** | **~84** (some overlap; many map to the same blueprint via different numbering) |

**Distinct blueprint paths to verify (de-duplicated):** ~58 backend blueprints from CLAUDE.md § 5.

---

## Phase 2 plan

For each item:

1. Backend: `ls dashboard/backend/<name>/` + `grep -n register_blueprint app_cloud.py | grep <name>`
2. Frontend: `grep -n "<ComponentName>" dashboard/frontend/aipet-dashboard/src/App.js`
3. Endpoints: with a valid JWT, `curl http://localhost:5001/<endpoint>` for at least one happy-path endpoint per claim
4. UI sanity: enumerate the route in App.js and confirm the component file exists OR is defined inline

Specific deep-dives required by the brief:
- (a) Confirm `TeamAccessPage` non-existence with `grep` → file:line evidence
- (b) Enumerate every route in `dashboard/backend/iam/routes.py`, curl each
- (c) Test 10 frontend-only modules from `89662f40`
- (d) Capability 30 RBAC + SSO — backend in `enterprise_rbac/`, frontend?
- (e) IAM Exposure Analyzer (`37b82e30`) — backend in `iam_exposure/`, frontend?
- (f) All 33 capabilities classified

Phase 2 results land in `verification/state-of-system/02-verification-results.md`.
