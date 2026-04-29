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

## Definition of "Complete"

As of 2026-04-28, AIPET X uses the following rule for marking any
capability, PLB, or feature as Complete:

A capability is Complete only when ALL FOUR conditions hold:

1. All acceptance tests pass.
2. A human clicked every UI element exposed by the capability,
   in a real browser, on a fresh page load, against the latest
   commit. (For non-UI capabilities: live curl/CLI verification
   of every endpoint, command, or job.)
3. Live verification confirms every endpoint or behaviour
   responds as documented (correct status codes, response shapes,
   side effects).
4. The verification report names the actor, date, commit SHA,
   and lists every checked element.

Tests passing alone = TESTED, not COMPLETE.

Retroactive: any capability or PLB previously marked ✅/CLOSED
that has not been verified against this rule must be re-audited
or downgraded to TESTED until verified. The state-of-system
inventory begun on 2026-04-28 (verification/state-of-system/)
applies this rule to every existing claim.

---

## State-of-System Audit, 2026-04-28

A full state-of-system inventory was performed on 2026-04-28 after the Team & Access UI bug was discovered (TeamAccessPage component never built; routing crashes on click; twelve days latent). This was the third feature this week found to be partially or fully broken despite being declared Complete (PLB-9 NSSM AppExit watchdog, flask-migrate Migrate(app,db) latent crash, Team & Access UI). Three is a pattern. The audit re-classifies every existing ✅/Complete/Closed claim against the new "Tested vs Complete" rule above.

**Evidence:** `verification/state-of-system/01-claims-manifest.md`, `verification/state-of-system/02-verification-results.md`, `verification/state-of-system/REPORT-2026-04-28.md`.

**Team & Access follow-up F1 closed (2026-04-28):** `seed_default_roles()` was imported at `app_cloud.py:66` but never invoked, leaving the DB with 1 of 4 roles and 0 of 10 permissions. Wired into the existing `with app.app_context()` startup block next to the MITRE seed; idempotent across restarts; pinned by 2 pytest cases (`tests/test_iam_seed.py`). DB now seeded 4 roles + 10 permissions on app boot. Endpoints still 403 by default until users are role-assigned (separate follow-up). Phase A backend audit + F1 closure: `verification/team-access/PHASE-A-backend-audit-2026-04-28.md`. Fourth wire-not-connected bug fixed this week (the others: TeamAccessPage, flask-migrate, PLB-9 NSSM AppExit).

**Team & Access follow-up F2 closed (2026-04-28, commit `f2e9174e`):** role assignment on registration + backfill. New `assign_role_to_user()` helper in `iam/routes.py` (idempotent, audit-logging via `node_meta={"role": ..., "reason": ...}`). `auth/routes.py:register()` now auto-assigns `owner` to new users. One-off SQL backfill applied to byallew@gmail.com + test@aipet.io (NOT recurring code). All 6 IAM endpoints that 403'd in F1 verify now return non-403 for owner-assigned users. **Multi-tenancy in the data model remains an open foundation gap** — `tenant_id` is absent from User/UserRole/Role/AuditLog/SSOProvider, so the `owner` role is currently global. Documented as out-of-scope for F2; tracked as a separate larger task (1-2 days, schema migration touching every role-scoped query). 503 tests passing.

**Headline counts** (across ~103 distinct claims):

| Classification | Count | Meaning |
|---|---|---|
| **VERIFIED** (mechanically — backend blueprint registered + frontend Page present + sample endpoint live) | ~63 | Wired and reachable. NOT yet "Complete" per the new rule (no human click-through verification) — these are TESTED-AND-WIRED. |
| **PARTIAL** | 7 | Wiring exists; specific gap (path-uncertain, install-missing, or naming-misleading). |
| **NOT-PRESENT, KNOWN-BAD** | 11 | Claim has no working implementation (1 + 10). |
| **NOT-PRESENT, correctly deferred** | 22 | Roadmap rows correctly marked Pending. |
| **UNCERTAIN** | 0 | None hit the 30-min cap. |

### Mis-claimed Features (Audit 2026-04-28)

These items were declared Complete in commit messages or CLAUDE.md but do **not** have working end-to-end implementations:

1. **Team & Access UI** (Prompt 2 frontend, commit `4ebecdcf`, 2026-04-16) — `TeamAccessPage` component **never built**. App.js routing block (lines 30423-30430 in commit `f7b42659`) references a component that does not exist anywhere in the codebase. User commented out the routing block 2026-04-28 as a stop-gap; the `team` sidebar entry remains visible but the click target is now hidden behind a comment. **Backend IAM is functional** (`iam/` module, 8 routes at `/api/iam/*`, two of which are admin-gated and correctly return 403 to non-owner users). Building the frontend page is ~2 hours of work. Sidebar entry should be hidden until built.

2. **The "10 new modules" of commit `89662f40`** (2026-04-23) — frontend-only ghost modules. 1,364 lines added to App.js with **zero backend implementation**. Each Page calls non-existent endpoints (`/api/prd/generate`, `/api/issuetracking*`, etc.) and returns 404 on any user action. They are also **not security capabilities** — they are SaaS-platform / dev-tooling features (Issue Tracking, AI PRD Generator, AI Sprint Planner, Dev Workflow, Team Collaboration, Edge Deployment, AI SDK, Zero-Config Deploy, AI UI Generator, CDN+Edge). They occupy nav real estate but do nothing. **Recommended: remove these 10 nav entries and the corresponding Page components from App.js.** They are out of scope for an IoT cybersecurity platform.

3. **Capability #30: "Enterprise RBAC + SSO"** (legacy numbering, commit `ceed5759`) — **mis-named**. Backend `enterprise_rbac/` module has only 4 routes (`/api/enterprise-rbac/assess|roles|history|health`) and is an *RBAC posture assessment* module, not a real RBAC system. The real RBAC lives in `iam/` (Prompt 2 backend). The sidebar label "RBAC + SSO" overstates what this module does. **Recommended: rename module to `enterprise_rbac_assessment/` and re-label sidebar to "RBAC Assessment" to disambiguate from `iam/`.**

### Module-overlap debt (audit observations)

The codebase has accumulated significant overlap between modules with similar names:

- **6 IAM-ish dirs**: `iam/`, `enterprise_rbac/`, `iam_exposure/`, `identity_guardian/`, `identitygraph/`, `itdr/`. Only `iam/` is the real auth/RBAC; the rest address adjacent concerns. The naming makes it hard for a new contributor to know which file owns which behaviour.
- **4 Compliance dirs**: `compliance/`, `complianceauto/`, `compliance_automation/`, `compliance_fabric/`.
- **3 Threat-Intel dirs**: `threatintel/`, `threat_intel_ingest/`, `threat_radar/`.
- **2 Defense, 2 Multi-Cloud, 2 Digital-Twin, 2 SOC, 2 SIEM, 2 Timeline, 3 Network-Map dirs.**

**Not in scope for this audit to fix.** Documented for future consolidation passes.

### Limitations of this audit

- **No click-through performed.** VERIFIED here means mechanically wired (backend blueprint registered, frontend Page present, representative endpoint returns 200 to curl). It does not satisfy the new "Tested vs Complete" rule's requirement of a human clicking every UI element. A separate click-through pass is needed to upgrade VERIFIED → Complete for any item where Complete actually matters (production capabilities, customer-visible claims).
- **Endpoint coverage was sample-based**, not exhaustive. ~26 endpoints curled across capabilities; full enumeration of all 89 registered blueprints' routes is left to a future audit.
- **Six false-positive 404s** during breadth-curl were due to me guessing wrong endpoint paths (e.g. `/api/digitaltwin/snapshots`); the blueprint exists, just the path differs. These are classified PARTIAL pending exact-path confirmation, not NOT-PRESENT.
- **No frontend-route exhaustion test.** The 102 `activeTab === "<id>"` branches in App.js were not all individually click-rendered against the latest commit.

---

## 4. Current State

- **89 backend blueprints registered** (verified 2026-04-28: `grep -c register_blueprint app_cloud.py` = 89) — most respond 200 to representative endpoint curls. The "93+ modules complete" headline used pre-audit was looser; the audit-verified count of registered blueprints is 89, and "complete" was a presentation-level claim, not an end-to-end click-tested guarantee. See state-of-system audit (above) for detail.
- **Production hardening done** — Flask-Talisman CSP/HSTS, per-user rate limiting (100 req/min), input validation on all POST endpoints
- **Real Nmap scanner** integrated with NVD CVE matching
- **Celery worker + Beat running** via `start_cloud.sh` (as of D3 / 2026-04-24). NVD sync schedule first observed firing on 2026-04-24, adding 474 CVEs to `live_cves`. Previously Celery was wired but never launched.
- **Automated ML retrain** — `retrain_anomaly_model` task runs every 24 h via Beat; manual trigger via `POST /api/ml/anomaly/retrain_now`; skips gracefully when <20 unique feature vectors available
- **AlienVault OTX** — `sync_otx_threat_intel` runs every 6 h via Beat; first full sync produced 45,750 IOCs from 1,000 pulses (218s). `app_cloud.py` and `tasks.py` both load `.env` via explicit `pathlib.Path(__file__).parents[n]` so the API key reaches the Gunicorn and Celery worker processes regardless of CWD.
- **Stripe payments** — Free (5 scans), Professional (unlimited), Enterprise (unlimited + API access)
- **PDF report export** via WeasyPrint (A4, page breaks, email delivery)
- **Google OAuth** login
- **User onboarding wizard** and password reset flow
- **Python device agent** — live CPU/mem/disk/process/network telemetry every 30 s. Capability 13 Day 2 ships a `.deb` install package (`agent/packaging/`), `curl|sudo bash` installer, security-hardened systemd unit, and a token-revocation watchdog. Linux: live-verified end-to-end (install → start → telemetry → revoke → exit (no restart) → purge). Windows (Day 3): NSSM service, batch installer, AppExit 1 Exit (was Stop — silently invalid; PLB-9 caught it). **Live-verified end-to-end on Windows 11 VM 2026-04-28 (PLB-9): 17/19 PASS, 2/19 PARTIAL.** Final installer SHA256 `84977e61beefacfa87116c03ade24f226d77eecba586671032759ae973f5e6ef`.
- **Load tested** — Locust, 100 concurrent virtual users, 4 task types
- **Sentry error monitoring** live (PLB-5 closed). Real DSN configured in `.env`; three layers of PII scrubbing in `before_send`; 24 unit tests; live events confirmed shipped to the real Sentry project. Runbook: `docs/runbooks/sentry.md`.
- **UptimeRobot** `/api/ping` endpoint ready; monitor creation deferred to launch day (PLB-6 PARTIAL — UptimeRobot probes the public internet and aipet.io is not yet deployed). Runbook + launch-day handover ready: `docs/runbooks/uptime-monitoring.md`.
- **Last commit tag:** `Pre-Month1: all fixes complete, ready for depth phase` (legacy; out-of-date — most recent meaningful waves are PLB-1 through PLB-9 closure 2026-04-25..28, PLB-4 email delivery 2026-04-28, and the state-of-system audit 2026-04-28)

---

## Pre-Launch Blockers

These items must all be resolved before aipet.io accepts real customer traffic. Each task that closes a blocker **MUST** update this table — change Status to `Closed (commit <hash>, <date>)`. Each task that discovers a new blocker **MUST** add a row. This table is the source of truth — not memory, not other documents. Do not let a session end without updating this table if relevant work was done.

| ID | Blocker | Discovered | Effort | Status | Fix-When |
|---|---|---|---|---|---|
| PLB-1 | Alembic migrations — no baseline migration exists for any of the 100+ tables; project is entirely on db.create_all() | Day 1.5 recon | Half day predicted; ~4 hr actual | **Closed (commit `d2fa1b1b`, 2026-04-28). 5 phases / 5 commits / 1 runbook / 1 stamped baseline.** Baseline `68d67bfc6697 "baseline schema"` covers 166 user tables = 165 `__tablename__` + 1 `db.Table('role_permissions')`. Live tested forward (`alembic upgrade head`), back (`alembic downgrade base`), forward again (idempotency), and restore-into-test-DB row-count identical across all 167 tables. Two-role least-privilege convention adopted: `aipet_user` (LOGIN, no CREATEDB) for app, `aipet_admin` (LOGIN, CREATEDB) for migrations -- `ALEMBIC_DATABASE_URL` reads first from env then falls back to `DATABASE_URL`. `scripts/backup.sh` + `scripts/restore.sh` shipped with production typo guard (`restore.sh` refuses target=`aipet_db` without `--i-know-what-im-doing`). Runbook at `docs/runbooks/backup-and-restore.md`. Full report: `verification/plb1/PLB-1-alembic-baseline-2026-04-28.md`. Follow-ups completed (commit `265edf4b`, 2026-04-28): ✅ flask-migrate removed from requirements + venv (was a no-op `Migrate(app, db)` wiring; nothing called the `flask db` CLI it registered); ✅ legacy `dashboard/backend/monitoring/backup.py` deleted + runbook references stripped (had hardcoded `/home/binyam/...` paths, zero remaining code references). Remaining open follow-up: move `aipet_admin_password` from `.env` to a real secrets manager (Vault / AWS SM / 1Password) before any production deploy. | Closed |
| PLB-2 | Flask-Limiter view_functions reassignment pattern not applied to auth/login/register — those rate limits are silent no-ops in Flask-Limiter 4.x | Day 1.5 | 30 min | Closed (commit 915e86c9, 2026-04-25) | Pre-launch hardening sprint |
| PLB-3 | Flask-Limiter storage backend is memory:// per-worker — with 10 Gunicorn workers, effective rate limits are ~10x looser than configured | Day 3 verification (Step 6f) | 5 min | Closed (commit 138f8269, 2026-04-25) | Pre-launch hardening sprint |
| PLB-4 | Gmail SMTP credentials not set in production .env — Flask-Mail wired but cannot send | Day 1 | 5 min config predicted; ~3 hr actual (full init module + graceful skip-if-no-creds + 6 unit tests + live verify + runbook) | **Closed (commit `3b520bff`, 2026-04-28).** Replaces the inline `MAIL_*` config block in `app_cloud.py` with `dashboard/backend/observability/email_setup.py` carrying `init_email(app)` -- mirrors the Sentry pattern: reads `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM_NAME`, sets `MAIL_*` Flask config keys, binds `Mail(app)`, and writes `app.email_enabled`. When unset, app loads identically with a single WARNING; `forgot_password` returns the same enumeration-safe 200 (no token minted, log line points at the runbook); enterprise PDF email returns 503 + runbook hint. Sentry `_BODY_KEY_DENYLIST` extended with `smtp_password / mail_password / smtp_user / mail_username`. **6 unit tests** at `tests/test_zzzzzzzzzzzzzzzz_email_backend.py` (init enabled / init disabled / forgot-password mock send / forgot-password disabled-warning / SMTP_PASSWORD-not-in-logs / default-sender format). **Live verified end-to-end 2026-04-28**: `/api/__email_test` to byallew@gmail.com returned 200 in 2.46s, user-confirmed inbox receipt; full password reset cycle exercised against API (forgot-password 200 → token in DB → reset-password 200 → login with new pw 200 → restore to Test1234! 200). pytest: **498 passed, 3 skipped** (was 492 + 6 new). Fresh Gmail App Password rotated into `.env`. Runbook at `docs/runbooks/email-delivery.md` covers rotation, transactional-provider migration plan (Postmark / SES / Resend), and triage. Production must source `SMTP_PASSWORD` from secrets management; pre-launch task to migrate from personal Gmail to a transactional provider tracked under "Deferred Production Tasks". | Closed |
| PLB-5 | Sentry DSN not set in production .env — Sentry wired in app_cloud.py but no real DSN | Day 1 | 5 min predicted; ~2 hr actual (full PII scrubber + real-DSN live verify) | **Closed (commit `5234bcbf`, 2026-04-28).** Existing minimal init replaced with `dashboard/backend/observability/sentry_setup.py` carrying the full PLB-5 spec: FlaskIntegration + SqlalchemyIntegration + CeleryIntegration, traces=0.1, profiles=0.0, env+release tagging, `send_default_pii=False`, and a `before_send` hook that scrubs (header denylist, body-key denylist case-insensitive, regex pattern scrubber for aipet/JWT/Sentry-DSN/Stripe/LLM/postgres-URI). Fail-closed on scrubber crash. `/api/sentry-test` now gated to `FLASK_ENV != "production"`; redundant `capture_exception` removed from the 500 handler. **24 unit tests** (`tests/test_zzzzzzzzzzzzzz_sentry_scrub.py`), **3 live events shipped to the real Sentry project** (auto-capture path + capture_message + scrubber-verification), `client.transport=HttpTransport`, `client.flush(5)` returned cleanly. Runbook at `docs/runbooks/sentry.md`. Full report: `verification/plb5_6/PLB-5-6-observability-2026-04-28.md`. Production must source the DSN from secrets management. | Closed |
| PLB-6 | UptimeRobot monitor not yet configured — /api/ping endpoint exists but no monitor pointing at aipet.io | Day 1 | 10 min + aipet.io must be live | **Open (PARTIAL — runbook ready, monitor creation deferred to launch day).** UptimeRobot probes the public internet; localhost / WSL host-only IPs (10.0.3.x) cannot be monitored. Production deployment is itself blocked on payment infra (Revolut/Monzo card pending, noted 2026-04-28). What ships now: `docs/runbooks/uptime-monitoring.md` (operational runbook with monitor table, alert contacts, two safe test-alert procedures, triage steps for live alerts) + `verification/plb5_6/evidence/uptimerobot_pending_launch_day.md` (6-step launch-day handover note). The only remaining work to fully close is a 5-10 minute web-UI session in UptimeRobot once aipet.io is public. | Launch day (after aipet.io is deployed) |
| PLB-7 | Celery worker + Beat launched via start_cloud.sh (nohup) — production needs systemd services for restart-on-reboot and proper process management | Day 3 | 30 min | Closed (commit 1ec88357, 2026-04-25) — systemd units are templates in deploy/systemd/; not installed on dev. Production deploy task installs them (see deploy/systemd/INSTALL.md). | Production deployment task (alongside DigitalOcean deploy) |
| PLB-8 | Watch agent instrumentation gaps — 9 of 12 ml_anomaly features cannot be computed from real data because watch agent does not collect: TCP flag counts, directional bytes, per-protocol packet counts. Also: dest_ips list is hard-capped at 10, breaking detection of port scans to many destinations | Day 2 recon | Half day | Open | Month 2, alongside watch agent improvements |
| PLB-9 | Capability 13 Day 3 Windows live verification on real Windows VM | Day 3 | ~1 hr predicted; ~6 hr actual (7 production bugs found and fixed) | **Closed (commit `1410fd01`, 2026-04-28). 17/19 PASS, 2/19 PARTIAL** (item 04 LocalSystem account, documented as v1; item 14 flat retry, no exponential backoff, documented as v1 — revisit if outage windows extend). Full evidence in `verification/plb9/evidence/`. Report: `verification/plb9/PLB-9-windows-verify-2026-04-28.md`. **7 bugs fixed in this sweep**: (1) UTF-8 box-drawing chars in 4 .bat files broke cmd parsing under stdin redirection; (2) findstr "Out of memory" on 20-char-class regex; (3) NSSM `install` swallowed quotes around script-path arg, broke paths-with-spaces; (4) install.bat self-test 4-second sleep race-conditioned first-start; (5) LocalSystem PATH didn't include nmap install dir; (6) **CRITICAL** `AppExit 1 Stop` is invalid NSSM syntax (silently fell back to Restart, breaking watchdog security guarantee — agent kept restarting on revoked key); (7) uninstall_windows.bat couldn't delete its own containing dir, leaving ProgramData + registry orphans (now self-relocates to %TEMP%). | Closed |
| PLB-12 | Resend-cooldown 429 wait-minute message is wrong by ~1 hour on dev (BST). The rate-limit ENFORCEMENT is correct (429 fires within seconds of the previous resend), but the `body.message` reads `"Resent too recently. Wait ~65 minute(s) and try again."` when only seconds have actually elapsed. Root cause: `Invitation.last_resent_at` is being persisted as local time (BST = UTC+1) despite `routes.py:882` calling `datetime.now(timezone.utc)`; on readback `.replace(tzinfo=timezone.utc)` re-stamps the naive value as UTC, but the value was never actually UTC — so `(now_utc − last_local_as_utc) ≈ −3600s` and `wait_min = (300 − (−3600)) // 60 + 1 ≈ 66`. SQLAlchemy + naive `DateTime` column behaviour with aware-datetime input is the common factor; same pattern likely affects `revoked_at` / `accepted_at` though their messages don't surface a derived duration. Frontend impact: zero — Phase F's `_request` helper just renders `body.message`, so once the backend is fixed the toast self-corrects with no frontend change. | 2026-04-29 (Phase F recon) | ~30 min: switch the relevant columns to `DateTime(timezone=True)` via Alembic + audit any place that reads them with `.replace(tzinfo=...)`. | Open | Alongside next IAM tidy-up; non-blocking for Phase F. |
| PLB-13 | AcceptInvitationPage has no probe-on-mount: the user must fill in name + password before learning the invitation is invalid / expired / revoked / already-accepted. Phase F recon proposed a `{token, name:"", password:""}` probe, but the backend's validation order is `missing_token → missing_name → weak_password → token lookup` (auth/routes.py:455-463), so that probe always returns `missing_name` without consulting the token. A valid-shape probe creates the user on a happy-path token (unsafe). The robust fix is a new public `GET /api/auth/invitation/<token>/info` returning `{status, email, role, expires_at}` (no token, no PII beyond what the recipient already learnt from the email). Frontend probes that on mount and renders the right state without the form-fill cost. UX cost today: ~30 seconds of typing on a dead link. | 2026-04-29 (Phase F build) | ~15-30 min backend (one route + a serializer that strips token/inviter id) + ~10 min frontend integration. | Open | When AcceptInvitationPage UX is revisited; non-blocking for v1 launch. |
| PLB-14 | App.js prefetches 7 endpoints on every page mount (summary, devices, findings, ai, reports, scan/status, scans) and at the default 2000/day rate limit this exhausts within ~285 page loads, blocking development and giving real customers a hard ceiling. Should be lazy per-route OR a single `/api/dashboard-summary` aggregate endpoint. | 2026-04-29 (Phase F browser verification) | ~half day to refactor App.js prefetch into per-route lazy loads, OR ~half day to add an aggregate endpoint. | Open | Pre-launch hardening; non-blocking for Phase F sign-off but real-customer-facing. |
| PLB-15 | Rate-limiter 429 responses do not include CORS headers, so browsers surface them as misleading "Access-Control-Allow-Origin" preflight failures rather than the real "Too Many Requests" message. Backend should apply CORS middleware before rate-limiting middleware so 429 responses retain `Access-Control-Allow-Origin`. | 2026-04-29 (Phase F browser verification, surfaced while exercising PLB-14's prefetch ceiling) | ~30 min: middleware reorder + a curl-with-Origin smoke test against `/api/__ratelimit_test`. | Open | Bundle with PLB-14 fix or treat as a follow-up — both touch the same wiring. |
| PLB-16 | flask-limiter is configured with in-memory storage. Rate-limit state is per-Gunicorn-worker AND is wiped on graceful HUP. Production must move to Redis-backed storage so all workers share state and limits survive reload. (Related to but distinct from PLB-3, which closed the multi-worker leakage by switching to a single shared limiter — that fix still leaves state in-memory.) | 2026-04-29 (Phase F browser verification) | ~1 hr: provision Redis (already in stack for Celery), point flask-limiter `storage_uri` at it, smoke-test multi-worker shared state survives HUP. | Open | Pre-launch hardening; bundle with the production Redis pass. |
| PLB-17 | AuditTab's action-filter dropdown is built from the actions visible on the currently-loaded page (Phase D+E+G recon discovered `GET /api/iam/audit/actions` was assumed by the build prompt but does not exist in `iam/routes.py`; the alternative was a backend change ruled out of frontend-only scope). UX consequence: if the user filters down to a narrow result set, the dropdown shrinks to that set, and historic actions outside the current page never appear in the dropdown until the user widens the filter. The robust fix is a public-ish (audit:read-gated) `GET /api/iam/audit/actions` returning a deduped list of every action ever logged; frontend then loads it once on mount and keeps it stable across filtering. | 2026-04-29 (Phase D+E+G recon) | ~30 min backend (one route + a `SELECT DISTINCT action FROM audit_log` query, audit:read gated) + ~5 min frontend swap (drop the `dynamicActions` `useMemo`, replace with the fetched list). | Open | Bundle with next IAM audit-log pass; non-blocking for v1. |

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
| `automated_response` | Automated response chain (Capability 8). Watches `device_risk_scores` after each 5-min recompute. Per-user thresholds: notify ≥60, high_alert ≥80, emergency ≥95. Per-entity 4-hour cooldown tracked in `response_history` table (NOT `DefensePlaybook.last_triggered` which stays for the manual path). `send_alert` action now calls `settings/routes.send_slack_alert()` + `send_teams_alert()` when webhooks configured (was previously a silent DB-only write). Emits `automated_response_triggered` to `central_events` after each fire. Tier 1 web push (emergency ≥95 only) via `push_notifications.dispatcher.send_web_push` — non-fatal. 6 REST endpoints. `AutomatedResponsePanel` React panel with threshold editing, history table, stats bar. |
| `push_notifications` | Web Push API integration (Capability 12). `PushSubscription` model: endpoint, p256dh_key, auth_secret, enabled, failure_count. Auto-disables on HTTP 410 or 5 consecutive failures. `send_web_push()` — never raises, VAPID/pywebpush 2.3.0. Tier 1 scope: emergency threshold only (score ≥95). 5 endpoints: GET /api/push/vapid-public-key (no auth), POST subscribe/unsubscribe/test, GET subscriptions. `PushNotificationPanel` React component in Settings tab. VAPID keys in `.env`. |
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
| `endpoint_agent` / `agent_monitor` | Endpoint telemetry agent and monitor. POST /api/agent/telemetry now uses `@agent_or_jwt_required(scope="agent", permissions=["telemetry:write"])` (Cap 13 Day 2 fix) — accepts both JWT (dashboard humans) and X-Agent-Key (systemd-managed device agent). |
| `agent_keys` | Per-device non-expiring API key system for agent authentication. Keys bcrypt-hashed at rest, shown once at creation, scoped to "agent" only (cannot hit user endpoints), revocable. 6 REST endpoints under `/api/agent/keys` (Day 2 added `GET /me` for the watchdog — returns 200 if key valid, 401 if revoked). `AgentKeysPanel` React component in Settings tab. `auth.py` exports `agent_key_required` (key-only) and `agent_or_jwt_required` (hybrid). |
| `agent_scan_ingest` | POST /api/agent/scan-results accepts nmap XML or structured JSON from authenticated agents. Writes to `real_scan_results` table (same as cloud-side scanner — visible in existing scan UI immediately). Idempotent via agent-provided `scan_id`. Cross-tenant scan_id collision → 403. Emits `scan_completed` to `central_events`. |
| Agent install package (Day 2) | `.deb` for Debian/Ubuntu (~14KB, all-arch) at `agent/packaging/aipet-agent_1.0.0_all.deb`. Single-command bash installer (`curl -sSL https://aipet.io/install \| sudo bash`, 3 questions max, designed for non-technical IT staff). systemd unit (`/lib/systemd/system/aipet-agent.service`) with security hardening (NoNewPrivileges, ProtectSystem=strict, ProtectHome, dedicated `aipet-agent` user, only CAP_NET_RAW + CAP_NET_ADMIN, RestartPreventExitStatus=1). Token refresh watchdog (`agent/watchdog.py`) re-validates the agent key every 5 min via `GET /api/agent/keys/me`; on 401, exits with code 1 and systemd does not restart it. Self-test on install (✓ Connected, ✓ Logging, ✓ Registered). `aipet-agent` wrapper command supports `setup` / `test` / `status` / `uninstall`. Agent v1.2.0: `AIPET_AGENT_LABEL`, `AIPET_SCAN_TARGET`, `AIPET_SCAN_INTERVAL_HOURS`, `AIPET_WATCHDOG_INTERVAL`. Backward compat preserved — `python3 aipet_agent.py --agent-key …` still works. |
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

**Current status:** Capabilities 1–12 ✅ + Capability 13 (Days 1+2+3) ✅. **13 of 33 capabilities (39%).** 20 remaining (14–33).

> **Audit caveat (2026-04-28):** The ✅ marks below were originally applied without per-row click-through verification. After the state-of-system audit, all are confirmed mechanically VERIFIED (backend blueprint registered + frontend Page present + representative endpoint returns 200), but per the new "Tested vs Complete" rule none have been re-stamped under the human-clicks-every-UI-element bar. Treat ✅ here as TESTED-AND-WIRED until a click-through pass upgrades them. See `verification/state-of-system/02-verification-results.md` § A for the per-row evidence.

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
| 12 | Production-ready PWA + Web Push notifications | ✅ **COMPLETE** — `push_notifications/` module: `PushSubscription` model (endpoint, p256dh_key, auth_secret, enabled, failure_count, auto-disable on 410/5-failures), `dispatcher.py` (send_web_push — never raises, VAPID/pywebpush, Tier 1 emergency-only scope), 5 REST endpoints (`/api/push/vapid-public-key`, subscribe, unsubscribe, subscriptions, test). Wired into `automated_response/engine.py` — emergency threshold (score≥95) fires web push after Slack/Teams; non-fatal. pywebpush 2.3.0. VAPID keys in `.env`. `pwa/pushNotifications.js` (frontend helper: requestPermissionAndSubscribe, sendTestPush, listSubscriptions, disableSubscription). `PushNotificationPanel` React component in Settings tab. iOS detection + "Tap Share → Add to Home Screen" instructions. Install dismissed guard via `localStorage`. Mobile responsive pass: hamburger nav (<768px sidebar overlay), RiskScoreTable card layout, RiskTopBar vertical stack, EventsFeedPanel horizontal-scroll filters, ThresholdsCard vertical stacking, AnomalyResultCard overflow fix, AskPanel auto-fill grid. 18 backend tests (299 total). |
| 12b | AI-written weekly security briefings | Pending (original Cap 12 deferred to 12b) |

### Month 2 — Deep Scanner + Firmware (Capabilities 13–16)

| # | Capability | Status |
|---|---|---|
| 13 Day 1 | Agent API keys + scan ingest endpoint | ✅ **COMPLETE** — `agent_keys/` module: `AgentApiKey` model (bcrypt at rest, prefix-indexed, scope=agent, revocable), `generate_api_key()`, `verify_key()`, `agent_key_required()` decorator, 5 endpoints (`/api/agent/keys` CRUD + usage). `agent_scan_ingest/` module: POST `/api/agent/scan-results` accepts nmap XML + structured JSON, writes to `real_scan_results` table, idempotent via scan_id, cross-tenant 403, emits central event. `AgentKeysPanel` React component in Settings tab. aipet_agent.py updated for `--agent-key` mode + `--scan` one-shot. Rate limits: create 5/min, ingest 60/min. 41 backend tests (342 total). |
| 13 Day 2 | Agent install package + systemd + token watchdog | ✅ **COMPLETE** — `.deb` package (Debian/Ubuntu, ~14KB) at `agent/packaging/`: control + postinst/prerm/postrm + ships systemd unit at `/lib/systemd/system/`. Security hardening: dedicated `aipet-agent` system user (no shell, no home), NoNewPrivileges, ProtectSystem=strict, ProtectHome, only CAP_NET_RAW + CAP_NET_ADMIN. `agent/watchdog.py` re-validates key every 5 min via new `GET /api/agent/keys/me`; 401 → `sys.exit(1)` + systemd `RestartPreventExitStatus=1` honoured. `agent/packaging/install.sh` is the `curl|sudo bash` UX (3 questions, regex-validated; supports `AIPET_DEB_URL=file://…` for dev). `usr/bin/aipet-agent setup/test/status/uninstall` wrapper. **Day 1 gap closed**: `/api/agent/telemetry` was JWT-only and broke under systemd; new `agent_or_jwt_required(scope, permissions)` decorator accepts both auth modes — set on `/api/agent/telemetry` with permissions=["telemetry:write"]. Backward compat preserved (`python3 aipet_agent.py --agent-key …` still works). 54 new backend tests (47 install + 7 hybrid auth) → **396 backend total**, 3 skipped (2 = shellcheck not installed, 1 = pre-existing). Live verified end-to-end: `apt-get install` → `systemctl start` → telemetry flowing → key revoked via API → watchdog detected within 30 s → exit code 1 → systemd did NOT restart → `apt-get purge` left zero traces (config dir, lib dir, log dir, opt dir, system user — all gone). |
| 13 Day 3 | Windows service + Windows installer | ✅ **COMPLETE — live-verified on Windows 11 VM 2026-04-28 (PLB-9 closed)**. Platform-portable `aipet_agent.py` v1.2.0 (`IS_WINDOWS`/`IS_LINUX` constants; `_resolve_config_path/_log_dir/_install_dir` helpers via `pathlib.PureWindowsPath`/`PurePosixPath`; `psutil.net_if_addrs()` for cross-platform CIDR auto-detect; `os.fork()` guarded). NSSM 2.24 win64 bundled. `install_windows.bat`: 3-question UX, admin + Python 3.8+ + nmap detection, copies to `%ProgramFiles%\AIPET\`, writes summary to `%ProgramData%\AIPET\agent.conf` (key value held only in NSSM AppEnvironmentExtra), self-test, Add/Remove Programs registration. `aipet-agent-service-install.bat`: SERVICE_AUTO_START, log rotation 10 MB, **`AppExit 1 Exit`** (was `Stop` — invalid NSSM syntax silently fell back to Restart; PLB-9 caught it), `AppExit Default Restart`, all 8 `AIPET_*` env vars, plus `PATH=` injection so LocalSystem can find nmap. `uninstall_windows.bat`: **self-relocates to `%TEMP%`** (PLB-9 found that running from `%INSTALL_DIR%` left ProgramData + registry orphans), removes service via NSSM, rmdirs install + ProgramData, deletes registry. **PLB-9 verification: 17/19 PASS, 2/19 PARTIAL** (item 04 LocalSystem documented v1; item 14 flat retry documented v1). **7 production bugs found + fixed live**: see `verification/plb9/PLB-9-windows-verify-2026-04-28.md`. Final installer SHA256 `84977e61beefacfa87116c03ade24f226d77eecba586671032759ae973f5e6ef`. 51 cross-platform unit tests + 19-item live verification = total. Linux .deb backward compat preserved (still builds + installs). |
| 14 | Exploit path mapping (attack chain visualisation) | Pending |
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
sudo pg_ctlcluster 17 main start && cd /home/byall/AIPET && source venv/bin/activate && bash start_cloud.sh
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
- **Database migrations** are managed by Alembic (PLB-1). Baseline `68d67bfc6697 "baseline schema"` covers the 166 user tables. **Every future schema change must be a new Alembic revision** — never edit a model and rely on `db.create_all()` (which still runs at app boot for now but is becoming a no-op as schema drift converges to zero). Workflow:
    1. Edit a model under `dashboard/backend/<module>/models.py`.
    2. `venv/bin/alembic revision --autogenerate -m "describe change"`
    3. **Read the generated file line by line** — autogenerate misses indexes (especially partial/functional), server-defaults that match Python defaults, sequences/triggers/functions, and check constraints. Add manually as `op.execute(...)` if needed; mirror in `downgrade()`.
    4. Round-trip test on a throwaway DB: `alembic upgrade head` → `alembic downgrade base` → `alembic upgrade head`. Schema diff vs source must be zero.
    5. Commit. **Backup before applying in any non-dev environment** (`./scripts/backup.sh pre-deploy`).
    Two roles, two URLs (least-privilege): `aipet_user` (LOGIN, no CREATEDB) for the running app via `DATABASE_URL`; `aipet_admin` (LOGIN, CREATEDB) for migrations only via `ALEMBIC_DATABASE_URL`. `alembic/env.py` reads `ALEMBIC_DATABASE_URL` first then falls back to `DATABASE_URL`. The placeholder `aipet_admin_password` in `.env` must be replaced with a secrets-managed value before production deployment. See `alembic/README` for full workflow + `verification/plb1/PLB-1-alembic-baseline-2026-04-28.md` for closure evidence. **Worked example for adding a new column**: revision `5a01a50ef701` (`agent_devices.deleted_at` + `audit_log.node_meta`) exercised the full flow — model edit → autogenerate → line-by-line review → bidirectional throwaway-DB test → applied to `aipet_db`. Report: `verification/soft-delete/REPORT-2026-04-28.md`.
- **Soft-delete pattern.** Canonical implementation lives on `AgentDevice` in `dashboard/backend/agent_monitor/routes.py`. Every model that needs soft-delete should follow the same shape so the codebase stays consistent: (1) `deleted_at = Column(DateTime, nullable=True, index=True)` with a matching alembic migration; (2) two query classmethods — `Model.active()` returning `cls.query.filter(cls.deleted_at.is_(None))` for app paths and `Model.with_deleted()` returning `cls.query` for admin / audit / lifecycle ops; (3) two idempotent lifecycle methods — `instance.soft_delete(actor_user_id, reason=None)` (returns False if already deleted, no extra audit row) and `instance.restore(actor_user_id, reason=None)` (returns False if already active); both write to `audit_log` via `log_action(user_id, action, resource, details=...)`. The `audit_log.node_meta` JSON column is the canonical place for structured audit detail across the codebase — used to denormalise the device hostname, capture the reason text, and stash timestamps that survive even if the referenced row is later hard-deleted. **No bare `Model.query` in new code** — every callsite must consciously pick `active()` or `with_deleted()`. When converting an existing model, audit every existing `Model.query` callsite and list each one explicitly in the commit message (no handwave summaries) — see `61cd43f5` for the worked example. **Auth model (Pattern A, 2026-04-28)**: the list endpoint has three modes. Default returns the caller's active devices (JWT only). `?include_deleted=true` returns the caller's own active + soft-deleted devices (still JWT only — owner-implicit access; per-tenant `filter_by(user_id=uid)` is the safety net). `?include_deleted=true&all_tenants=true` returns deleted devices across all tenants (requires `owner` role OR `audit:read` permission). The all_tenants-without-include_deleted combination is rejected 400 by design. Frontend: "View deleted" toggle auto-untoggles on a 403 (only happens in the admin all_tenants path, which the v1 UI doesn't currently expose). Restore endpoint stays per-tenant scoped — cross-tenant admin restore is a separate feature if a customer asks. **v2 enhancement (Pattern C, ~2.5 hr, separate task)**: dedicated "Recently Deleted" tab + 30-day retention sweep + bulk restore + bulk hard-delete. Recovery gap closed for v1; Pattern C tracked as nice-to-have, not blocking launch. Reports: `verification/soft-delete/REPORT-2026-04-28.md` (v1) + `verification/soft-delete/PATTERN-A-RECOVERY-FIX-2026-04-28.md` (this fix).
- **Backups** are taken via `scripts/backup.sh` (timestamped, gzipped, gzip-verified, idempotent). `scripts/restore.sh BACKUP target_db` drops + recreates `target_db` and loads the dump under `aipet_admin`; **refuses target=`aipet_db` without `--i-know-what-im-doing`** as a typo guard against accidental prod restore. `backups/` is gitignored. Recommended retention: 7 daily / 4 weekly / 3 monthly. Production must replicate `backups/` off-host (S3/B2/etc.). Full runbook at `docs/runbooks/backup-and-restore.md`. The legacy `dashboard/backend/monitoring/backup.py` module was retired 2026-04-28 (PLB-1 follow-up); the shell scripts are the single source of truth.
- **Observability** is two complementary systems. Sentry (PLB-5, closed) tells you when something breaks **inside** production — captures unhandled exceptions, slow requests at 10 % sample, SQLAlchemy + Celery errors. Init lives at `dashboard/backend/observability/sentry_setup.py`, called once at `app_cloud.py` import time before Flask/SQLAlchemy/Celery so the integrations can patch them. Skip-if-no-DSN: app runs identically when `SENTRY_DSN` is unset. **`before_send` PII scrubber** is the security-critical bit — three layers: (1) header denylist (Authorization, X-Agent-Key, X-API-Key, Cookie, …) → `[Filtered]` (case-insensitive); (2) body-key denylist (password, agent_key, full_key, *_secret, *_key, jwt, token, refresh_token, …) → `[Filtered]` (recursive into nested dicts + lists); (3) regex scrubber for free-form strings (exception messages, top-level message, breadcrumbs) → labelled filters: `[Filtered:aipet_key]`, `[Filtered:jwt]`, `[Filtered:sentry_dsn]`, `[Filtered:stripe_sk]`, `[Filtered:llm_key]`, `[Filtered:db_password]`. Fail-closed: any exception inside the scrubber drops the event rather than ship raw data. 24 unit tests at `tests/test_zzzzzzzzzzzzzz_sentry_scrub.py`. Runbook: `docs/runbooks/sentry.md`. — UptimeRobot (PLB-6, partial) tells you when production stops **answering** at all by probing `/api/ping` from the public internet. The probe endpoint is unauthenticated and ships `{"status": "ok", "timestamp": "<iso>"}` HTTP 200; defined at `app_cloud.py:557`. Monitor creation deferred to launch day because UptimeRobot can't reach localhost / WSL IPs. Runbook: `docs/runbooks/uptime-monitoring.md` (every input the operator needs on launch day). Both DSN and UptimeRobot API key must come from secrets management (Vault / AWS SM / 1Password) in production — never `.env` outside dev. Future observability work (NOT blocking launch): distributed tracing via OpenTelemetry, structured JSON logs, business metrics + SLOs, synthetic monitoring beyond UptimeRobot.
- **Email delivery** (PLB-4, closed). Two libraries by design: Flask-Mail for app-flow emails (auth/forgot_password, enterprise PDF report delivery) and raw smtplib for ops alerts (`monitoring/alerting.py`, runs in Celery / signal contexts where Flask app context isn't always available). Both share the canonical **`SMTP_*`** env-var prefix (`SMTP_USER`, `SMTP_PASSWORD`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_NAME`). **Do not rename `SMTP_USER` to `SMTP_USERNAME`** to match Flask-Mail's `MAIL_USERNAME` -- `SMTP_USER` is referenced from `aipet_agent.py`, deploy templates, and operator muscle memory; the cost of churn outweighs the cost of a non-Flask-Mail-matching name. Init lives at `dashboard/backend/observability/email_setup.py:init_email(app)` -- reads SMTP_* env, sets `MAIL_*` Flask config keys, binds `Mail(app)`, writes `app.email_enabled`. Skip-if-no-creds: when `SMTP_USER` or `SMTP_PASSWORD` is unset, app loads identically with a single WARNING; `forgot_password` returns the same enumeration-safe 200 (no token minted, log line points at runbook); enterprise PDF email returns 503 + runbook hint; ops alerts print "Email skipped". Sentry `before_send` body-key denylist covers `smtp_password / mail_password / smtp_user / mail_username` (the username is denylisted because exposing it narrows an attacker's target list). Dev-only smoke endpoint `/api/__email_test` (POST `{"to":...}`) gated on `FLASK_ENV != production`. Runbook at `docs/runbooks/email-delivery.md` -- includes rotation procedure, transactional-provider migration plan (Postmark / SES / Resend), and triage steps. **Pre-launch task**: migrate from personal Gmail App Password to a verified-domain transactional provider; Gmail's 500/day cap and shared-account suspension risk are not acceptable at scale.
- **Celery worker + Celery Beat** both started by `start_cloud.sh` (D3). Beat schedule: `sync-nvd-cves-hourly` (3600s) + `retrain-anomaly-model-daily` (86400s) + `sync-otx-threat-intel-every-6-hours` (21600s). PIDs under `pids/`, logs under `logs/`. Redis required before Celery starts (script checks with `redis-cli ping`).
- **OTX_API_KEY required in .env** — get a free key at https://otx.alienvault.com → Settings → API Integration. Without it, the 6-hour OTX sync task returns `{"status": "error"}` silently (non-fatal).
- **CISA KEV is unauthenticated** — no API key needed. Daily sync downloads all 1,583+ entries in one GET request (~2MB JSON). Re-running the sync is safe: `session.merge()` upserts by cve_id PK, producing zero duplicates.
- **Celery systemd templates** at `deploy/systemd/` (PLB-7 closed). `start_cloud.sh` detects if `aipet-celery-worker.service` / `aipet-celery-beat.service` are active; if so, it skips nohup launch (systemd owns those processes). On dev, nohup fallback runs as before. See `deploy/systemd/INSTALL.md` for production install instructions.
- **Risk forecast engine** (`risk_forecast/`) — forecasting pipeline is decoupled from automated response. `DeviceRiskScoreHistory` accumulates snapshots every 5 min; `forecast_all_entities()` runs hourly. ARIMA(1,1,1) requires ≥30 daily observations; falls back to `numpy.polyfit` linear when resampling produces <2 daily points (e.g. first hour of operation). `ForecastAlert` unique constraint `(user_id, entity, threshold_name, status='active')` prevents duplicate active alerts per entity per threshold. Cap 11 alerts are READ ONLY from Cap 8's perspective — no join to `response_history`.
- **Risk score engine** (`risk_engine/`) — formula constants at module level in `engine.py`, reviewable without reading computation logic: `SEVERITY_POINTS = {critical:60, high:35, medium:15, low:8, info:2}`, `SOURCE_MULTIPLIERS = {ml_anomaly:1.0, live_cves:1.2, threatintel:1.1, behavioral:0.9, mitre_attack:0.7, real_scanner:0.8, redteam:1.0, defense:0.6, auth:0.6, siem:0.7, multicloud:0.9, otics:1.0, zerotrust:0.9, identity_guardian:1.0, digitaltwin:0.5}`, `HALF_LIFE_HOURS=8`, `LOOKBACK_HOURS=24`. Capability 8 queries `device_risk_scores` via `filter(user_id==uid, score>=threshold)` using the `ix_device_risk_user_score` composite index.
- **Automated response** (`automated_response/`) — runs inside `recompute_device_risk_scores` Celery task after scores refresh. Per-entity cooldown tracked in `response_history.fired_at` (NOT `DefensePlaybook.last_triggered` — that stays for the manual path). Default thresholds seeded lazily (idempotent) on first API call. `send_alert` action now calls `settings.send_slack_alert()` + `send_teams_alert()` when webhooks configured; failure is non-fatal (logged, slack_sent=False, status still "executed"). `_execute_action` now returns 3-tuple `(log, siem_ev, notif_meta)` — existing manual callers use `_`.
- **Central event pipeline** (`central_events/`) — synchronous `emit_event()` call inserted after each module commits its domain row. Failures are always silent (try/except + rollback in adapter; belt-and-suspenders try/except at each call site). Every event carries `user_id` for per-user scoping. 8 modules dual-write (siem_events + central_events); refactor to single-source is a future task. Cycle prevention in siem/ingest: if incoming event has `node_meta.from_central_emit=True`, the emit is skipped to break re-ingest loops. The `_execute_action` helper in defense returns `(log, Optional[SiemEvent])`; `_ingest_siem_zt` in zerotrust returns `Optional[SiemEvent]` — callers emit after their respective commits.
- **Agent authentication model** — two paths: (1) JWT (`Authorization: Bearer`) for human users — 15-min expiry, returned by `/api/auth/login`; (2) Agent keys (`X-Agent-Key`) for device agents — non-expiring, bcrypt-hashed at rest, scope=`agent` (cannot access user endpoints). Agent key routes are under `agent_keys_bp` at `/api/agent/keys`. Three decorators in `dashboard/backend/agent_keys/auth.py`: `agent_key_required(scope, permissions)` (key-only, used by `/api/agent/scan-results` and `/api/agent/keys/me`); `agent_or_jwt_required(scope, permissions)` (Day 2 — hybrid; sets `g.current_user_id` + `g.auth_mode = "jwt" \| "agent_key"`; used by `/api/agent/telemetry` so the same endpoint serves dashboard humans AND the systemd-managed device agent); `@jwt_required` (vanilla Flask-JWT, used by `/api/agent/devices` and the rest of the dashboard). Agent scan ingest is idempotent: `agent_scan_submissions` table tracks `(user_id, scan_id)` unique pairs to prevent duplicates. Cross-tenant collision → 403.
- **Agent deployment model (Linux)** — `.deb` built from `agent/packaging/deb/`, installed to `/opt/aipet-agent/` (binaries + venv), `/etc/aipet-agent/agent.conf` (EnvironmentFile, mode 640, `root:aipet-agent`), `/var/lib/aipet-agent/` + `/var/log/aipet-agent/` (state + logs, owned by aipet-agent user). systemd unit at `/lib/systemd/system/aipet-agent.service` (NOT `/etc/systemd/system/` — dpkg owns it). `aipet-agent` system user: no shell, no home, granted only `CAP_NET_RAW + CAP_NET_ADMIN` for nmap raw sockets. Service is **not** auto-started by postinst — user must run `sudo aipet-agent setup` (or the installer's interactive prompts) to write `agent.conf` and `systemctl enable --now`. Watchdog at `/opt/aipet-agent/watchdog.py` runs as a daemon thread inside the agent process: `GET /api/agent/keys/me` every `AIPET_WATCHDOG_INTERVAL` seconds (default 300), `sys.exit(1)` on 401, network errors are treated as transient (do NOT exit). systemd's `RestartPreventExitStatus=1` keeps the agent stopped after a revocation. Windows + macOS deferred to Capability 13 Day 3.
- **Gunicorn** serves Flask in production (`gunicorn_config.py`)
- **Nginx** reverse-proxies to Gunicorn (port 5001) and serves the React build
- **PWA stack** (Capability 12) — `public/manifest.json` (8 icons, 3 shortcuts, categories), `public/sw.js` v4.0.0 (install/activate/fetch/push/notificationclick lifecycle), SW registered in `public/index.html`. VAPID keys in `.env` (VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY, VAPID_SUBJECT). `push_notifications/dispatcher.py` imports `webpush` at module level (patchable). Tier 1 scope: emergency ≥95 only — notify/high_alert do NOT trigger push. Mobile responsive pass applied to 5 panels (Risk Score, Events Feed, Ask AIPET, Automated Response, AnomalyResultCard) + hamburger nav; other panels deferred to Polish Pass 1.

---

## PWA Testing Instructions

### Chrome DevTools (no real phone needed)
1. Start frontend: `cd dashboard/frontend/aipet-dashboard && npm start`
2. Open http://localhost:3000, log in
3. DevTools → Application → Manifest — verify manifest loads with all 8 icons
4. DevTools → Application → Service Workers — verify sw.js "activated and running"
5. Toggle Device Toolbar (Ctrl+Shift+M) → select iPhone SE (375px)
6. Verify hamburger menu appears; tap → all nav sections reachable
7. Navigate to Settings → Push Notifications section → click "Enable push notifications" → Allow
8. Click "Send test notification" → notification should appear in OS

### Real Android phone
1. `ip addr show | grep inet` — note laptop's local IP (e.g. 10.0.3.4)
2. Phone on same WiFi → open Chrome → navigate to `http://10.0.3.4:3000`
3. Log in → verify dashboard loads → Chrome menu → "Add to Home Screen"
4. AIPET X icon on home screen → tap → fullscreen (standalone mode)
5. Settings → Notifications → Enable → Allow → Send test
6. From laptop: `curl -X POST http://localhost:5001/api/response/check_now -H "Authorization: Bearer <token>"`
7. Phone should buzz within 30s with emergency notification (if risk score ≥95)

### Real iPhone (requires HTTPS)
- Run `ngrok http 3000` → access via the https:// URL provided
- OR use `mkcert` to set up localhost HTTPS: `mkcert localhost` then configure CRA to use the cert
- iOS 16.4+ required for push notifications via PWA
- Safari Share button → Add to Home Screen → open from home screen → Settings → Enable

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
| **Migrate outbound email from personal Gmail to a transactional provider** | PLB-4 wired Flask-Mail against a personal Gmail App Password as a stop-gap. Pre-launch (or shortly post-launch with a small soak window), replace with Postmark / AWS SES / Resend / Mailgun against the verified `aipet.io` domain (DKIM + SPF + DMARC). Gmail caps at 500 recipients/day, has no per-message delivery analytics, and a single bounce/spam complaint can suspend the personal account. The two-library convention (Flask-Mail for app paths, smtplib for ops alerts) is provider-agnostic — only `.env` SMTP_* vars change. Full migration steps in `docs/runbooks/email-delivery.md`. |
| **`datetime.utcnow()` deprecation cleanup — 130 callsites across 46 files** | Python 3.12 deprecated `datetime.utcnow()`; pytest currently emits multiple `DeprecationWarning: datetime.datetime.utcnow() is deprecated` per run. Recon done 2026-04-28 (`verification/datetime-utcnow-recon-2026-04-28.md`); deferred because the original "30-min mechanical" framing was wrong — actual work splits into three sub-tasks: **(i) backend src** (102 callsites in `dashboard/backend/**` + `app_cloud.py`, 60-90 min, decision needed up-front on whether SQLAlchemy `default=` columns get widened to `DateTime(timezone=True)` with an Alembic migration or stay naive via `.replace(tzinfo=None)` wrapping); **(ii) soft-delete test** (21 callsites in `tests/test_zzzzzzzzzzzzzzz_soft_delete.py`, likely cascades into widening `AgentDevice.deleted_at`/`first_seen`/`last_seen` to `DateTime(timezone=True)` + Alembic migration, 30-60 min, depends on what (i) decided); **(iii) agent v1.2.1 release** (6 callsites in 3 agent files — `agent/aipet_agent.py`, `agent/packaging/deb/...`, `agent/packaging/windows/...`, bundle with next intentional agent release, requires version bump + .deb rebuild + Windows installer rebuild + PLB-9-style live re-verify on the Win11 VM + new installer SHA256, 2-4 hr). Order: (i) first, then (ii), (iii) independent. Don't bundle into one PR. Full recon + per-file counts + risk hits + acceptance criteria per sub-task in `verification/datetime-utcnow-recon-2026-04-28.md`. |

---

## Standing Reminders for Claude Code

Every Claude Code task that fixes a Pre-Launch Blocker MUST update the table in the Pre-Launch Blockers section to mark the relevant PLB row as Closed with the commit hash and date. Every task that discovers a new blocker MUST add a new PLB-N row. Do not trust memory across sessions — trust this file.
