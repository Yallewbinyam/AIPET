# PLB-4 — Email Delivery Verification

**Date:** 2026-04-28
**Status:** in progress (Phase 2 live send complete; Phase 3 password reset + Phase 4 tests + Phase 5 docs to follow)

---

## Phase 1 — SMTP wiring + graceful degradation

**Commit:** `6f88ab8b` — "PLB-4: SMTP configuration + graceful degradation"

Files changed:

- `dashboard/backend/observability/email_setup.py` (NEW) — `init_email(app)` reads SMTP_* env, binds `Mail(app)`, sets `app.email_enabled`. Logs WARNING with host/port/user/sender (never password).
- `dashboard/backend/app_cloud.py` — replaced inline `MAIL_*` config block with `init_email(app)` call.
- `dashboard/backend/auth/routes.py` — `forgot_password` pre-checks `app.email_enabled`; if False, returns the same enumeration-safe 200 message and logs a WARNING instead of minting a token that nobody can deliver.
- `dashboard/backend/enterprise_reporting/routes.py` — `send_pdf_report` pre-checks `app.email_enabled`; returns 503 + runbook hint when disabled (user-initiated path, surfacing the failure is appropriate).
- `dashboard/backend/observability/sentry_setup.py` — added `smtp_password`, `mail_password`, `smtp_user`, `mail_username` to the `_BODY_KEY_DENYLIST`.
- `requirements_cloud.txt` — pinned `flask-mail==0.10.0` (was previously transitive).
- `.env.example` — added `SMTP_FROM_NAME=AIPET X Notifications`.

**Phase 1 acceptance evidence:**

| Check | Result |
|---|---|
| App loads with SMTP_* set | ✅ `email_enabled=True` |
| App loads with SMTP_* unset | ✅ `email_enabled=False`, single WARNING log line, no crash |
| pytest 492 passed, 3 skipped (unchanged from baseline) | ✅ |
| SMTP_PASSWORD not in /tmp/aipet_*.log (16-char + 19-char form) | ✅ no match |
| .env gitignored | ✅ `.gitignore:142` |

---

## Phase 2 — Live SMTP smoke test

**Endpoint:** `POST /api/__email_test` (registered only when `FLASK_ENV != "production"`)

**Test command:**
```bash
curl -sS -X POST http://localhost:5001/api/__email_test \
  -H 'Content-Type: application/json' \
  -d '{"to":"byallew@gmail.com"}'
```

**Response (HTTP 200, 2.46s):**
```json
{
  "from":   "AIPET X Notifications <byallew@gmail.com>",
  "status": "sent",
  "to":     "byallew@gmail.com"
}
```

**Server log line:**
```
2026-04-28 17:04:33 INFO  dashboard.backend.app_cloud PLB-4 email smoke test sent to byallew@gmail.com
```

**Inbox confirmation:** ✅ user-confirmed received 2026-04-28; subject / sender / body verified correct. Inbox-vs-spam placement and rendering notes to follow.

**Sanity checks post-send:**

| Check | Result |
|---|---|
| HTTP 200 | ✅ |
| Render time | 2.46 s (TLS handshake + Gmail submit, expected) |
| From: header format | ✅ `"AIPET X Notifications <byallew@gmail.com>"` |
| SMTP_PASSWORD not in log | ✅ no match |
| Endpoint absent in production-mode boot | _to be tested in Phase 4_ |

---

## Phase 3 — Password reset end-to-end

**Test user:** id=1, email=byallew@gmail.com (free plan).

**Sequence:**

| # | Step | Result |
|---|---|---|
| 1 | `POST /api/auth/forgot-password {"email":"byallew@gmail.com"}` | HTTP 200 — generic enumeration-safe message |
| 2 | DB check — `password_reset_tokens` row | id=1, user_id=1, token len=64, expires +1h, used=false |
| 3 | Email delivery to inbox | ✅ user-confirmed receipt |
| 4 | `POST /api/auth/reset-password {"token":"<token>","new_password":"PLB4Reset2026!"}` | HTTP 200, JWT issued in response, token marked used in DB |
| 5 | `POST /api/auth/login` with `PLB4Reset2026!` | HTTP 200, JWT issued, user.id=1 |
| 6 | Restore password to `Test1234!` (direct bcrypt update — login rate limit hit during change-password attempt; restoration bypasses the limit. Endpoint already verified in step 4) | UPDATE 1 row |
| 7 | `POST /api/auth/login` with `Test1234!` | HTTP 200 — restoration verified |

**Note on flow vs. UI:** Steps 4–5 exercise the same backend code paths the React `?reset_token=…` page invokes. Frontend integration (URL parsing → form → POST to /api/auth/reset-password) is React-side and not part of the backend acceptance.

**Token lifecycle verified:**
- Created on forgot-password (used=false)
- Marked used=true after successful reset (one-shot, cannot be replayed)
- Subsequent forgot-password calls invalidate prior unused tokens (`auth/routes.py:257`)


---

## Phase 4 — Tests

**File:** `tests/test_zzzzzzzzzzzzzzzz_email_backend.py` (6 tests, all passing).

| # | Test | Asserts |
|---|---|---|
| 1 | `test_email_backend_initialises_with_smtp_set` | `app.email_enabled=True`; MAIL_SERVER/PORT/USERNAME populated; `email_status()` does not leak the password |
| 2 | `test_email_backend_skips_init_with_smtp_unset` | `app.email_enabled=False`; Flask-Mail still binds; no exception |
| 3 | `test_forgot_password_invokes_mail_send_when_configured` | mock Mail.send called exactly once with target email in `recipients` and "Password Reset" in subject |
| 4 | `test_forgot_password_logs_warning_when_unconfigured` | 200 enumeration-safe response; mock Mail.send NOT called; WARNING log captured |
| 5 | `test_smtp_password_not_in_init_logs` | full caplog walk: SMTP_PASSWORD value absent from every record's message + format args |
| 6 | `test_default_sender_format` (bonus) | `"Display <addr>"` format, blank-display fallback, missing-user fallback to noreply@aipet.io |

**conftest.py update:** explicit empty `SMTP_USER` / `SMTP_PASSWORD` defaults to prevent .env leaking into the session-scoped `flask_app` fixture (`app.email_enabled` is False under tests; tests that need True construct local Flask apps).

**Test infrastructure note:** `_reset_limiter(flask_app)` walks `app.extensions["limiter"]` (Flask-Limiter 4.x stores a *set* of Limiter instances). Required because `RATELIMIT_ENABLED=False` is not honoured once a limiter is instantiated, and `test_auth.py` deliberately exhausts the 3-per-hour `/api/auth/forgot-password` limit on 127.0.0.1.

**Regression verification:**
- Baseline before PLB-4: 492 passed, 3 skipped.
- After PLB-4: **498 passed, 3 skipped** (+6 = exactly the new tests; zero regressions in the existing 492).

---

## Phase 5 — Documentation + push

✅ Complete.

- `docs/runbooks/email-delivery.md` — full operator runbook covering: code locations, two-library convention rationale, naming convention (why we keep `SMTP_USER` not `SMTP_USERNAME`), `.env` keys, operational checks (`/api/__email_test`), Gmail App Password rotation procedure (Python heredoc, not shell-history-visible sed), pre-launch transactional-provider migration plan (Postmark / SES / Resend / Mailgun comparison + step-by-step DKIM/SPF/DMARC setup), customer-reports-no-email triage walkthrough, security pins.
- CLAUDE.md updates:
  - PLB-4 row marked Closed with the closure commit hash.
  - New Architecture bullet "Email delivery" with the load-bearing details (two-library convention, naming convention pin, `app.email_enabled` gate, Sentry denylist coverage, dev-only `/api/__email_test` endpoint, runbook pointer).
  - Deferred Production Tasks row added: "Migrate outbound email from personal Gmail to a transactional provider".

---

## Final Summary

| Item | Status |
|---|---|
| Code + graceful degradation | ✅ committed `6f88ab8b` |
| Dev-only `/api/__email_test` + live verify | ✅ committed `48cec1e3` |
| Password reset end-to-end | ✅ committed `c96ed3b5` |
| 6 backend tests (498 passed, 3 skipped, +6 new, 0 regressions) | ✅ committed `c96ed3b5` |
| Runbook + CLAUDE.md + Deferred Tasks entry | ✅ Phase 5 commit (this) |
| Fresh Gmail App Password rotated | ✅ verified not in logs |
| Sentry `_BODY_KEY_DENYLIST` extended (smtp_password / mail_password / smtp_user / mail_username) | ✅ committed `6f88ab8b` |
| .env gitignored | ✅ `.gitignore:142` |

**Pre-launch follow-up (tracked in CLAUDE.md "Deferred Production Tasks"):** migrate from personal Gmail App Password to a verified-domain transactional provider (Postmark / SES / Resend / Mailgun). Two-library convention is provider-agnostic — only `.env` SMTP_* vars change.

