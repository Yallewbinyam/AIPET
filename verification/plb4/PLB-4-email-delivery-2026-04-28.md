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

**Inbox confirmation:** _pending — awaiting user check of byallew@gmail.com_

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

_Pending._

---

## Phase 4 — Tests

_Pending. Five tests planned:_

1. `test_email_backend_initialises_with_smtp_set` — env vars set ⇒ `email_enabled=True`, `MAIL_SERVER` populated.
2. `test_email_backend_skips_init_with_smtp_unset` — env vars unset ⇒ `email_enabled=False`, app loads.
3. `test_email_send_calls_smtp_transport_when_configured` — mock `Mail.send`; verify `forgot_password` invokes it once with the reset URL in body.
4. `test_email_send_logs_warning_when_unconfigured` — `email_enabled=False`; `forgot_password` returns 200 + log captured at WARNING with "email backend disabled".
5. `test_smtp_password_not_in_logs` — log capture of init + send paths; assert SMTP_PASSWORD value never appears.

---

## Phase 5 — Documentation + push

_Pending._
- `docs/runbooks/email-delivery.md` — operator runbook (creds, rotation, transactional-provider migration plan).
- CLAUDE.md — close PLB-4 row; add "Email delivery" section under Architecture.
- Pre-deploy checklist item: migrate from personal Gmail App Password to a transactional provider (Postmark / SES / Resend).
