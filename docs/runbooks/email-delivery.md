# Email delivery -- runbook

PLB-4 closure. Outbound email is the channel for password reset,
enterprise PDF report delivery, and ops alerts. This runbook
describes how it is wired, what credentials it needs, the
graceful-degradation contract when those credentials are missing,
how to rotate the App Password, how to swap to a transactional
provider before launch, and how to triage delivery failures.

## Where the code lives

* `dashboard/backend/observability/email_setup.py` -- `init_email(app)`
  reads SMTP_* env vars, sets the `MAIL_*` Flask config keys, binds
  `Mail(app)`, and writes `app.email_enabled = True/False`. Logs
  WARNING on enable (host/port/user/sender, never the password) and
  on disable (clear "DISABLED -- not set in .env" line).
* `dashboard/backend/app_cloud.py` -- `init_email(app)` called once
  inside `create_app()`. Same idempotency guarantee as Sentry: the
  app loads identically when SMTP_USER / SMTP_PASSWORD are unset.
* `dashboard/backend/auth/routes.py:forgot_password` -- pre-checks
  `app.email_enabled` before calling Mail.send. When disabled, logs
  a WARNING and returns the same enumeration-safe 200 message as the
  success path.
* `dashboard/backend/enterprise_reporting/routes.py:send_pdf_report`
  -- pre-checks `app.email_enabled`. When disabled, returns 503 with
  a runbook pointer (this path is user-initiated; surfacing the
  failure is the right behaviour).
* `dashboard/backend/monitoring/alerting.py:send_alert` -- raw
  `smtplib`, runs in Celery / signal-handler contexts where Flask
  app context may not exist. Same SMTP_* env vars, same skip-if-
  unset behaviour ("Email skipped -- SMTP not configured" print).

## Two-library convention

The project intentionally uses **two** SMTP libraries: Flask-Mail for
app-flow emails (auth, reports) and raw smtplib for ops alerts. They
share the same SMTP_* env vars. Future contributors who want to
introduce a third path: don't. Future contributors tempted to
consolidate to one: keep Flask-Mail for app paths because it
participates in the request lifecycle (logging, error handlers, JWT
identity) and keep smtplib for Celery/signal paths because the Flask
app context is not always available there.

## Naming convention

The canonical env-var prefix is **`SMTP_*`** (`SMTP_USER`,
`SMTP_PASSWORD`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM_NAME`). This
predates the introduction of Flask-Mail (which uses `MAIL_*`).
`init_email()` reads the SMTP_* vars and translates into Flask-Mail's
`MAIL_*` config keys at boot. **Do not rename SMTP_USER to
SMTP_USERNAME** -- the variable is referenced from `aipet_agent.py`,
`monitoring/alerting.py`, deploy templates, and operator muscle
memory; the cost of churn outweighs the cost of a non-Flask-Mail-
matching name.

## Configuration

Set in `.env` (gitignored at `.gitignore:142`):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=byallew@gmail.com
SMTP_PASSWORD=<gmail-app-password>     # 16 chars, no spaces in storage
SMTP_FROM_NAME=AIPET X Notifications
```

Rendered From: header: `"AIPET X Notifications <byallew@gmail.com>"`.

Production must source `SMTP_PASSWORD` from secrets management
(Vault / AWS Secrets Manager / 1Password) -- never check it into
version control.

If either `SMTP_USER` or `SMTP_PASSWORD` is unset, `init_email()`
logs a single WARNING and sets `app.email_enabled = False`. The app
runs identically; downstream paths short-circuit with explicit log
lines (forgot-password) or 503s (enterprise PDF email). This is the
canonical way to disable outbound email in dev.

## Operational checks

`/api/__email_test` (POST, dev-only -- gated on `FLASK_ENV !=
production`) sends a small HTML smoke message and returns the
rendered From: header. Use it to confirm:

```bash
curl -sS -X POST http://localhost:5001/api/__email_test \
  -H 'Content-Type: application/json' \
  -d '{"to":"<your-email>"}'
```

Expected response: `{"status":"sent","to":...,"from":"AIPET X
Notifications <...>"}` HTTP 200, ~2-3 seconds.

If the response is 503 with `"Email backend disabled"`, SMTP_USER or
SMTP_PASSWORD is unset.

## Rotating the Gmail App Password

1. https://myaccount.google.com/apppasswords -> revoke the existing
   AIPET entry.
2. Generate a new app password (16 chars). Copy it once -- Google
   never shows it again.
3. Update `.env` (NOT via shell-history-visible `sed` -- use a
   text editor or a Python heredoc):
   ```bash
   python3 - <<'EOF'
   from pathlib import Path
   p = Path("/home/byall/AIPET/.env")
   lines = p.read_text().splitlines()
   for i, l in enumerate(lines):
       if l.startswith("SMTP_PASSWORD="):
           lines[i] = "SMTP_PASSWORD=NEWAPPPASSWORD"
           break
   p.write_text("\n".join(lines) + "\n")
   EOF
   ```
4. Reload Gunicorn so workers pick up the new env: `kill -HUP $(cat
   pids/gunicorn.pid)`.
5. Verify with `/api/__email_test` to your inbox.
6. Verify the new password is not in any log file:
   `grep -lF "<new-password>" /tmp/aipet_*.log` -- expect no match.

## Pre-launch: migrate to a transactional provider

The current setup uses a personal Gmail with a Gmail App Password.
This is fine for development and the first dozen real customers but
must be replaced before scale. Gmail enforces a 500-recipient/day
limit, has no per-message delivery analytics, and a single bounce or
spam complaint can suspend the entire personal account.

Options (in rough order of preference for a small SaaS):

| Provider | Free tier | Notes |
|---|---|---|
| Postmark | 100 emails/mo | Highest deliverability for transactional |
| AWS SES  | 62k/mo from EC2 | Cheapest at scale; warm-up takes a week |
| Resend   | 3k/mo | Simplest API; younger product |
| Mailgun  | 5k for 3 months | Strong tooling, complex pricing |

Migration steps (any provider):
1. Sign up, verify the sending domain (DKIM + SPF + DMARC records on
   `aipet.io` DNS).
2. Get the SMTP credentials (or API key) from the provider dashboard.
3. Update `.env`: `SMTP_HOST=<provider>`, `SMTP_PORT=587`,
   `SMTP_USER=<provider username>`, `SMTP_PASSWORD=<provider key>`.
4. Reload Gunicorn (`kill -HUP $(cat pids/gunicorn.pid)`).
5. `/api/__email_test` to a deliverable inbox; verify From: header
   renders the verified domain (e.g. `noreply@aipet.io`), not Gmail.
6. Update `SMTP_FROM_NAME` if the brand name should differ.
7. Trigger a real password reset; verify the email arrives without
   the "via gmail.com" suffix and without a spam-folder placement.

The two-library convention (Flask-Mail + smtplib) is provider-
agnostic -- any SMTP provider works without code changes.

## Triage: a customer reports they didn't get the reset email

1. Was the request actually made? Grep `/tmp/aipet_access.log` for
   `POST /api/auth/forgot-password` near the report time.
2. Did the request return 200? Grep `/tmp/aipet_error.log` -- a 500
   would have logged the exception.
3. Did the email actually go out? Grep
   `/tmp/aipet_cloud.log` for `Password reset email failed` -- if
   present, the SMTP send raised. The exception type tells you what:
     * `SMTPAuthenticationError` -> wrong/expired App Password.
     * `SMTPRecipientsRefused` -> Gmail bounced the recipient.
     * `SMTPServerDisconnected` -> transient; retry usually works.
4. Is `app.email_enabled` actually True in the running process?
   `curl http://localhost:5001/api/__email_test -d '{"to":"x"}'`
   returns 503 if not. (The endpoint is only registered in
   `FLASK_ENV != production` -- in production, check the boot
   WARNING log instead.)
5. Spam folder? Gmail-from-Gmail often lands in spam for
   non-Gmail recipients. Mitigation: migrate to a transactional
   provider with verified DKIM (see above).

## Security pins

* `SMTP_PASSWORD` is in the Sentry `before_send` body-key denylist
  (`dashboard/backend/observability/sentry_setup.py`,
  `_BODY_KEY_DENYLIST` includes `smtp_password`, `mail_password`,
  `smtp_user`, `mail_username`). An exception that stuffs MAIL_PASSWORD
  into its locals dict will not leak the value to Sentry.
* `email_status()` is the public introspection helper. It returns
  `enabled / host / port / user_configured / default_sender` only --
  the password is never returned.
* `tests/test_zzzzzzzzzzzzzzzz_email_backend.py::test_smtp_password_not_in_init_logs`
  pins the in-process logging behaviour: any future change to
  `init_email`'s log lines must keep the password out.
