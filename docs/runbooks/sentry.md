# Sentry error tracking -- runbook

PLB-5 closure. Sentry is the default destination for unhandled
exceptions, slow requests (10 % of traffic), and SQLAlchemy / Celery
errors. This runbook describes how it is wired, what is and is not
sent, and how to operate it.

## Where the code lives

* `dashboard/backend/observability/sentry_setup.py` -- the init
  function, the `_before_send` PII/secret scrubber, the regex pattern
  table, the release-version resolver.
* `dashboard/backend/app_cloud.py` (lines 22-29) -- the call site
  that runs at module-import time, BEFORE Flask / SQLAlchemy / Celery
  are imported. Sentry must initialise first so its integrations can
  patch those frameworks.

## Configuration

Set in `.env` (gitignored):

```
SENTRY_DSN=https://<key>@o<orgid>.ingest.<region>.sentry.io/<projectid>
APP_RELEASE=                    # optional; defaults to short git SHA
FLASK_ENV=development           # tags Sentry events with the environment
```

Production must source `SENTRY_DSN` from secrets management
(Vault / AWS Secrets Manager / 1Password) -- never check it into
version control.

If `SENTRY_DSN` is unset, `init_sentry()` logs a single
`Sentry: SENTRY_DSN not set -- skipping init` line at INFO and
returns. The app runs identically without Sentry; this is the
canonical way to disable error tracking in dev.

## What is sent to Sentry

* Unhandled exceptions caught by the Flask integration (auto).
* SQLAlchemy errors and slow queries.
* Celery task failures.
* 10 % of all requests get a performance trace
  (`traces_sample_rate=0.1`).
* The release identifier (env `APP_RELEASE` or short git SHA).
* The environment tag (env `FLASK_ENV`, default `development`).

## What is NOT sent (PII / secret scrubbing)

`send_default_pii=False` is set globally, so the SDK does not auto-
attach user IPs, cookies, or `Authorization` headers. On top of
that, every event passes through `_before_send` which scrubs:

### Header denylist (replaced with `[Filtered]`)

* `Authorization`, `X-Agent-Key`, `X-API-Key`,
  `X-Forwarded-Authorization`, `Proxy-Authorization`
* `Cookie`, `Set-Cookie`, `X-CSRF-Token`

### Body key denylist (case-insensitive, replaced with `[Filtered]`)

* `password`, `current_password`, `new_password`, `confirm_password`,
  `old_password`
* `secret`, `client_secret`, `private_key`, `vapid_private_key`
* `api_key`, `agent_key`, `full_key`,
  `stripe_secret_key`, `anthropic_api_key`, `otx_api_key`,
  `sentry_dsn`
* `jwt`, `token`, `access_token`, `refresh_token`, `id_token`
* `session_key`

### Pattern scrubber (works on free-form strings, e.g. exception messages)

| Pattern                                | Replacement                |
| -------------------------------------- | -------------------------- |
| `aipet_<urlsafe-base64 of length 20+>` | `[Filtered:aipet_key]`     |
| JWT (3 base64url segments)             | `[Filtered:jwt]`           |
| Sentry DSN                             | `[Filtered:sentry_dsn]`    |
| `sk_live_…` / `sk_test_…` (Stripe)     | `[Filtered:stripe_sk]`     |
| `sk-…` / `sk-ant-…` (LLM keys)         | `[Filtered:llm_key]`       |
| Postgres URI password                  | `[Filtered:db_password]`   |

`_before_send` is wrapped in a try/except that returns `None` on
any internal error -- the policy is **fail closed**: if scrubbing
crashes for any reason we drop the event rather than ship something
we couldn't scan. Better to lose telemetry than to leak secrets.

These rules are exercised by 24 unit tests in
`tests/test_zzzzzzzzzzzzzz_sentry_scrub.py` and run on every
`pytest` invocation. To add a new secret shape, extend
`_BODY_KEY_DENYLIST` or `_SECRET_PATTERNS` in `sentry_setup.py`
and add a matching test.

## Operating Sentry

### Daily

Check the Issues dashboard at `https://sentry.io/organizations/<org>/issues/`.

* New issues with high event count -> investigate first.
* Issues marked as `regression:true` -> the issue was previously
  resolved and re-appeared; treat as urgent.
* Issues tagged `environment:production` -> always prioritise over
  development noise.

### When an alert fires

1. Triage in the Sentry UI (or via the email link). Look at:
   * Frequency over time (one-off vs ongoing).
   * Affected users / requests.
   * Stack trace -- which file and which line.
2. If it's a real bug, file an issue (or a ticket in your tracker
   of choice) referencing the Sentry event URL.
3. Resolve in Sentry once the fix is shipped. If the fix is in a
   commit, mark the resolution with the commit so Sentry can detect
   regressions automatically.
4. If it's noise (a known third-party flake, a deprecated client
   firing), use Sentry's "Ignore" / "Mute until N occurrences"
   features rather than letting it accumulate.

### Disabling in dev

```
unset SENTRY_DSN
```

or comment the line in `.env`. Restart the gunicorn / dev server.
The startup log shows `Sentry: SENTRY_DSN not set -- skipping init`.

### Test the integration end-to-end

In a non-production environment (`FLASK_ENV != "production"`):

```
curl http://localhost:5001/api/sentry-test
```

That endpoint raises a `ValueError("PLB-5 sentry test")`. Within
60 seconds the exception should appear in the Sentry Issues
dashboard. The endpoint is registered conditionally: in production
(`FLASK_ENV=production`) it is **not** registered at all -- a
publicly-reachable `/api/sentry-test` would be a small but real
DoS vector.

## Cost notes

* `traces_sample_rate=0.1` -> 10 % of requests get performance
  traces. At a typical RPM the free tier should handle this.
  Lower it if your event budget is exhausted.
* `profiles_sample_rate=0.0` -> no profiling. Profiling is a
  separate feature with its own quota.
* Pricing: Sentry Developer plan covers 5k events/month free.
  Move to Team if event volume exceeds.

## See also

* `verification/plb5_6/PLB-5-6-observability-2026-04-29.md` -- the
  closure report.
* `tests/test_zzzzzzzzzzzzzz_sentry_scrub.py` -- the scrubber test
  suite (24 cases).
* `docs/runbooks/uptime-monitoring.md` -- the complementary
  alive-or-dead monitor.
