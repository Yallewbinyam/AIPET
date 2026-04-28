# PLB-5 + PLB-6 -- Observability closure

| Field | Value |
| --- | --- |
| **Date** | 2026-04-28 |
| **Branch / starting HEAD** | `main` / `a31b66e5` |
| **Sentry project region** | `de.sentry.io` (org id `o4511297267957760`, project id `4511297278771280`) |
| **Sentry public key length** | 32 hex chars |
| **PLB-5 status** | **CLOSED** |
| **PLB-6 status** | **PARTIAL -- deferred to launch day** |

## Summary

Both PLBs are observability primitives. Sentry tells you when something
breaks **inside** production (exceptions, slow requests). UptimeRobot
tells you when production stops **answering** at all. Together they
cover the basic alive-and-behaving question.

PLB-5 is closed today because we have a real Sentry project, the SDK
is wired with PII scrubbing, and live events have been shipped through
the real ingest endpoint. PLB-6 is partial because UptimeRobot is a
public-internet probe service and aipet.io is not yet public --
production deployment is blocked on payment infrastructure.

Three commits, plus a fourth for cleanup:

| # | SHA | Title |
| --- | --- | --- |
| -- | `3a47e55d` | PLB-9 cleanup-debt: AppExit 1 Stop -> Exit in README + matching test |
| 1 | `75fb0cb4` | **PLB-5**: Sentry error tracking with PII scrubbing |
| 2 | `27145e8b` | **PLB-6 PARTIAL**: UptimeRobot runbook ready; monitor creation deferred to launch day |
| 3 | (this commit) | report + CLAUDE.md + push |

## PLB-5: Sentry

### What changed in code

The Sentry init was previously a 9-line inline call inside `app_cloud.py`:

```python
sentry_sdk.init(
    dsn=_sentry_dsn,
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0,        # too expensive for production
    send_default_pii=False,
)
```

Replaced with a one-line call into a new module
`dashboard/backend/observability/sentry_setup.py` which carries the
full PLB-5 spec: SqlalchemyIntegration + CeleryIntegration,
traces_sample_rate=0.1, profiles_sample_rate=0.0,
environment + release tagging, and a `before_send` hook that scrubs
secrets before they leave the process.

Also addressed two bugs found during the recon:

1. `/api/sentry-test` was registered unconditionally -- a publicly-
   reachable endpoint that returned 500 was a small but real DoS
   vector. Now gated behind `FLASK_ENV != "production"`.
2. The `@app.errorhandler(500)` was calling
   `sentry_sdk.capture_exception(e)` manually. FlaskIntegration
   auto-captures, so 500s were being sent to Sentry twice. Manual
   capture removed.

### The `before_send` scrubber

Three layers of defence:

1. **Header denylist** -- entire header value replaced with
   `[Filtered]` (case-insensitive). Covers Authorization,
   X-Agent-Key, X-API-Key, X-CSRF-Token, X-Forwarded-Authorization,
   Proxy-Authorization, Cookie, Set-Cookie.

2. **Body-key denylist** -- entire field value replaced with
   `[Filtered]` (case-insensitive). Covers password (and variants),
   secret, client_secret, api_key, agent_key, full_key, private_key,
   vapid_private_key, stripe_secret_key, anthropic_api_key,
   otx_api_key, sentry_dsn, jwt, token, access_token, refresh_token,
   id_token, session_key. Recurses into nested dicts and lists.

3. **Pattern scrubber** -- substring replacement inside free-form
   strings (exception messages, top-level message, breadcrumb data).

   | Pattern                              | Label                  |
   | ------------------------------------ | ---------------------- |
   | `aipet_<urlsafe-base64>`             | `[Filtered:aipet_key]` |
   | JWT (3 base64url segments)           | `[Filtered:jwt]`       |
   | Sentry DSN                           | `[Filtered:sentry_dsn]`|
   | `sk_(live|test)_*`                   | `[Filtered:stripe_sk]` |
   | `sk-(ant-)?<32+>`                    | `[Filtered:llm_key]`   |
   | Postgres URI password                | `[Filtered:db_password]`|

The hook is wrapped in a try/except that returns `None` on any
internal error -- the policy is **fail-closed**: drop the event
rather than ship something we couldn't scan. This matters because
a buggy scrubber that crashes silently is worse than no scrubber
(the SDK would then ship the raw event).

### Test coverage

`tests/test_zzzzzzzzzzzzzz_sentry_scrub.py` has 24 unit tests across
seven test classes. They run on every `pytest` invocation and protect
the scrubber against regressions when new secret shapes are added.

```
TestSecretRegexes              (8 tests) -- regex patterns + word boundaries
TestHeaderDenylist             (4 tests) -- case-insensitive header replacement
TestBodyKeyDenylist            (6 tests) -- nested dicts + lists + case
TestExceptionScrubbing         (2 tests) -- exception value, top-level message
TestBreadcrumbs                (1 test)  -- breadcrumb data scrubbing
TestFailureMode                (1 test)  -- fail-closed on internal error
TestReleaseDetection           (2 tests) -- APP_RELEASE > git SHA > unknown
```

Full pytest run after the commit: **471 passed, 3 skipped**. Was
450/3 before the work; +24 sentry-scrub tests; -3 stale PLB-9 tests
folded into the AppExit-Stop-to-Exit cleanup commit.

### Live verification against the real Sentry project

DSN added to `.env` (gitignored) using the production-region project
the user provided. Backend gunicorn restarted. Three event paths
were exercised:

1. **Auto-capture path**: `curl /api/sentry-test` hit twice. Each hit
   raises `ValueError("PLB-5 sentry test")` at `app_cloud.py:574`.
   FlaskIntegration auto-captures. HTTP 500 returned to caller.

2. **Manual capture_message**: `sentry_sdk.capture_message(...)`
   returned event_id `b3bedbb84d8a457e818376e4bcb80a11`.

3. **Scrubber verification event**: `sentry_sdk.capture_message(...)`
   with a fabricated payload containing fake `aipet_*`,
   JWT, Stripe key, postgres URI, plus body-key denylist matches
   (password, client_secret, agent_key). Returned event_id
   `b37982f312c44c9d883ccc3bc570eee9`.

After all three: `client.transport` reported as `HttpTransport`
(real network), `client.flush(timeout=5)` returned cleanly without
timeout. Visual receipt + scrubbing inspection by the user in the
Sentry Issues UI -- evidence saved at
`verification/plb5_6/evidence/sentry_events_fired.txt`.

### What the SDK was running with

```
client.options.dsn               = (real, redacted)
client.options.environment       = development
client.options.release           = a31b66e5
client.options.traces_sample_rate = 0.1
client.options.profiles_sample_rate = 0.0
client.options.send_default_pii  = False
client.options.before_send       = set
client.transport                 = HttpTransport
active integrations              = aiohttp, anthropic, argv, atexit,
                                    celery, dedupe, excepthook, flask,
                                    httpx, logging, modules, redis,
                                    sqlalchemy, stdlib, threading
```

### PLB-5 acceptance

| Spec item | Result |
| --- | --- |
| App runs with `SENTRY_DSN` set | PASS |
| App runs with `SENTRY_DSN` unset (no init, no crash) | PASS |
| Test exception reaches Sentry | PASS (event ID returned by SDK + flush returned cleanly + user UI confirmation) |
| `before_send` scrubbing tested | PASS (24 unit tests + live event with 7 secret types) |
| `/api/sentry-test` gated to non-prod | PASS (verified via FLASK_ENV introspection) |
| Documentation in `docs/runbooks/sentry.md` | PASS |

## PLB-6: UptimeRobot

### Why this is PARTIAL

UptimeRobot is a SaaS probe service. It hits target URLs from the
public internet. It cannot reach `localhost`, `127.0.0.1`, or
WSL2 host-only IPs (`10.0.3.x`). Creating the live monitor requires
aipet.io to be deployed and publicly reachable.

Production deployment is itself blocked by the user on payment
infrastructure (Revolut/Monzo card pending) -- noted 2026-04-28.

Closing PLB-6 today would require fabricating a monitor against a
non-existent URL. That would not be honest closure.

### What this commit does ship

* `docs/runbooks/uptime-monitoring.md` -- the full operational
  runbook. Every input the operator needs on launch day:
    * Why `/api/ping` (cheap, unauthenticated, stable, defined at
      `app_cloud.py:557`).
    * Active production monitor table (HTTPS GET of
      `https://aipet.io/api/ping`, 5-minute interval, 30s timeout,
      expects 200).
    * Step-by-step UptimeRobot web-UI walkthrough (Alert Contacts
      first, then Monitor; "Notify after 1 failure" so a single
      missed 5-minute check raises an alert).
    * Test-alert procedure with two safe options. Option A
      (temporarily change URL to a 404 path) is preferred -- zero
      customer impact.
    * Triage procedure for a live alert (DNS / TCP-TLS / nginx /
      app / DB).
    * When to add more monitors.
    * Status-page deferral note (defer to post-launch).

* `verification/plb5_6/evidence/uptimerobot_pending_launch_day.md`
  -- the launch-day handover note. 6-step procedure for fully
  closing PLB-6 once aipet.io is public.

### PLB-6 acceptance (what it will look like at full closure)

| Spec item | Status today |
| --- | --- |
| Monitor exists and is "Up" in UptimeRobot UI | DEFERRED -- aipet.io not yet public |
| Test alert email received (user-confirmed) | DEFERRED -- nothing to fail yet |
| Documentation in `docs/runbooks/uptime-monitoring.md` | PASS |

## Incidents during PLB-5/6

### Incident 1 -- two stale PLB-9 test/doc artefacts

Full pytest run during PLB-5 work flagged
`test_appexit_1_is_stop` failing. Investigation showed PLB-9 closure
correctly fixed the installer (`AppExit 1 Stop` -> `AppExit 1 Exit`)
but did not update the unit test or the README that asserted the
old broken value. Fixed in a separate commit (`3a47e55d`) so PLB-5
work stayed focused.

Lesson: when fixing a bug + adding a regression test, also grep
for OTHER places that asserted the broken value. The test+README
were unchanged from before PLB-9 found the bug.

### Incident 2 -- gunicorn pkill killed parent shell exec

`pkill -KILL -f "gunicorn.*app_cloud"` matched my own bash command
substitution and the shell exited 144. Recovered by re-issuing the
launch command in a fresh subshell. Cosmetic; documented for future
operators who see exit 144 from a Bash tool call.

## Recommendations (NOT closure items)

### Production: source SENTRY_DSN from secrets management

The current `.env` has the dev DSN inline. Production deployment
must source it from Vault / AWS Secrets Manager / 1Password and
remove the line from `.env` before deploy. Same pattern as
`aipet_admin_password` in PLB-1.

### Add aipet.io status page (post-launch)

UptimeRobot offers a free public status page. Defer until aipet.io
has external users who'd benefit from it. Tracked in
`docs/runbooks/uptime-monitoring.md`.

### Future observability work (NOT blocking launch)

* Distributed tracing (OpenTelemetry) -- worth adding when there
  is a real microservice boundary to trace across.
* Structured logs -- the existing logging is text-based; moving
  to JSON would help when log volume grows.
* Business metrics + SLOs -- "% of devices that get a successful
  scan within 24h", etc. Different shape of telemetry from Sentry.
* Synthetic monitoring (more sophisticated than UptimeRobot) --
  log in, click around, log out -- once the dashboard is mature.

## Closure protocol

PLB-5 row in CLAUDE.md: `Closed (commit <PHASE3_SHA>, 2026-04-28)`.
PLB-6 row in CLAUDE.md: `Open (PARTIAL: code+runbook ready, monitor
creation deferred to launch day)`.

PLB count after this closure: **5 Open / 6 Closed** (was 4/5).
Three of the five remaining are launch-week / launch-day work
(PLB-4 SMTP credentials, PLB-6 PARTIAL, plus PLB-7 already-closed
production deploy). PLB-8 is the genuine engineering item left.
