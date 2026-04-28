# PLB-6 -- UptimeRobot deferred to launch day

**Status: PARTIAL.** Procedure is documented in
`docs/runbooks/uptime-monitoring.md`; live monitor creation is
blocked by the absence of a public URL for `/api/ping`.

## Why partial, not closed

UptimeRobot is a public-internet probe service. It cannot reach
`localhost`, `127.0.0.1`, or any of the WSL host-only IPs
(`10.0.3.x`). The only thing left to close PLB-6 is to wire up the
monitor in UptimeRobot's UI, point it at the live `/api/ping`, and
fire a test alert. None of that is possible until production is
deployed.

Production deployment is itself blocked on payment infrastructure
(Revolut / Monzo card pending) -- noted by the user 2026-04-28.

## Why the partial is acceptable

* Code-side prerequisite: `/api/ping` already exists at
  `dashboard/backend/app_cloud.py:557` and returns
  `{"status": "ok", "timestamp": "<iso>"}` HTTP 200. Verified.
* Runbook: `docs/runbooks/uptime-monitoring.md` ships every input
  the operator needs on launch day -- friendly name, interval,
  alert contacts, alert thresholds, the test-alert procedure,
  what to do on a real alert, and the cutover criteria for adding
  more monitors.
* No engineering work remains. The only remaining task is a 5-10
  minute web-UI session in UptimeRobot.

## What to do on launch day to fully close PLB-6

1. Sign in at https://uptimerobot.com (free Developer plan covers
   50 monitors, 5-minute interval -- enough for v1).
2. Follow the steps in `docs/runbooks/uptime-monitoring.md` -> the
   "Setting up the monitor (one time, in the UptimeRobot web UI)"
   section. Order of operations is: Alert Contacts -> Monitor.
3. Run **Option A** of the test-alert procedure (no customer impact)
   to confirm the email path works.
4. Forward the down + up emails to your records as evidence.
5. Update CLAUDE.md: PLB-6 row -> Closed (commit ..., date).
6. Update the report
   `verification/plb5_6/PLB-5-6-observability-2026-04-29.md` with:
     - Monitor URL + monitor ID from UptimeRobot
     - Screenshots / forwarded emails of the test alert path
     - Confirmation the recovery email arrived

## Out of scope for v1

* SMS alerts (paid tier).
* Public status page at status.aipet.io (defer until customer
  base justifies it).
* Multi-region probes.
* Pingdom / StatusCake redundancy.

## Related

* `docs/runbooks/uptime-monitoring.md` -- the full operational
  runbook; this file is just the launch-day handover note.
* `docs/runbooks/sentry.md` -- the complementary observability
  runbook (PLB-5, closed).
