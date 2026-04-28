# Uptime monitoring -- runbook

PLB-6 closure. UptimeRobot watches `/api/ping` from the public internet
and emails when production stops responding. Sentry handles
"something inside production broke"; UptimeRobot handles "production
stopped answering at all".

## Why /api/ping?

`/api/ping` is the canonical liveness endpoint. It is:

* Unauthenticated (UptimeRobot can hit it without an API key).
* Cheap (returns a 25-byte JSON, no DB query, no auth check).
* Stable (defined in `dashboard/backend/app_cloud.py:557`,
  schema is `{"status": "ok", "timestamp": "<iso>"}`,
  HTTP 200 when alive).

If production cannot answer this endpoint within 30 s, something
is wrong at the network / process / database level and we want to
know within minutes -- not when a customer reports it.

## Monitors

The active production monitor list:

| Friendly name                         | URL                                  | Type | Interval | Timeout |
| ------------------------------------- | ------------------------------------ | ---- | -------- | ------- |
| AIPET X Production - /api/ping        | `https://aipet.io/api/ping`          | HTTP | 5 min    | 30 s    |

(Free tier minimum interval is 5 minutes. Move to a paid tier later if
sub-5-minute detection becomes important.)

Future monitors to add when those endpoints exist:

| Friendly name                         | URL                                  | When to add |
| ------------------------------------- | ------------------------------------ | ----------- |
| AIPET X Production - landing page     | `https://aipet.io/`                  | At public launch |
| AIPET X Production - dashboard login  | `https://app.aipet.io/`              | At first paying customer |

## Alert contacts

| Channel        | Address                  | Notify when down | Notify when up |
| -------------- | ------------------------ | ---------------- | -------------- |
| Email primary  | byallew@gmail.com        | yes              | yes            |
| SMS (paid)     | (deferred -- paid tier)  | -                | -              |

Recovery alerts are on so we get a clear "all clear" signal --
without it, multiple short outages produce noise but no resolution.

## Setting up the monitor (one time, in the UptimeRobot web UI)

1. Sign in at <https://uptimerobot.com>.
2. Add a contact:
   * **My Settings -> Alert Contacts -> Add Alert Contact**
   * Type: E-mail
   * Friendly name: "Binyam primary"
   * Email: byallew@gmail.com
   * Save and verify (UptimeRobot sends a confirmation email).
3. Add the monitor:
   * **Monitors -> + Add New Monitor**
   * Monitor type: HTTP(s)
   * Friendly name: `AIPET X Production - /api/ping`
   * URL: the production URL of the ping endpoint
   * Monitoring interval: 5 minutes
   * Monitor timeout: 30 seconds
   * HTTP method: GET
   * Expected status codes: 200
   * Alert contacts: tick "Binyam primary" with **Notify when down** and
     **Notify when up** both enabled. Set "Notify after 1 failure" so
     a single missed check (5 min) raises an alert -- this is the
     fastest free-tier escalation.
   * Save.
4. The monitor turns green ("Up") within ~30 seconds if the URL is live.

## Testing the alert path (do this before the team relies on it)

There are two safe ways to confirm that an alert email actually arrives.
Pick one. **Do not test by stopping production unless you've coordinated
the maintenance window**:

### Option A -- temporarily change the monitored URL to a 404 path

* In the UptimeRobot UI: edit the monitor, change URL from
  `/api/ping` to `/api/this-does-not-exist` and save.
* Wait 5-10 minutes.
* Email arrives ("AIPET X Production - /api/ping is DOWN").
* Edit the monitor back to `/api/ping`. Within the next interval the
  recovery email arrives.
* Forward both emails to your archive -- evidence for PLB-6 closure.

### Option B -- stop the backend during a coordinated 6-minute window

* Announce a 6-minute maintenance window.
* `sudo systemctl stop aipet-gunicorn` (or kill gunicorn manually).
* Wait 5-10 minutes for the monitor to mark down + email.
* Restart the backend.
* Wait for the recovery email.

Option A is preferred because it has zero customer impact.

## When an alert fires

The email subject is the monitor's friendly name + "is DOWN" /
"is UP". Triage in this order:

1. **Is the alert real?**
   * Curl the URL yourself: `curl -i https://aipet.io/api/ping`
   * If you get HTTP 200, the alert may be a flake (UptimeRobot's
     own probe network had a transient issue). Wait one cycle for
     the recovery email.
   * If you get a real failure, continue.

2. **Where is the failure?**
   * Network -- is `aipet.io` resolvable? `dig aipet.io`
     If DNS fails: cloud DNS provider issue. Check status pages.
   * TCP/TLS -- is port 443 open?
     `openssl s_client -connect aipet.io:443 -servername aipet.io < /dev/null`
   * Reverse proxy (nginx) -- `sudo systemctl status nginx`
   * Application -- `sudo systemctl status aipet-gunicorn`
     and `journalctl -u aipet-gunicorn -n 100 --no-pager`
   * Database -- `pg_isready -h localhost -p 5433`

3. **Is the cause already in Sentry?**
   * Check Sentry Issues. If the application exited because of an
     unhandled exception, it'll be there with a stack trace.

4. **Restore service.**
   * Most common cause is a worker crash that systemd would normally
     restart but for some reason hasn't (out of memory, hit
     `RestartLimit`, ...). `sudo systemctl restart aipet-gunicorn`
     usually clears it.
   * If a database failure: see `docs/runbooks/backup-and-restore.md`.

5. **Recovery email arrives.**
   * Confirms service is back up.
   * If the email doesn't arrive, the monitor configuration is
     broken; fix the monitor before fixing the next outage.

6. **Post-incident.**
   * If the alert fired for >5 minutes, write a short note in the
     incident log with: time, symptoms, root cause, mitigation.
   * If the alert was a flake or a known maintenance window, ignore.

## Adding new monitors as the platform grows

UptimeRobot's free tier covers 50 monitors. Add a monitor whenever:

* A new service goes public (e.g. a marketing site at
  `https://aipet.io/`, the agent installer download endpoint).
* A critical third-party dependency you can probe externally goes
  down often enough that you'd want to see it before customers do
  (this is rare; most third-parties have their own status pages).

Don't add a monitor for every individual endpoint -- the goal is
fast detection, not exhaustive validation.

## Status page (deferred)

UptimeRobot offers a public status page on the free tier. Defer
configuring it until aipet.io is live and there are external
customers who need the visibility. When the time comes:

* **My Settings -> Public Status Pages -> + Add Public Status Page**
* Custom domain: `status.aipet.io` (requires a CNAME to UptimeRobot)
* Monitors to include: all production monitors
* Visibility: public

Tracked separately from PLB-6 closure.

## See also

* `docs/runbooks/sentry.md` -- the complementary "what's broken
  inside production" runbook.
* `verification/plb5_6/PLB-5-6-observability-2026-04-29.md` -- the
  closure report for both observability PLBs.
