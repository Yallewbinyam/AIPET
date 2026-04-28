# Pattern A -- owner-implicit access to own deleted devices

| Field | Value |
| --- | --- |
| **Date** | 2026-04-28 |
| **Branch / starting HEAD** | `main` / `da266c33` (soft-delete v1 closure) |
| **Tests added** | 5 net new (was 17, now 21 in the soft-delete file; full suite 488 -> 492) |
| **Status** | Recovery gap **CLOSED** for v1 |

## What changed

The "View deleted" toggle on Agent Monitor previously returned 403
unless the caller had the `audit:read` permission or `owner` role. A
regular tenant user who soft-deleted their own device by accident had
no UI path to recover it. That is unacceptable basic UX for a
data-retention feature.

Pattern A opens the per-tenant include_deleted view to any
authenticated user, while keeping cross-tenant viewing behind the
existing admin gate via a separate explicit flag.

## Auth model (post-Pattern-A)

`GET /api/agent/devices` now has three modes:

| Query string | Visibility | Auth |
| --- | --- | --- |
| (default) | Caller's own ACTIVE devices | JWT |
| `?include_deleted=true` | Caller's own + soft-deleted | **JWT only -- no perm needed** |
| `?include_deleted=true&all_tenants=true` | Deleted devices across all tenants | JWT + (`owner` role OR `audit:read` permission) |

Defensive guards:

* `?all_tenants=true` without `include_deleted=true` -> HTTP 400. The
  cross-tenant active-device snooping case is intentionally not
  supported -- forces future use cases to declare themselves.
* `?include_deleted=true&all_tenants=true` without admin role -> HTTP
  403. The cross-tenant gate did NOT regress when we opened the
  per-tenant gate.

Per-tenant scope (`filter_by(user_id=uid)`) is still applied as the
primary safety net for modes 1 and 2. Mode 3 is the only path that
drops the user_id filter, and only after the auth check.

## Tests

`tests/test_zzzzzzzzzzzzzzz_soft_delete.py::TestListEndpointFiltering`:

| Test | Asserts |
| --- | --- |
| `test_list_default_excludes_soft_deleted` (existing) | Default path returns active only |
| `test_user_can_view_own_deleted_devices` (NEW) | No-roles user can `?include_deleted=true` and sees own deleted |
| `test_user_cannot_view_other_users_deleted_devices` (NEW) | Per-tenant scope still applies even when include_deleted is open -- another tenant's deleted device does not appear |
| `test_user_can_restore_own_deleted_device` (NEW) | Pattern A round-trip: user soft-deletes own -> restores own |
| `test_admin_can_view_cross_tenant_with_explicit_flag` (NEW) | `?all_tenants=true` + owner role returns deleted devices across tenants |
| `test_all_tenants_without_include_deleted_rejected` (NEW) | `?all_tenants=true` alone -> 400 |
| `test_all_tenants_without_admin_role_rejected` (NEW) | `?all_tenants=true&include_deleted=true` without admin -> 403 |
| `test_list_include_deleted_with_owner_role_returns_deleted` (existing, still passes) | Owner can see their own deleted devices via include_deleted (now redundant with Pattern A but harmless) |

The previous test
`test_list_include_deleted_requires_audit_read_permission` was
**removed** -- it asserted exactly the bug Pattern A fixes. Its
replacement is `test_user_can_view_own_deleted_devices` which
asserts the new correct behaviour.

Full pytest run after Pattern A: **492 passed, 3 skipped** (was
488/3; +5 net new tests in this file, -1 stale test rewritten).

## Live verification

Backend SIGHUP'd to load the new code (gunicorn pid 243183).
test@aipet.io confirmed at this point to have **zero roles assigned**
-- the temporary owner grant from Phase 5 of the soft-delete v1
closure was already revoked at end of that session.

User refreshed Agent Monitor at http://localhost:3000 and:

* **Toggled "View deleted"** -- previously returned 403 toast and
  auto-untoggled. NOW: silently loads, shows the 3 soft-deleted
  devices (verify, Binyam Linux/WSL, Binyam Windows) greyed out
  with DELETED badges and restore buttons. **The bug is fixed.**
* Confirmed the toggle works for round-trip browsing of deleted
  devices.
* Final agent_devices state: 3 rows, all soft-deleted, dashboard
  active view shows "No agents connected".

The audit trail is unchanged from the soft-delete v1 closure (5
rows: 3 initial deletes + restore/re-delete from Phase 5
verification). Pattern A is a read-path fix; no new write events
were needed for the verify because the write paths already had
test coverage and the bug was specifically about the GET endpoint.

## Confirmation: temporary grant cleanup

Per the brief's Phase 3 instruction, confirm the temporary
audit:read / owner grant on test@aipet.io is removed:

```sql
SELECT u.email, COALESCE(r.name, '<none>') AS role
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.id
LEFT JOIN roles r ON r.id = ur.role_id
WHERE u.email='test@aipet.io';
-- result: test@aipet.io | <none>
```

The grant was already revoked at end of Phase 5 of the soft-delete
v1 closure (today's earlier session). No further action needed.
With Pattern A, this user's empty role set is now sufficient to use
the View Deleted feature on their own devices -- which is exactly
the point of Pattern A.

## What did NOT change

* Cross-tenant access (mode 3) still requires `owner` role or
  `audit:read` permission. The admin path is intact.
* `POST /api/agent/devices/<id>/restore` is still per-tenant scoped
  -- a user can only restore their own devices. Cross-tenant admin
  restore is **not** a feature today; the brief mentioned it as a
  possibility but expanding admin powers wasn't required for Pattern
  A's stated goal (own-device self-service). If a customer needs
  it, add a `?cross_tenant=true` flag to the restore endpoint
  later, gated on the same audit:read check as the list path.
* The soft-delete v1 audit trail format (action +
  `audit_log.node_meta` JSON) is unchanged.
* Backend logs, frontend layout, and the systemd-managed agent are
  untouched.

## Pattern C (Trash + 30-day retention) -- separate task

Pattern A is the focused fix that closes the recovery gap for v1.
Pattern C is the long-term design:

* A dedicated **"Recently Deleted" tab** rather than a checkbox toggle
  on the device list.
* **30-day retention policy** -- soft-deleted rows older than 30 days
  are hard-deleted by a Celery beat sweep (with audit log preserved).
* **Bulk restore / bulk hard-delete** in that view.
* **Per-device "Empty trash" affordance** for users who want to
  destroy their own data immediately (with confirmation).

Pattern C is tracked as a separate ~2.5 hour task. Not blocking
launch; nice-to-have.

## Recommendations (NOT closure items)

1. **Hard-delete-after-N-days policy** (Pattern C) -- ~2.5 hr.
2. **Audit log composite index** on `(action, timestamp DESC)` and
   `(resource, timestamp DESC)` -- as audit_log grows, queries like
   "show me device.soft_deleted events in the last 30 days for user
   X" will benefit. ~10 min in a future migration.
3. **Cross-tenant restore endpoint flag** (only if a real customer
   asks). ~15 min.
4. **`device:read_deleted` permission** -- if we later want a model
   where the include_deleted toggle is admin-only AND auditable, we
   can re-introduce a perm check with this narrower name. Tracked
   in case the product direction shifts; not needed for v1.

## Closure protocol

Soft-delete recovery gap -> CLOSED. Tracked in CLAUDE.md.
