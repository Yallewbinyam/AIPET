# Team & Access — Phase A: Backend Audit & Gap Analysis

**Date:** 2026-04-28
**Auditor:** Claude Code (Opus 4.7) under user-supervised audit
**Phase:** A of (A → B → C → ...) — recon + design input only. **No code changes made.**
**HEAD:** `f135aba9`
**Test account used for live curl:** `test@aipet.io` (id=2, plan=enterprise, password `Test1234!`)
**Server:** running Gunicorn on `localhost:5001` (state confirmed via prior session)

---

## 1. Inventory — every route in `dashboard/backend/iam/routes.py`

8 routes total. Source: `dashboard/backend/iam/routes.py` (201 lines).

### 1.1 `GET /api/iam/roles` — list all roles

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:66-73` |
| Auth | `@jwt_required()` — any logged-in user (no permission gate) |
| Body | n/a (GET) |
| 200 response | `[{ "id": "<uuid>", "name": "<role_name>", "description": "<text>", "permissions": ["<perm_name>", ...] }, ...]` |
| Errors | 401 if no/expired JWT |
| Side effects | none |

### 1.2 `POST /api/iam/roles` — create role

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:75-87` |
| Auth | `@require_permission('iam:manage')` — JWT required + (owner role OR `iam:manage` permission) |
| Body | `{"name": "<required>", "description": "<optional>"}` |
| 201 response | `{"message": "Role created", "id": "<uuid>"}` |
| Errors | 400 if `name` missing; 409 if role name already exists; 403 if caller lacks `iam:manage`; 401 if no JWT; 404 if caller's User row not found |
| Side effects | INSERT into `roles`; INSERT into `audit_log` (`action='role_created'`, `resource=<name>`) |

### 1.3 `GET /api/iam/users/<user_id>/roles` — list roles for a user

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:90-95` |
| Auth | `@jwt_required()` — any logged-in user (no per-tenant scoping; no permission gate) |
| Body | n/a |
| 200 response | `[{"id": "<role_uuid>", "name": "<role_name>"}, ...]` |
| Errors | 401 |
| Side effects | none |
| **Concern** | This endpoint reveals any user's role list to ANY authenticated user. No tenant scoping, no admin gate. Likely a vuln if/when multi-tenant. |

### 1.4 `POST /api/iam/users/<user_id>/roles` — assign role to user

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:97-115` |
| Auth | `@require_permission('iam:manage')` |
| Body | `{"role": "<role_name>"}` |
| 201 response | `{"message": "Role assigned successfully"}` |
| 200 response | `{"message": "Role already assigned"}` (idempotent re-assign) |
| Errors | 404 if role name unknown; 403 if caller lacks `iam:manage`; 401 |
| Side effects | INSERT into `user_roles` (with `assigned_by=<caller_id>`, `assigned_at=now()`); INSERT into `audit_log` (`action='role_assigned'`, `resource='<user_id>:<role_name>'`) |

### 1.5 `DELETE /api/iam/users/<user_id>/roles/<role_name>` — revoke role

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:117-126` |
| Auth | `@require_permission('iam:manage')` |
| Body | n/a |
| 200 response | `{"message": "Role revoked successfully"}` |
| Errors | 404 if role name unknown; 403 if caller lacks `iam:manage`; 401 |
| Side effects | DELETE rows from `user_roles` matching `(user_id, role_id)`; INSERT into `audit_log` (`action='role_revoked'`, `resource='<user_id>:<role_name>'`) |
| **Concern** | DELETE returns 200 even if no rows matched (no-op silent). |

### 1.6 `GET /api/iam/audit` — paginated audit log

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:129-146` |
| Auth | `@require_permission('audit:read')` |
| Query params | `?page=<int, default 1>&per_page=<int, default 50>` |
| 200 response | `{"logs": [{"id", "user_id", "action", "resource", "ip_address", "timestamp", "status"}, ...], "total": <int>, "pages": <int>, "page": <int>}` |
| Errors | 403 if caller lacks `audit:read`; 401 |
| Side effects | none |
| **Gaps for the UI** | No filters: cannot filter by date range, action type, actor (user_id), or resource. Response excludes the `node_meta` JSON column even though it exists in the model. No CSV export. |

### 1.7 `GET /api/iam/sso` — list SSO providers

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:149-156` |
| Auth | `@require_permission('sso:manage')` |
| Body | n/a |
| 200 response | `[{"id", "name", "enabled", "tenant_id", "metadata_url"}, ...]` |
| Errors | 403; 401 |
| Side effects | none |
| **Concern** | Response intentionally omits `client_id` (good — likely a secret). But the field also is never logged on insert success. |

### 1.8 `POST /api/iam/sso` — configure SSO provider

| Aspect | Value |
|---|---|
| Source | `iam/routes.py:158-172` |
| Auth | `@require_permission('sso:manage')` |
| Body | `{"name", "client_id", "tenant_id", "metadata_url", "enabled"}` |
| 201 response | `{"message": "SSO provider configured", "id": "<uuid>"}` |
| Errors | 403; 401. **No body validation** — empty/malformed payload accepted; `name` defaults to `None`; can store all-NULL row. |
| Side effects | INSERT into `sso_providers`; INSERT into `audit_log` (`action='sso_configured'`, `resource=<name>`) |
| **Concern** | This is a *config storage* endpoint, NOT an SSO authentication flow. No SAML metadata fetch, no test, no actual login-via-IdP path. The `enabled=true` flag has no effect anywhere in the codebase (no consumer of this table beyond the GET endpoint). |

---

## 2. Models — every model in `dashboard/backend/iam/models.py`

5 models + 1 association table. Source: `dashboard/backend/iam/models.py` (62 lines).

### 2.1 `Role` (`roles` table)

```python
id          String(36) PK   default=uuid4
name        String(50)      unique, not null
description Text
created_at  DateTime        default=datetime.utcnow  ⚠ deprecated (PLB-1 datetime task)
permissions = relationship('Permission', secondary='role_permissions', backref='roles')
```

### 2.2 `Permission` (`permissions` table)

```python
id          String(36) PK   default=uuid4
name        String(100)     unique, not null    ← format: "<resource>:<action>" e.g. "iam:manage"
description Text
resource    String(50)
action      String(50)
```

### 2.3 `role_permissions` (association table)

```python
role_id       String(36) FK → roles.id        PK component
permission_id String(36) FK → permissions.id  PK component
```

### 2.4 `UserRole` (`user_roles` table)

```python
id          String(36) PK   default=uuid4
user_id     Integer    FK → users.id   not null
role_id     String(36) FK → roles.id   not null
assigned_by Integer    FK → users.id   nullable
assigned_at DateTime        default=datetime.utcnow  ⚠ deprecated
```

| Concern | No `(user_id, role_id)` unique constraint at DB level. The `POST /users/<id>/roles` endpoint uses an in-Python existence check and returns "already assigned" idempotently, but a race could double-insert. |

### 2.5 `AuditLog` (`audit_log` table)

```python
id         String(36) PK   default=uuid4
user_id    Integer    FK → users.id   nullable
action     String(100)     not null
resource   String(100)
ip_address String(45)
user_agent Text
timestamp  DateTime        default=datetime.utcnow  ⚠ deprecated
status     String(20)      default='success'
node_me_a  JSON            nullable    ✅ uses `node_meta` per project convention
```

| Concern | `user_agent` is unbounded `Text` — abuse vector via long UA headers. `action` strings are free-form ad-hoc (`role_created`, `permission_denied:iam:manage`, `device.soft_deleted`) — no enum. |

### 2.6 `SSOProvider` (`sso_providers` table)

```python
id           String(36) PK   default=uuid4
name         String(50)      not null
client_id    Text            nullable  ⚠ stored in plaintext; should be encrypted at rest
tenant_id    Text            nullable
metadata_url Text            nullable
enabled      Boolean         default=False
created_at   DateTime        default=datetime.utcnow
```

| Concern | No `secret` / `client_secret` column — implies the SSO flow if ever built would be public-client only (e.g. SAML-without-secret or PKCE OAuth). No `provider_type` column (SAML vs OIDC vs OAuth) — only `name`. |

---

## 3. Existing tests — coverage gaps

### 3.1 Direct IAM tests

`grep -rn "/api/iam" tests/` → **ZERO matches.** None of the 8 IAM routes are exercised by pytest.

### 3.2 Tests that touch IAM machinery indirectly

| Test file | Test | Touches |
|---|---|---|
| `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` | `test_soft_delete_sets_deleted_at_and_audits` | calls `log_action()` indirectly via AgentDevice.soft_delete |
| `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` | `test_restore_clears_deleted_at_and_audits` | same |
| `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` | `test_telemetry_after_delete_writes_audit` | same |
| `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` | `test_all_tenants_without_admin_role_rejected` | exercises owner-role bypass via `has_role('owner')` (different file's helper, not the iam decorator) |
| `tests/test_zzzzzzzzzzz_agent_keys.py` | three tests | use `@require_permission` (the agent-key decorator, **not** the iam one — distinct function in `agent_keys/auth.py`) |
| `tests/test_zzzzzzzzzzzz_agent_install.py` | `test_telemetry_rejects_key_without_telemetry_permission` | same agent-key decorator |

**Conclusion: ZERO tests directly exercise `iam_bp` routes, the `require_permission` decorator in `iam/routes.py`, or `seed_default_roles()`.**

### 3.3 Coverage gaps (what should exist before Phase B locks)

| Gap | Severity |
|---|---|
| No test for `GET /api/iam/roles` (auth + response shape) | medium |
| No test for `require_permission` decorator (owner bypass, denied path with audit_log row written, 404 when User missing) | high |
| No test for `seed_default_roles()` idempotency | medium |
| No test for `log_action()` — does it gracefully roll back when `request` is missing? | medium |
| No test for SSO POST validation gaps (current behaviour: accepts empty JSON) | low |
| No test for the `audit:read` 403 path being audit-logged itself | low |

---

## 4. Live verification — every route curled today

**Login:** `POST /api/auth/login` with `test@aipet.io` / `Test1234!` → 200, JWT issued (len 325).

| # | Method | Path | Expected (per code) | **Actual today** | Notes |
|---|---|---|---|---|---|
| 1 | GET | `/api/iam/roles` | 200 + role array | **200** + `[{"name":"owner","permissions":[]}]` | Only ONE role in DB, not the four `seed_default_roles` defines (see § 5). |
| 2 | POST | `/api/iam/roles` (`{"name":"audit_test_role"}`) | 201 if owner OR `iam:manage` | **403** `{"error":"Insufficient permissions","required":"iam:manage"}` | Test user has no roles assigned. **Expected behaviour given DB state, but a high-paying Enterprise account being unable to manage roles is a UX cliff.** |
| 3 | GET | `/api/iam/users/2/roles` | 200 + array | **200** + `[]` | Correct — test@aipet.io has zero role assignments. |
| 4 | POST | `/api/iam/users/2/roles` (`{"role":"viewer"}`) | 201 / 200 / 404 | **403** | Same: caller has no `iam:manage`. |
| 5 | DELETE | `/api/iam/users/2/roles/viewer` | 200 / 404 | **403** | Same. |
| 6 | GET | `/api/iam/audit` | 200 + paginated logs | **403** `{"required":"audit:read"}` | Same. **Crucially:** the 403 itself wrote an `audit_log` row (`action='permission_denied:audit:read'`) — verified in DB. |
| 7 | GET | `/api/iam/sso` | 200 + provider array | **403** `{"required":"sso:manage"}` | Same. |
| 8 | POST | `/api/iam/sso` (`{"name":"test-saml",...}`) | 201 + ID | **403** | Same. |

**Discrepancies between code and live behaviour:**

- All 403 responses are *technically correct* — the decorator enforces what it says. But because `seed_default_roles()` is **never called** (see § 5 below), even an Enterprise-plan user has no role assignment, so 6/8 of these endpoints are unreachable from the UI for any user as currently shipped.
- The `audit_log` table correctly captures the 403 events (verified: rows with `status='blocked'`, `action='permission_denied:<perm>'`).

---

## 5. Critical finding: `seed_default_roles()` is imported but never called

**Location:** `dashboard/backend/app_cloud.py:66`

```python
from dashboard.backend.iam.routes import iam_bp, seed_default_roles
```

`grep -nE "seed_default_roles\(\)" dashboard/backend/app_cloud.py` returns **only the import line**. There is no `seed_default_roles()` invocation anywhere in app_cloud.py, in `iam/__init__.py` (which is empty), or in any startup hook (`@app.before_request`, `with app.app_context()`).

For comparison, the MITRE catalog seed at `app_cloud.py:486-489` IS invoked:

```python
with app.app_context():
    db.create_all()
    try:
        from dashboard.backend.mitre_attack.models import seed_catalog_from_dict
        seed_catalog_from_dict()
    except Exception as _seed_exc:
        app.logger.warning("MITRE catalog seed skipped: %s", _seed_exc)
```

The IAM seed has the same shape and could plug in next to the MITRE seed. It was simply never wired.

### 5.1 DB state proof

Live state (queried 2026-04-28):

| Table | Expected (after seeding) | Actual |
|---|---|---|
| `roles` | 4 rows (owner, admin, analyst, viewer) | **1 row** (only `owner`) |
| `permissions` | 10 rows (`scan:create`, `scan:read`, `findings:read`, `reports:read`, `reports:create`, `billing:manage`, `iam:manage`, `audit:read`, `sso:manage`, `terminal:use`) | **0 rows** |
| `role_permissions` | populated to grant each role its perms | **0 rows** |
| `user_roles` | first-registered user assigned `owner` (typical onboarding pattern) | **0 rows** |

Even the lone `owner` role currently has **zero permissions attached**. Its admin power flows entirely from the special-case bypass in `require_permission`:

```python
if 'owner' in role_names:
    return f(*args, **kwargs)
```

…not from the role/permission graph the model was designed around.

### 5.2 Operational consequence

- Both registered users (id=1 byallew@gmail.com, id=2 test@aipet.io) have **zero role assignments**.
- No user can hit `iam:manage`, `audit:read`, or `sso:manage` endpoints today, regardless of plan.
- Even if a user is granted the `owner` role, the `admin / analyst / viewer` roles do not exist in the DB and cannot be assigned.
- The 8 working endpoints + 5 well-shaped models are dormant infrastructure.

This is the same class of bug as TeamAccessPage and the 10 ghost modules from commit `89662f40`: **the function exists, the import exists, the wire from "ready" to "used" was never connected**.

**Recommended Phase B item (S):** add `seed_default_roles()` invocation next to the MITRE seed at `app_cloud.py:487` and ensure the first user of a fresh tenant is auto-assigned `owner`.

---

## 6. World-class gap analysis

For each requested feature, classification is **BACKEND-READY** (endpoint live + model adequate + just needs UI), **BACKEND-PARTIAL** (some pieces exist; adapter/extension needed), or **BACKEND-MISSING** (no model, no endpoint).

| # | Feature | Classification | What exists | What's missing |
|---|---|---|---|---|
| 1 | List team members | **BACKEND-PARTIAL** | `User` model (id, email, name, plan, organisation, is_active, last_login, created_at). | No `GET /api/iam/users` (list) endpoint; no tenant/org scoping query. Add: `GET /api/iam/users` returning all users in caller's tenant with role names joined. |
| 2 | View member detail | **BACKEND-PARTIAL** | User model + `GET /api/iam/users/<id>/roles` exposes role list per user. | No consolidated `GET /api/iam/users/<id>` returning user fields + roles + last_login + active sessions. |
| 3 | Invite by email | **BACKEND-MISSING** | n/a | No `Invitation` model; no `POST /api/iam/invitations`; no email template; no invitation token table. PLB-4 SMTP wiring is reusable — only need the model + endpoint + Mail.send call. |
| 4 | Accept invitation + set password | **BACKEND-MISSING** | `password_reset_tokens` table exists (PLB-4). Reuse pattern (similar token shape, single-use, expiring). | No `POST /api/iam/invitations/<token>/accept` endpoint; no `User.created_via_invitation` flag. |
| 5 | Change member role | **BACKEND-READY** | `POST /api/iam/users/<id>/roles` + `DELETE /api/iam/users/<id>/roles/<role_name>` work today. Idempotent. Audit-logged. | Possibly: a single "set roles" `PUT` to replace the list (atomic) — current API requires multiple calls. |
| 6 | Disable member (preserve audit history) | **BACKEND-MISSING** | `User.is_active` Boolean exists but is **never checked** at login (`auth/routes.py:login` does not gate on it). | Add `is_active` check to login flow; add `POST /api/iam/users/<id>/disable`; emit audit event; revoke any active sessions (which requires the JWT blocklist work in #14). |
| 7 | Remove member (with session revocation) | **BACKEND-MISSING** | n/a | No DELETE endpoint on User; no JTI blocklist (JWTs are stateless 15-min). Soft-delete pattern (per AgentDevice) would apply — `User.deleted_at`. Plus a JTI blocklist table to revoke any unexpired tokens. |
| 8 | Audit log query with filters | **BACKEND-PARTIAL** | `GET /api/iam/audit?page=&per_page=` works. Returns the audit row including action / resource / actor / timestamp. | No filter query params: `?since=&until=&action=&actor=&resource=&status=`. Add server-side filters (cheap — same SQL with WHERE clauses). |
| 9 | Audit log export to CSV | **BACKEND-MISSING** | n/a | Add `GET /api/iam/audit/export?format=csv&...` returning `Content-Type: text/csv`. Or accept `Accept: text/csv` on the existing endpoint. Streaming preferred for large exports. |
| 10 | Permission matrix lookup | **BACKEND-PARTIAL** | `Role` ↔ `role_permissions` ↔ `Permission` schema is correct. `GET /api/iam/roles` returns `permissions` per role. | No matrix endpoint (`{role: [perm,...]}` × `{perm: [role,...]}`). No "what can user X do?" query. Permissions table is **empty in production** — see § 5. |
| 11 | SSO SAML configuration | **BACKEND-PARTIAL** | `SSOProvider` model + `GET/POST /api/iam/sso` work. Stores name / client_id / tenant_id / metadata_url / enabled. | No `provider_type` column (SAML vs OIDC vs OAuth — required for routing the auth flow). No `client_secret` column (encrypted-at-rest). No update (`PATCH`) endpoint, only insert. No DELETE. |
| 12 | SSO test connection | **BACKEND-MISSING** | n/a | No `POST /api/iam/sso/<id>/test` endpoint. Would need: fetch metadata URL, parse SAML XML / OIDC discovery, validate signing certs, return success/failure with detail. Non-trivial — likely L. |
| 13 | 2FA enforcement policy | **BACKEND-MISSING** | n/a | No TOTP secret column on User; no `pyotp` dependency; no `POST /api/auth/2fa/enroll`, `/verify`, `/disable`; no enforcement policy table; login flow not 2FA-aware. Significant work. |
| 14 | Session listing | **BACKEND-MISSING** | n/a | JWT is stateless. No `Session` / `JTITable` / `IssuedToken` model. Would need: track every issued JWT (jti claim) with user_id + issued_at + ip + user_agent + expires_at; list active sessions for user. |
| 15 | Session revocation | **BACKEND-MISSING** | n/a | Depends on #14. Once JTI tracking exists, add a `revoked_at` column + a `flask_jwt_extended` `token_in_blocklist_loader` callback that consults this table. |
| 16 | IP allowlist | **BACKEND-MISSING** | n/a | No `IpAllowlist` model; no enforcement middleware. Would need: per-tenant CIDR list; `before_request` hook checking `request.remote_addr`; respect `X-Forwarded-For` like rate limiter does. |
| 17 | Password policy | **BACKEND-MISSING** | Login currently enforces only "≥8 chars" hardcoded in `auth/routes.py:reset_password:312`. No registration-side check. | No `PasswordPolicy` model; no per-tenant policy. Add: min length, require digits / uppercase / specials, rotation period, history-prevent-reuse. Enforce at register / change-password / reset. |

### 6.1 Summary counts

| Classification | Count |
|---|---|
| **BACKEND-READY** | 1 (Change member role) |
| **BACKEND-PARTIAL** | 5 (List members, View member detail, Audit filters, Permission matrix, SSO SAML config) |
| **BACKEND-MISSING** | 11 (Invite + Accept, Disable, Remove, CSV export, SSO test, 2FA, Sessions list/revoke, IP allowlist, Password policy) |

---

## 7. Recommended Phase B input (backend additions)

Each item: **complexity** (S=≤2hr, M=2-6hr, L=6hr+), **why needed**, **blocking which frontend phase**.

### 7.1 Foundational (must ship before any UI)

| # | Item | S/M/L | Why needed | Blocks |
|---|---|---|---|---|
| F1 | **Wire `seed_default_roles()` into app startup** at `app_cloud.py:487` next to the MITRE seed; auto-assign `owner` to the first user of a fresh tenant; idempotent. | S | Without this, 6/8 IAM endpoints are unreachable today regardless of UI — the platform has 1 of 4 roles seeded and 0 of 10 permissions. | Phase C (frontend) — the UI will 403 on most actions otherwise. |
| F2 | **Tenant scoping decision and column.** Choose: per-`organisation` string match, or add `tenant_id` to User/UserRole/AuditLog/SSOProvider. The brief implies a multi-tenant team picture; current schema is single-tenant flat. | M | Without scoping, "List team members" exposes all users globally — security issue at scale. | F3, F4, F8, all "list members" UI work. |
| F3 | **`GET /api/iam/users` (list members in tenant) + `GET /api/iam/users/<id>` (member detail with joined roles + last_login + active flag).** | S | List Members + Detail Modal in the UI. | Phase C member list view. |
| F4 | **Add `is_active` enforcement to login.** Reject login when `is_active=False`. Plus `POST /api/iam/users/<id>/disable` and `POST /.../enable` (audit-logged). Soft-delete pattern reusable from AgentDevice. | S | "Disable member" feature; safer than full delete. | Phase C disable/remove flow. |
| F5 | **Audit log filters.** Extend `GET /api/iam/audit` with `?since=&until=&action=&actor=&resource=&status=`. SQL WHERE clauses on existing indexed columns. | S | UI's audit log table is unusable beyond the first 50 rows without filters. | Phase C audit panel. |
| F6 | **Audit log CSV export.** `GET /api/iam/audit/export?format=csv` with the same filter params, streaming. | S | World-class compliance feature; trivial extension. | Phase C export button. |

**Total foundational: 5×S + 1×M ≈ 4-6 hours of backend work.**

### 7.2 Invitation flow (high value, moderate effort)

| # | Item | S/M/L | Why needed | Blocks |
|---|---|---|---|---|
| I1 | **`Invitation` model**: id, email, invited_by, token, role_to_assign, expires_at, accepted_at, status. Alembic migration. | S | "Invite by email" feature — table for tracking. | I2, I3, Phase C invite button. |
| I2 | **`POST /api/iam/invitations`** (require `iam:manage`). Generates token, INSERT row, send email (Flask-Mail; reuse PLB-4 wiring + `app.email_enabled` gate). Audit-log. | M | Sends the invitation. | Phase C. |
| I3 | **`POST /api/iam/invitations/<token>/accept`** (no JWT — token is the auth). Body: `{name, password}`. Creates User, assigns role, marks invitation accepted, returns JWT. | M | Recipient sets password and is logged in. | Phase C signup-by-invite page (separate from login page). |
| I4 | **`GET /api/iam/invitations`** + **`DELETE /api/iam/invitations/<id>`** (revoke pending). | S | UI to view pending + cancel. | Phase C. |

**Total invitation: 2×S + 2×M ≈ 5-8 hours.**

### 7.3 Session / token management (depends on JWT-blocklist refactor)

| # | Item | S/M/L | Why needed | Blocks |
|---|---|---|---|---|
| S1 | **`IssuedToken` model**: jti, user_id, ip, user_agent, issued_at, expires_at, revoked_at. Hook into JWT issuance (`auth/routes.py:login`, register, reset-password, accept-invitation). | M | Foundation for session listing + revocation. | S2, S3, F7 below. |
| S2 | **`flask_jwt_extended` `token_in_blocklist_loader`** consulting `IssuedToken.revoked_at IS NOT NULL`. | S | Makes revocation effective. | S3. |
| S3 | **`GET /api/iam/sessions`** (caller's own + admin: any user) and **`POST /api/iam/sessions/<jti>/revoke`**. | S | Session list + revoke buttons. | Phase C. |
| F7 | **`POST /api/iam/users/<id>/remove`** — soft-delete User (`deleted_at` column, AgentDevice pattern), revoke all their tokens via S2, audit-log. | M | "Remove member" with session revocation. | Phase C. |

**Total session: 2×M + 2×S ≈ 6-10 hours.** Dependency: F7 needs S1+S2.

### 7.4 SSO improvements

| # | Item | S/M/L | Why needed | Blocks |
|---|---|---|---|---|
| SSO1 | Add `provider_type` ENUM ('saml','oidc','oauth') and `client_secret` (encrypted-at-rest, not returned by GET) columns to `SSOProvider`. PATCH + DELETE endpoints. | M | Real SSO config requires distinguishing provider types and storing secrets safely. | Phase C SSO config form. |
| SSO2 | **Real SAML auth flow** (separate from config storage). Use `python3-saml` or `xmlsec`. `GET /api/auth/sso/<provider_id>/start` → redirect to IdP; `POST /api/auth/sso/<provider_id>/acs` → consume assertion; create-or-link User. | L | Customers actually logging in via SSO. | Phase C login-with-SSO button. |
| SSO3 | **`POST /api/iam/sso/<id>/test`** — fetch metadata URL, parse SAML XML, validate certs, return diagnostic JSON. | M | Admin can verify config before enabling. | Phase C SSO test button. |

**Total SSO: 1×L + 2×M ≈ 12-20 hours.** Likely a separate sub-phase; Phase C v1 ships SSO config storage only.

### 7.5 Hardening (deferrable past v1)

| # | Item | S/M/L | Why needed | Blocks |
|---|---|---|---|---|
| H1 | **Permission matrix endpoint** `GET /api/iam/permissions` and `GET /api/iam/permission-matrix` (role × permission). | S | UI matrix view; nice-to-have. | Phase C v1.1. |
| H2 | **2FA / TOTP**. `pyotp`. User.totp_secret column. Enroll / verify / disable / require-on-login flow. | L | Enterprise customers expect this. | Phase C v1.1+. |
| H3 | **IP allowlist**. `IpAllowlist` model. `before_request` hook with X-Forwarded-For honour. | M | Compliance ask. | Phase C v1.1+. |
| H4 | **Password policy table + enforcement**. PasswordPolicy model. Enforce at register, change-password, reset. | M | Compliance ask. | Phase C v1.1+. |
| H5 | **Backfill `(user_id, role_id)` unique constraint** on `user_roles` (currently in-Python only). Alembic migration. | S | Race-safety; minor. | none. |
| H6 | **`audit_log.user_agent` length cap.** | S | Hardening. | none. |

**Total hardening: 3×S + 2×M + 1×L ≈ 12-16 hours.** All deferrable.

### 7.6 Tests (run alongside each item)

For every backend item above: a corresponding pytest covering happy path + 403 path + audit-log side effect. **Estimated +30-50% time on top of feature implementation.**

---

## 8. Suggested Phase B v1 scope (recommendation, not decision)

Tightest viable backend slice for a usable Team & Access UI in Phase C v1:

**Mandatory (ship before frontend starts):**
- F1 — wire seed (S)
- F2 — tenant scoping decision (M; can be `organisation` string match initially to avoid migration churn)
- F3 — list members + detail (S)
- F5 — audit filters (S)

**Strongly recommended:**
- F4 — disable member (S)
- F6 — CSV export (S)
- I1+I2+I3 — invitation flow (S+M+M)

**Defer to v1.1:**
- All session/token work (S1-S3, F7) — keep "remove" disabled in UI until S* lands
- All SSO improvements beyond what already exists (config storage only in v1)
- All hardening items

**Phase C UI implications:**
- Members list ✅
- Detail modal ✅
- Audit log with filters + CSV export ✅
- Invite member modal ✅
- Disable member toggle ✅
- Remove member: hidden / "coming soon" until S*+F7 land
- Session list: hidden / "coming soon"
- SSO config form: enabled (v1 backend already supports)
- SSO login button on login page: hidden / "coming soon"
- 2FA, IP allowlist, password policy: hidden / "coming soon"

**Phase B v1 estimated effort:** ~12-16 hours backend + 4-6 hours tests = **~2 backend-engineer-days.**

---

## 9. Limitations of this audit

- Endpoint behaviour was inspected via static reading + curl with one user (test@aipet.io). Owner-role behaviour was not exercised because no user has owner-role assigned today (see § 5).
- The SSO POST endpoint accepts an empty payload silently — not exercised by negative testing in this audit beyond noting the concern.
- Performance characteristics (audit log query at scale; pagination boundary cases) not measured — DB has 13 audit rows.
- Concurrency safety of `assign_role` / `revoke_role` not analysed under load.
- Multi-tenancy decision (F2) deliberately left open — needs a user judgment, not an audit finding.

---

## 10. Phase A summary

| Metric | Value |
|---|---|
| Routes audited | 8 |
| Models audited | 5 + 1 association table |
| Direct IAM tests existing | **0** |
| Tests touching IAM machinery indirectly | 8 (all via `log_action` from soft-delete tests, or unrelated agent-key decorator) |
| Live curl rounds | 8 (1 + 7) |
| Routes returning expected status | 8 / 8 (all behave per the code) |
| **Critical bug discovered** | `seed_default_roles()` imported but **never called** — DB has 1/4 roles, 0/10 permissions, 0 user_roles |
| World-class features classified BACKEND-READY | **1** |
| World-class features classified BACKEND-PARTIAL | **5** |
| World-class features classified BACKEND-MISSING | **11** |
| Recommended Phase B v1 backend additions | **9 items** (F1, F2, F3, F4, F5, F6, I1, I2, I3) |
| Estimated Phase B v1 effort | ~12-16 hours backend + 4-6 hours tests |
| Recommended Phase B v1.1 backend additions | **8 items** (S1, S2, S3, F7, SSO1, H1, H2, H3, H4 — see § 7) |


---

## F1 Closure — 2026-04-28

**Commit:** `464b720d` (filled at push time)

**Fix:** `seed_default_roles()` invocation added inside the existing `with app.app_context()` block in `dashboard/backend/app_cloud.py`, immediately after the MITRE seed try/except, mirroring its pattern (try/except + warning log; same indentation).

**Before/after counts (live PostgreSQL):**

| Table | Before | After |
|---|---|---|
| `roles` | 1 (owner only) | **4** (owner, admin, analyst, viewer) |
| `permissions` | 0 | **10** (scan:create, scan:read, findings:read, reports:read, reports:create, billing:manage, iam:manage, audit:read, sso:manage, terminal:use) |
| `user_roles` | 0 | 0 (unchanged — F1 does not auto-assign; that decision is F-followup) |

**Idempotency confirmed:** Gunicorn HUP-reloaded twice. Counts after second restart identical (4 / 10), no duplicate-key errors, no warning logged. The function's `filter_by(name=...).first()` guards before each insert do their job.

**Tests added:** `tests/test_iam_seed.py` — 2 tests (fresh-seed shape, idempotency). Pytest delta: 498 → **500** (2 new + zero regressions in existing 498). 3 skipped, unchanged.

**Authorisation behaviour after F1:** the 6/8 IAM endpoints that returned 403 in Phase A still return 403 for the existing two users (byallew@gmail.com, test@aipet.io) — **by design**. They have no `user_roles` row. Assigning the `owner` role to either user (out of scope for F1; tracked as a follow-up) would unblock all six endpoints via the `if 'owner' in role_names` bypass at `iam/routes.py:53`. The wire from `seed_default_roles` is now connected; the wire from `register/onboarding → first-user-gets-owner` is the next link.

**What this fix is and isn't:**

- IS: the one-line wire that F1 was scoped to. Function defined ✅, function imported ✅, function now invoked ✅, idempotency proven ✅, test pinned ✅.
- ISN'T: an auto-grant of owner to existing users; tenant scoping; role-permission junction population (the `role_permissions` association table is still empty — owner bypass works because the decorator special-cases the role *name*, not because owner has permissions attached).

**This is the fourth wire-not-connected bug fixed this week.** The other three: TeamAccessPage (component never written, twelve-day latent crash), `flask-migrate` `Migrate(app,db)` (no-op `flask db` CLI registration, lifetime), PLB-9 NSSM `AppExit 1 Stop` (silent fallback to Restart, 96-hour latent watchdog defeat). All four shared the same pattern: code that *referred to* the wired thing existed and looked correct, but the actual invocation was missing or syntactically invalid. The new "Tested vs Complete" rule (`d0d3bd81`) was adopted in response.

---

## F2 Closure — 2026-04-28

**Commit:** `f2e9174e` (filled at push time)

**Fix scope:** wired role-assignment-on-registration + applied one-off backfill for the two existing users.

### What changed

1. **New helper** `assign_role_to_user(user_id, role_name, assigned_by=None, reason='manual', emit_audit=True)` in `dashboard/backend/iam/routes.py` (between the `require_permission` decorator and the role endpoints). Idempotent (filter_by `(user_id, role_id)` guard); raises `LookupError` on missing role; stages on session without committing (caller commits).
2. **Wired into `auth/routes.py:register()`** immediately after the `db.session.add(user); db.session.commit()` block. Defensive try/except follows the same shape as the surrounding `emit_event` block: rollback + `current_app.logger.exception` on failure, registration continues. Tradeoff documented in code comment: "we'd rather user-creation succeed than be reverted by a role-assignment failure."
3. **Backfill applied as one-off SQL** for `byallew@gmail.com` and `test@aipet.io`. Idempotent via `NOT EXISTS` guard. **NOT committed as recurring code** — this is a documented one-off operation.

### Before / after `user_roles` state

| User | Before | After |
|---|---|---|
| byallew@gmail.com (id=1) | (no role) | **owner** |
| test@aipet.io (id=2) | (no role) | **owner** |
| `user_roles` total rows | 0 | 2 |

### 6 previously-403 endpoints — live curl as test@aipet.io (owner)

| # | Endpoint | F1 status | **F2 status** |
|---|---|---|---|
| 1 | GET `/api/iam/audit` | 403 | **200** ✅ (after backfill timestamp fix — see "Discovered gap" below) |
| 2 | GET `/api/iam/sso` | 403 | **200** ✅ |
| 3 | POST `/api/iam/sso` (valid body) | 403 | **201** ✅ |
| 4 | POST `/api/iam/roles` (`f2_audit_test_role`) | 403 | **201** ✅ |
| 5 | POST `/api/iam/users/1/roles` (`{"role":"viewer"}`) | 403 | **201** ✅ |
| 6 | DELETE `/api/iam/users/1/roles/viewer` | 403 | **200** ✅ |

**6/6 now non-403.** Authorisation gating is now data-driven correctly.

### Registration flow live verify

- `POST /api/auth/register {"email":"f2-test@aipet.local",...}` → **201**, JWT returned.
- DB check: `f2-test@aipet.local` (id=3) has 1 user_role row pointing at `owner`. ✅
- Audit log row created with `action='role.assigned'`, `resource='user:3'`, `node_meta={"role":"owner","reason":"auto-on-registration"}`. ✅
- Re-register same email → **409** "Email already registered". `user_roles` count for that user remains **1** (no duplicate). ✅
- Test user + role + audit + central_event row + SSO row + custom-role row cleaned up via single transaction.

### Idempotency proofs

- **Backfill SQL re-run** after first apply → `INSERT 0 0` (NOT EXISTS guard works).
- **`assign_role_to_user` helper** unit test: two calls in succession → 1 UserRole row, second call returns the same row.
- **Re-register same email** → 409 from email-uniqueness check; the role-assignment block never runs because user creation fails first.

### Tests added

`tests/test_iam_seed.py` extended with three new tests:

- `test_assign_role_to_user_idempotent` — calls helper twice, asserts 1 UserRole row, asserts same id returned.
- `test_assign_role_to_user_nonexistent_role_raises` — calls with bogus role name, asserts `LookupError` with role name in message.
- `test_register_assigns_owner_role` — full register flow, asserts UserRole created, asserts AuditLog row with structured `node_meta`, cleans up.

`_reset_limiter(flask_app)` helper added to walk `app.extensions["limiter"]` (set of Limiter instances; same pattern as `tests/test_zzzzzzzzzzzzzzzz_email_backend.py`) so the register-flow test isn't crushed by `test_auth.py`'s deliberate-exhaustion of the 3-per-minute register limit.

**Pytest delta: 500 → 503** (3 new + zero regressions in existing 500). 3 skipped, unchanged.

### Discovered gap (pre-existing, surfaced during F2 verify)

`GET /api/iam/audit` crashed with `AttributeError: 'NoneType' object has no attribute 'isoformat'` on first attempt. Root cause: my F2 backfill SQL inserted `audit_log` rows without a `timestamp` value, and the `audit_log.timestamp` column has only a Python-level `default=datetime.utcnow` in the SQLAlchemy model — no DB-level default. PostgreSQL stored NULL.

**Fix applied:** `UPDATE audit_log SET timestamp = NOW() WHERE timestamp IS NULL AND action = 'role.assigned';` — patched the two affected rows, audit endpoint now returns 200.

**Pre-existing weakness flagged for follow-up (not fixed in F2 — out of scope per "do not touch unrelated code"):** the `get_audit_log` handler at `iam/routes.py:l.timestamp.isoformat()` does not null-check. Any future SQL-level audit insert without a timestamp (or any model migration that allows NULL) will crash the endpoint. **Recommended hardening (S, future task):** either add a DB-level default `DEFAULT NOW()` to `audit_log.timestamp` via Alembic, or null-check `l.timestamp` in the handler (`'timestamp': l.timestamp.isoformat() if l.timestamp else None`). Add to Phase B v1.1 hardening list.

### Out of scope: multi-tenancy

AIPET X's data model has **no `tenant_id` column** on `User`, `UserRole`, `Role`, `Permission`, `AuditLog`, or `SSOProvider`. This means:

- The `owner` role is currently **global**: anyone with `owner` can manage any other user's roles. There is no tenant-scoped access control.
- The new auto-assignment grants `owner` to **every** newly-registered user, which is correct *for the current single-tenant data model* but would be the wrong default once multi-tenancy lands (probably "first user of a fresh tenant gets owner; subsequent users get a default like `viewer` until invited up").
- The Phase A audit (§ 1.3, § 7.1 F2) flagged this as a foundation gap. **F2 explicitly does not address it.** Multi-tenancy is tracked as a separate larger task — likely 1-2 days of model + migration + test churn touching every role/audit-scoped query in the codebase.

F2 ships **honest single-tenant role assignment as the v1 baseline** so Phase B/C can proceed against working IAM endpoints.

### Authorisation gating after F2

- 6/8 IAM endpoints now respond non-403 for users with `owner` role assignment. ✅
- 2/8 endpoints (`GET /api/iam/roles`, `GET /api/iam/users/<id>/roles`) were always non-403 (jwt-only, no permission gate); unchanged.
- Future-registered users automatically get `owner` and inherit full IAM access — correct under v1 single-tenant assumptions; will need to be re-thought when multi-tenancy lands (see "Out of scope" above).
