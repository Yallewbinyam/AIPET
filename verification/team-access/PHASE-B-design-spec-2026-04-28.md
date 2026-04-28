# Team & Access — Phase B: Design Specification

**Date:** 2026-04-28
**Author:** Claude Code (Opus 4.7) under user-supervised audit
**Phase:** B of (A → B → C-I) — design only. **No code changes.**
**Inputs:** `verification/team-access/PHASE-A-backend-audit-2026-04-28.md` (Phase A audit + F1 + F2 closures)
**Scope confirmed by user:** full world-class v1 (Tier 1 + 2 + 3); single-tenant data model with documented multi-tenancy migration path; visual upgrade — Team & Access becomes the new visual baseline.
**HEAD at start of Phase B:** `de1b5066`

This document is the canonical artifact for build phases C-I. It is committed in four parts (§§ 1-3, §§ 4-5, §§ 6-8, §§ 9-12) so the user can review incrementally before later parts depend on earlier decisions.

---

## 1. Executive Summary

### 1.1 What v1 ships

A single Team & Access experience that exposes every feature a security-platform IAM admin would expect from a production SaaS, integrated cleanly into the existing AIPET X dashboard. v1 covers:

- **Members** — list, search, detail view, invite by email, accept-invitation onboarding, role change, disable/enable, remove (with session revocation), bulk actions.
- **Roles & permissions** — view default roles (owner / admin / analyst / viewer), create custom roles, edit role permissions, delete custom roles (defaults locked), live permission matrix view (role × permission).
- **Audit log** — paginated with date / actor / action / resource / status filters, structured `node_meta` viewer, CSV export.
- **SSO** — SAML provider configuration (CRUD), test-connection diagnostic, per-tenant enable/disable.
- **Sessions** — view own active sessions, revoke a single session, revoke-all-for-user (admin), session detail (IP, user agent, issued, expires, last seen).
- **Security policy** — tenant-wide 2FA enforcement policy (off / opt-in / required), IP allowlist (CIDRs), password policy (length, classes, rotation, history-prevent-reuse).

The UI uses an upgraded visual language that becomes the new AIPET X baseline (§ 2).

### 1.2 What is deferred and why

| Deferred item | Reason | Tracked as |
|---|---|---|
| Multi-tenancy in the data model | Schema migration touching every role/audit-scoped query (~1-2 days). v1 ships single-tenant but with explicit migration notes (§ 7). | Foundation gap, separate larger task. |
| Live SAML auth flow (login-via-IdP) | v1 ships SSO **config storage + test connection** only. The actual `GET /api/auth/sso/<provider>/start` redirect-and-ACS handler requires `python3-saml` integration (~1-2 days incl. cert handling, signature validation, attribute mapping). | Phase B v1.1 SSO sub-spec. |
| Real 2FA enrolment flow | v1 ships **policy** (enforce-or-not at tenant level). The actual TOTP enrol / verify / disable / require-on-login flow on the user side (`pyotp`, recovery codes, secret encryption-at-rest) is significant work. v1's policy is enforced as "users matching this policy must enrol within N days, banner shown until they do." Phase C ships the banner; the enrolment screen ships in v1.1. | Phase B v1.1 2FA sub-spec. |
| OIDC / OAuth providers (Google, Microsoft, Okta) | v1 ships SAML only — covers the Enterprise customer's use case. OIDC is incremental in v1.1; the `provider_type` column added in v1 makes adding it a per-provider build, not a re-architecture. | Phase B v1.1 SSO sub-spec. |
| Recovery / break-glass account | A dedicated "owner cannot lock themselves out" flow. v1 retains the safety-net of preventing the last owner from being demoted/disabled, but does not ship a separate emergency account. | Tracked as a v1.1 hardening item. |

### 1.3 Effort estimates per build phase

Estimates given as `<hours> ±<range>, <confidence>`.

| Phase | Scope | Hours | Confidence |
|---|---|---|---|
| **B-backend** | Backend additions before any UI work begins (§ 8) | **18 ±4** | high |
| **C** | Foundation: visual upgrade + Team & Access shell + Members list + detail + role change | 14 ±3 | high |
| **D** | Invitations: invite modal + email send + accept-invitation page + revoke pending | 10 ±3 | medium |
| **E** | Disable + Remove: session-revocation infrastructure + remove flow + last-owner safety net | 8 ±2 | medium |
| **F** | Audit log: filters UI + CSV export + node_meta viewer | 8 ±2 | high |
| **G** | Roles & Permissions matrix: view + custom role create/edit/delete + permission grant UI | 10 ±3 | medium |
| **H** | SSO: config CRUD + test-connection + enable/disable | 10 ±3 | medium |
| **I** | Security policy: 2FA policy + IP allowlist + password policy | 10 ±4 | low (depends on enforcement design) |
| **(deferred to v1.1)** | Real SAML auth flow + 2FA enrolment + OIDC | 32 ±10 | low |

**v1 total: ~88 hours** (~11 backend-engineer-days). Front-loaded backend (B-backend) so Phase C's UI work has working endpoints to call from day one.

**v1.1 total: ~32 hours** (~4 days). Splits cleanly: SAML auth (12 ±4), 2FA enrolment (12 ±4), OIDC (8 ±2).

**Multi-tenancy migration (separate from v1 / v1.1): ~16 hours ±6** (2 days), see § 7.6.

### 1.4 Critical dependencies

1. **Multi-tenancy schema migration** is *not* a dependency for v1 to ship (single-tenant is honest), but it *is* a dependency for v1 to be **production-shippable to multiple paying customers**. The design here is multi-tenancy-ready; § 7 spells out exactly what changes.
2. **PLB-4 SMTP wiring** must remain functional — the invitation flow depends on Flask-Mail. If SMTP regresses, invitations fail and the disabled-graceful-degradation path applies (Phase B says "show config-warning banner on Team & Access page when `app.email_enabled=False`").
3. **PLB-1 Alembic baseline** is already in place; every backend addition in § 8 ships its own Alembic revision. No migration drift permitted.
4. **The new "Tested vs Complete" rule** (CLAUDE.md, commit `d0d3bd81`): every Phase C-I deliverable closes only when click-through verification has happened. § 10 specifies the click-through scenarios explicitly per phase.
5. **`audit_log.timestamp` NULL hardening** (flagged at F2 close) — fix in Phase B-backend before Phase F's filtered audit queries can rely on the column. Either DB-level default or null-coalesce in handler.

---

## 2. Visual language inventory + upgrade

### 2.1 Inventory of existing AIPET X visual language

The current dashboard ships a coherent dark-mode aesthetic that is closer to GitHub-style than to Stripe / Vercel. There are two concrete realisations of it that differ in subtle ways — they should be reconciled.

#### 2.1.1 The canonical palette (App.js:73-95)

```
COLORS = {
  // Severity (alert)
  critical: "#ff4444",    high: "#ff8c00",    medium: "#f5c518",
  low:      "#00ff88",    info:  "#6b7280",

  // Brand
  blue:     "#00d4ff",    purple: "#8b5cf6",  cyan: "#00d4ff",

  // Background layers
  dark:     "#080c10",    darker:    "#04060a",
  card:     "#0d1117",    cardHover: "#111820",

  // Borders
  border:   "#21262d",    borderHover: "#30363d",

  // Typography
  text:     "#e6edf3",    muted: "#7d8590",    subtle: "#484f58",
}
```

This is the **canonical baseline**. Newer panels (`AutomatedResponsePanel`, `RiskScoreDashboard`, `EventsFeedPanel`, `MLAnomalyPanel`) use it directly. Files in `src/components/automated_response/`, `src/components/risk/`, etc. import from this set or re-declare it locally with the same values.

#### 2.1.2 The drift palette (e.g. SettingsPage:6063, DefenseMeshPage, AdversaryProfilingPage)

Older pages each declare a **local `C` object** with subtly different values. SettingsPage uses:

```
C = { card: "#0f1729",   border: "#1e3a5f",   blue: "#00b4d8",
      text: "#e2e8f0",   muted: "#64748b",   green: "#10b981" };
```

Differences worth noting:
- Card background is slightly cooler (`#0f1729` vs `#0d1117`) — a hint of indigo.
- Border is brighter and more blue (`#1e3a5f` vs `#21262d`).
- Brand blue is `#00b4d8` not `#00d4ff` — a less-saturated cyan.
- Text is slightly less white (`#e2e8f0` vs `#e6edf3`).

These differences are visible side-by-side. The team-access build is the right moment to consolidate; ~80 % of pages already use the canonical palette, and Settings-style drift is the minority.

#### 2.1.3 Component patterns observed across 5 representative pages

| Pattern | Where observed | What it does | Strength |
|---|---|---|---|
| Card with rounded-2xl + 1px border + p-6 | `AutomatedResponsePanel`, `RiskScoreDashboard`, every `StatCard` | Primary content container | strong, used everywhere |
| Sidebar-overlay-on-mobile with hamburger | App.js (Capability 12) | Mobile responsive nav | strong |
| `showToast(message, level)` prop drilling | every Page | Inline transient feedback | works but not centralised; toast queue lives in App.js |
| `token` JWT prop drilling | every Page | Auth | works but every page hardcodes `http://localhost:5001` URL prefix |
| Per-page local `C = { ... }` palette | SettingsPage, DefenseMeshPage, etc. | Page-level theming | inconsistent — primary refactor target |
| Tailwind classes mixed with inline `style={{ ... }}` | every Page | Styling | works but verbose; would benefit from extracted UI primitives |
| 86 inline `function NamePage({...})` definitions in App.js | App.js | Page routing | massive 30,823-line single-file; new pages should live in `src/pages/` |
| `useEffect`-driven axios fetch + manual `setLoading` | every Page | Data fetching | no shared hook; Phase C should introduce `useApi` |
| Three loading patterns (skeleton, spinner, blank) | scattered | Loading states | inconsistent — primary refactor target |

#### 2.1.4 Specific visual weaknesses to address

1. **No design tokens.** Colours are hex strings inline. Spacing is ad-hoc (`padding: "24px"`, `padding: "16px"`, `padding: "3px 10px"`). Typography sizes are inconsistent (mix of `text-xs`, `text-sm`, `fontSize: "11px"`, `fontSize: "13px"`).
2. **No shared UI primitives.** Every page reinvents `<Button>`, `<Modal>`, `<Table>`, `<EmptyState>`, `<Toggle>`. The Toggle component appears in at least four pages with subtle visual differences.
3. **No empty-state design language.** Some pages show `[]` literally; some say "No data yet"; some show a placeholder card.
4. **Loading states are inconsistent.** Some show a spinner; some show "Loading..."; some show nothing.
5. **Modal pattern is ad-hoc.** Modals are inline JSX with `position: fixed` overlays. No portal, no focus trap, no esc-to-close consistency.

### 2.2 The upgrade — Team & Access becomes the visual baseline

Phase C ships the upgrade as a small set of new primitives plus a reconciled palette. Other modules opt-in over time during Polish Pass 1 (already in CLAUDE.md Deferred Tasks).

#### 2.2.1 Reconciled design tokens (canonical, single source of truth)

These get extracted to `src/theme/tokens.js` and imported by every new component built in Phase C-I.

```js
// src/theme/tokens.js  -- the canonical AIPET X design tokens, v2.

export const COLORS = {
  // Severity (alert) -- unchanged from App.js current palette
  critical: "#ff4444",    high: "#ff8c00",    medium: "#f5c518",
  low:      "#00ff88",    info:  "#6b7280",

  // Brand
  brand:    "#00d4ff",    brandStrong: "#00b4d8",   // accent / on-press
  purple:   "#8b5cf6",                              // secondary brand

  // Surfaces (dark theme, layered)
  bg:       "#080c10",    bgDeep:    "#04060a",     // page bg / shadow
  surface:  "#0d1117",    surfaceHi: "#111820",     // card / hover
  overlay:  "rgba(8,12,16,0.72)",                   // modal scrim

  // Borders
  border:        "#21262d",  borderHover: "#30363d",
  borderFocus:   "#00d4ff",                         // focus ring

  // Text
  textPrimary:   "#e6edf3",  textSecondary: "#94a3b8",
  textMuted:     "#7d8590",  textSubtle:    "#484f58",

  // Status
  success: "#00ff88",  warning: "#f5c518",  danger: "#ff4444",
};

export const SPACING = {
  xs: 4,   sm: 8,   md: 12,   lg: 16,   xl: 24,   xxl: 32,   xxxl: 48,
};

export const RADIUS = {
  sm: 6,   md: 10,   lg: 14,   xl: 18,   pill: 9999,
};

export const TYPOGRAPHY = {
  // sizes
  micro:    { fontSize: 11, lineHeight: 1.4, letterSpacing: 0.4 },
  caption:  { fontSize: 12, lineHeight: 1.5, letterSpacing: 0.2 },
  body:     { fontSize: 14, lineHeight: 1.55 },
  bodyLg:   { fontSize: 16, lineHeight: 1.55 },
  h4:       { fontSize: 18, lineHeight: 1.3, fontWeight: 600 },
  h3:       { fontSize: 22, lineHeight: 1.2, fontWeight: 700 },
  h2:       { fontSize: 28, lineHeight: 1.15, fontWeight: 700, letterSpacing: -0.4 },
  h1:       { fontSize: 36, lineHeight: 1.1, fontWeight: 800, letterSpacing: -0.6 },
  mono:     { fontFamily: "'JetBrains Mono', ui-monospace, monospace" },
};

export const SHADOWS = {
  sm:  "0 1px 2px rgba(0,0,0,.4)",
  md:  "0 4px 16px rgba(0,0,0,.4)",
  lg:  "0 12px 40px rgba(0,0,0,.5)",
  ringFocus: "0 0 0 2px rgba(0,212,255,0.45)",
};

export const TIMINGS = {
  // Animation discipline -- all transitions use these exact values.
  fast:   "120ms cubic-bezier(.4,0,.2,1)",   // micro-interactions (hover, focus)
  base:   "200ms cubic-bezier(.4,0,.2,1)",   // default
  slow:   "320ms cubic-bezier(.4,0,.2,1)",   // modals, page transitions
};
```

**Rules:**
- New code imports `COLORS`, `SPACING`, `RADIUS`, `TYPOGRAPHY` from this module. No hex strings inline. No magic numbers.
- Existing code is left alone unless touched for another reason. No big-bang rewrite — Polish Pass 1 picks them up as it visits each page.
- Tailwind continues to coexist for layout (`flex`, `grid`, `gap-*`, `px-*`). Tokens above replace ad-hoc colour/typography/spacing inline styles.

#### 2.2.2 Refined component visual specifications

**Card** — primary container.

```
Background:    COLORS.surface (#0d1117)
Border:        1px solid COLORS.border (#21262d)
Border-radius: RADIUS.lg (14px)
Padding:       SPACING.xl (24px) -- mobile: SPACING.lg (16px)
Shadow:        SHADOWS.sm (subtle on dark BG)
Hover:         border-color → COLORS.borderHover; transition TIMINGS.fast
```

**Button** — three variants.

```
Variant: primary
  bg:            COLORS.brand (#00d4ff)
  color:         #000814 (deep contrast)
  height:        36px (md) / 32px (sm) / 44px (lg)
  padding-x:     16px / 12px / 20px
  border-radius: RADIUS.md (10px)
  font-weight:   600
  transition:    background-color TIMINGS.fast
  hover:         bg → COLORS.brandStrong (#00b4d8)
  disabled:      opacity 0.4, cursor not-allowed

Variant: secondary
  bg:            transparent
  border:        1px solid COLORS.border
  color:         COLORS.textPrimary
  hover:         border-color → COLORS.borderHover; bg → COLORS.surfaceHi

Variant: danger
  bg:            COLORS.danger (#ff4444)
  color:         #fff
  hover:         filter brightness(1.1)
  Used for:      Disable, Remove, Revoke actions ONLY
```

**Modal**

```
Portal:       rendered into document.body via React Portal
Scrim:        COLORS.overlay (#080c10ee), animate-in TIMINGS.base
Container:
  width:        clamp(320px, 480px, calc(100vw - 32px))
  bg:           COLORS.surface
  border:       1px solid COLORS.border
  radius:       RADIUS.xl (18px)
  shadow:       SHADOWS.lg
  padding:      SPACING.xl (24px) header, SPACING.xl body, SPACING.lg footer
Focus:        first focusable element receives focus on mount
              Escape closes
              clicking scrim closes (unless `closeOnScrim={false}`)
              Tab trap inside modal
Animation:    scale(0.96) → scale(1), opacity 0 → 1, TIMINGS.slow
```

**Table** — used heavily by Members, Audit, Sessions, etc.

```
Container:    Card (above)
Header row:
  bg:           COLORS.surfaceHi
  height:       40px
  font-size:    TYPOGRAPHY.caption (12px)
  letter-spacing: 0.6px
  text-transform: uppercase
  color:        COLORS.textMuted
  border-bottom: 1px solid COLORS.border

Body row:
  height:       52px
  border-bottom: 1px solid COLORS.border (last child: none)
  hover:        bg → COLORS.surfaceHi; transition TIMINGS.fast

Row actions: trailing column, right-aligned, icon-only buttons (32px),
             revealed on hover desktop / always visible mobile.

Empty state: when 0 rows, render <EmptyState/> in body area, NOT a row.
Loading state: skeleton (3 rows, animated shimmer), 320ms hold to avoid flicker.
Error state: inline <Error/> banner above the table.
Pagination: footer row with [<] [1] [2] ... [10] [>] using buttons (secondary),
            page-size dropdown ("25 per page" / "50" / "100").
```

**EmptyState**

```
Container:    centered, padding SPACING.xxxl (48px) top/bottom
Icon:         48px lucide icon at COLORS.textMuted
Title:        TYPOGRAPHY.h4 in COLORS.textPrimary
Description:  TYPOGRAPHY.body in COLORS.textMuted, max-width 340px
Action:       optional Button (primary or secondary)
```

**Toast**

```
Position:     fixed top-right (desktop), top-center (mobile)
Width:        360px (desktop) / calc(100vw - 32px) (mobile)
Padding:      SPACING.lg (16px)
Bg:           COLORS.surface
Border-left:  4px solid <variant colour>
              -- success: COLORS.success
              -- error:   COLORS.danger
              -- info:    COLORS.brand
              -- warning: COLORS.warning
Shadow:       SHADOWS.lg
Auto-dismiss: 5s (success / info), 8s (warning), 0s (error -- manual)
Stacking:     newest at top, max 5 visible, older fade out
```

**Loading patterns** — pick exactly one per surface:

- **Skeleton shimmer** for tables, lists, cards-with-known-shape. Animated linear-gradient sweeping left-to-right, TIMINGS.slow loop.
- **Spinner (24px)** for inline button-action confirmation. Lucide `Loader2` with spin animation.
- **Page-level barber-pole** (3px tall at top of page) for navigations between pages where data is loading.

**Animation discipline.** Every interactive element transitions `TIMINGS.fast` for hover/focus, `TIMINGS.base` for state changes (e.g. Toggle), `TIMINGS.slow` for modal/page transitions. No bouncy easing. No staggered reveals. No celebration animations. Quiet, fast, predictable.

#### 2.2.3 Typography rules

- Page H1 (e.g. "Team & Access"): TYPOGRAPHY.h1 (36px / 800 weight / -0.6 letter-spacing).
- Section H2 (tab content title): TYPOGRAPHY.h2.
- Card title: TYPOGRAPHY.h4.
- Table headers: TYPOGRAPHY.caption + uppercase + 0.6px tracking.
- Body copy: TYPOGRAPHY.body (14px).
- Inline metadata (timestamps, IDs): TYPOGRAPHY.caption + COLORS.textMuted.
- Code / IDs / fingerprints: TYPOGRAPHY.mono.

### 2.3 The takeaway

The visual upgrade is a small surface-area change — a single `tokens.js` plus a handful of primitives (`Button`, `Modal`, `Table`, `EmptyState`, `Toast`, `Toggle`) — but it pays for itself across Phases C-I and seeds the Polish Pass 1 work already on the deferred-tasks list. Team & Access becomes the canonical example of the new style. New modules opt-in by importing from `src/theme/`. Nothing existing breaks.

---

## 3. Information Architecture

### 3.1 Top-level placement

**Decision:** Team & Access is its own top-level sidebar entry, NOT a tab inside Settings. The current sidebar entry `{ id: "team", label: "Team & Access", icon: Shield, group: "enterprise" }` (App.js:5905) is reused; the click target was the broken TeamAccessPage that this work replaces.

**Rationale:**
- IAM management is operationally distinct from notification webhooks (Settings) or billing (Billing). Mixing them confuses the mental model.
- Audit log alone justifies a top-level entry — it's a primary compliance interface.
- The sidebar entry already exists and users already know to look there (the bug discovered 2026-04-28 was that the click crashed, not that the entry was unfindable).

The `Team & Access` entry stays in the `enterprise` group. Visibility: shown to all logged-in users; gated content within the page enforces per-role visibility (§ 3.3).

### 3.2 Page-by-page sitemap

The Team & Access page is one route (`/team`) but has internal tabs for sub-areas. Single route keeps deep-linking simple and matches the rest of AIPET X (no nested routing currently).

```
/team
├── tab: Members          (default)        — list, invite, manage
├── tab: Roles             — view defaults, create custom, permission matrix
├── tab: Audit log         — paginated, filtered, CSV export
├── tab: Sessions          — current user's sessions; admin sees all
├── tab: SSO               — SAML provider config
├── tab: Security policy   — 2FA enforcement, IP allowlist, password policy

```

Tab IDs:
- `members` (default landing)
- `roles`
- `audit`
- `sessions`
- `sso`
- `policy`

**Sub-modal flows** (rendered as modals on top of a tab, do not change route):
- Members → Invite Member modal
- Members → Member Detail drawer (right-edge slide-in, 480px wide)
- Members → Confirm Disable / Remove dialogs
- Roles → Create Custom Role modal
- Roles → Role Detail drawer (with permission grid)
- Audit log → Audit Event Detail drawer (shows full `node_meta` JSON)
- SSO → Configure Provider modal
- SSO → Test Connection result dialog
- Sessions → Confirm Revoke dialog

**Standalone routes** (NOT inside `/team`):
- `/invite/<token>` — accept-invitation page (recipient flow). No auth required; token is the auth.
- `/sso/start/<provider>` — SAML initiation (v1.1; placeholder route in v1).
- `/sso/acs` — SAML assertion-consumer (v1.1).

### 3.3 Permission gating per tab

Permission gates are derived from the `iam:manage`, `audit:read`, `sso:manage`, `policy:manage`, `sessions:read` permissions in the seed catalogue (with one new permission added in Phase B-backend, see § 8). All gates apply server-side at the endpoint; the UI mirrors the gates by hiding tabs the caller cannot use (server is authoritative — UI hiding is courtesy).

| Tab | Permission required | Owner sees? | Admin sees? | Analyst sees? | Viewer sees? |
|---|---|---|---|---|---|
| Members | `iam:read` (NEW — Phase B-backend) | ✅ | ✅ | ✅ (read-only) | ✅ (read-only) |
| Members → invite/disable/remove actions | `iam:manage` | ✅ | ✅ | ❌ | ❌ |
| Roles | `iam:read` | ✅ | ✅ | ✅ (read-only) | ✅ (read-only) |
| Roles → create/edit/delete | `iam:manage` | ✅ | ✅ | ❌ | ❌ |
| Audit log | `audit:read` | ✅ | ✅ | ❌ | ❌ |
| Sessions (own) | always (jwt-only) | ✅ | ✅ | ✅ | ✅ |
| Sessions (others) | `iam:manage` | ✅ | ✅ | ❌ | ❌ |
| SSO | `sso:manage` | ✅ | ❌ (by default; can be granted) | ❌ | ❌ |
| Security policy | `policy:manage` (NEW — Phase B-backend) | ✅ | ❌ (by default; can be granted) | ❌ | ❌ |

**The owner role bypass remains** (`iam/routes.py:53` — `if 'owner' in role_names: return f(*args, **kwargs)`). Owners see and can do everything regardless of granular permission grants. This is intentional v1 design and aligns with the seed catalogue's "owner = Full platform access" description.

**Two new permissions are needed** (currently absent from the seed catalogue):

- `iam:read` — list members + roles, view audit log row count without seeing rows. Lets analyst/viewer see "who's on the team" without granting role-management. Phase B-backend extends `seed_default_roles()` to add this permission and grant it to all four default roles.
- `policy:manage` — set tenant-wide 2FA / IP-allowlist / password-policy. Distinct from `iam:manage` so an admin who manages users isn't automatically granted policy authority.

(Alternative considered: reuse `iam:manage` for policy. **Rejected** — separation-of-concerns matters here; many compliance frameworks require dedicated policy authority, distinct from user management. Adding the permission is cheap; collapsing it later if it proves unused is also cheap.)

### 3.4 Visual hierarchy on the Team & Access page

```
┌──────────────────────────────────────────────────────────────────┐
│ Sidebar (existing, unchanged)                Team & Access ▶     │  Header bar
│                                              breadcrumb + actions │
├──────────────────────────────────────────────────────────────────┤
│  ┌──Tabs──────────────────────────────────────────────────────┐  │
│  │ Members │ Roles │ Audit log │ Sessions │ SSO │ Policy       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  [tab content — see Section 4 per flow]                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Header bar** (always visible):
- Left: breadcrumb `Team & Access › <Active Tab>`. TYPOGRAPHY.body in textMuted, last segment textPrimary.
- Right: tab-specific primary action button (e.g. "Invite member" on Members; "Create role" on Roles; "Export CSV" on Audit). Hidden on tabs without a primary action.

**Tabs** (segmented control):
- Underlined active tab using a 2px brand-coloured underline.
- Tabs hidden when caller lacks the gating permission (server-side gate is the truth; client merely doesn't render).
- Mobile: tabs become a horizontal-scroll overflow row with snap-to.

**Tab content area:**
- Max-width 1280px centred.
- Mobile: full-bleed.
- Each tab loads its own data on tab-activation (no pre-fetching). Loading state per tab.

### 3.5 URL state

- Active tab persisted as URL query param: `/team?tab=audit`. This makes deep-linking to "the audit log" possible (e.g. customer-support links).
- Audit-log filters persisted as additional query params: `/team?tab=audit&since=2026-04-01&action=role.assigned`.
- Modal state is **not** in the URL (consistent with rest of AIPET X). Refreshing the page closes any open modal.
- Pagination state is in the URL: `?tab=members&page=2`.

### 3.6 Empty platform-state

Two distinct first-use cases the design must handle:

1. **Fresh install, single user (the developer testing locally).**
   - Members tab: shows the 1 member (themselves) with "Owner" pill.
   - "Invite member" action visible.
   - Empty state copy: not applicable (1 row > 0 rows).
2. **Inherited platform (a customer whose previous IAM was something else).**
   - Could have ≥1 user with no role assignment — F2 fixes new-user assignment but doesn't backfill historical users.
   - Members tab: shows users with "(no role)" pill in red, "Assign role" inline-action.

The audit log empty state is **never empty in practice** because the audit log captures admin actions (and currently soft-delete + permission-denied events). Phase B does not need a special "empty audit log" copy beyond a generic "No audit events yet" message — but the system pre-fills the audit log as soon as anything happens, so this is mostly a v1-day-1-of-fresh-install case.

The roles tab is **never empty** — the four defaults are always present via `seed_default_roles()`.

### 3.7 Mobile information architecture

The Team & Access page collapses gracefully on phones:

- Tabs become a horizontal scroller with snap-to (existing AIPET X mobile pattern).
- Members table becomes a card-stack (one card per member; existing pattern from `RiskScoreTable` mobile fallback).
- Audit log table similarly card-stacks; filter row becomes a collapsible accordion.
- Modals become full-screen sheets at width < 640px (slide up from bottom).

Detailed mobile screens specified per flow in § 4.

---

*[End of Sections 1-3. Sections 4-12 follow in subsequent commits.]*
