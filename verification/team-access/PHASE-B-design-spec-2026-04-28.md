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

---

## 4. User flows

This section is the build-time contract. Phase C-I implementations follow these flows verbatim. Every flow lists trigger, steps, success path, error paths, audit log entries, backend endpoints called, and edge cases. ASCII wireframes are included for screens with non-trivial layout.

**Convention:** [+] = button, [□] = checkbox, [○] / [●] = radio, ▼ = dropdown, ↻ = refresh, … = ellipsis menu.

### F4.1 — List team members

**Trigger:** user clicks `Team & Access` in sidebar; default tab is `Members`.

**Steps:**

1. Page mounts, sets `loading=true`, fires `GET /api/iam/users?include_roles=true&search=&page=1&per_page=25`. Skeleton renders (3 rows).
2. Response arrives within ~200 ms typical. Render members table.
3. User can search (debounced, 250 ms), paginate (24/50/100 per page), and sort (email asc/desc, last_login asc/desc).
4. Each row shows: avatar (initials), name, email, role pill, last_login (relative time or "Never"), `…` menu.
5. Sticky header with primary action `[+ Invite member]` (if `iam:manage`) and a search input.

**Wireframe (desktop, ≥1024px):**

```
┌─ Team & Access › Members ──────────── [+ Invite member] ──┐
│  ┌─────────────────────────────────────────────────────┐  │
│  │ 🔎 Search by name or email...        Status: All ▼  │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │ MEMBER          ROLE     LAST LOGIN     STATUS  …  │   │
│  ├────────────────────────────────────────────────────┤   │
│  │ ┌──┐ Binyam     [owner]  2 minutes ago   ●Active ⋮ │   │
│  │ │BY│ byallew@…                                     │   │
│  │ └──┘                                               │   │
│  ├────────────────────────────────────────────────────┤   │
│  │ ┌──┐ PyTest     [admin]  yesterday       ●Active ⋮ │   │
│  │ │PT│ test@…                                        │   │
│  │ └──┘                                               │   │
│  ├────────────────────────────────────────────────────┤   │
│  │ ┌──┐ Anna Q     (no role)  Never        ⊝Pending⋮  │   │
│  │ │AQ│ anna@acme.io                                  │   │
│  │ └──┘                                               │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  Showing 3 of 3 members.    25 per page ▼                 │
└───────────────────────────────────────────────────────────┘
```

**Wireframe (mobile, <640px):**

Each member is a card stack:

```
┌─────────────────────────────────────────┐
│ Members                  [+ Invite]     │
│ 🔎 Search...                            │
├─────────────────────────────────────────┤
│ ┌─────────────────────────────────────┐ │
│ │ ┌──┐ Binyam              ⋮          │ │
│ │ │BY│ byallew@gmail.com              │ │
│ │ └──┘ [owner]  • 2 minutes ago       │ │
│ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │
│ │ ┌──┐ PyTest               ⋮         │ │
│ │ │PT│ test@aipet.io                  │ │
│ │ └──┘ [admin] • yesterday            │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Success path:** member rows render. Pagination + search + sort all client-driven against the server's response (server handles search/sort; client renders).

**Error paths:**
- Network error: row of toast "Failed to load members. Try again." + inline retry button. Existing data (if any) stays visible — no blanking.
- 401: axios interceptor wipes token + reloads (existing pattern at App.js:60-65).
- 403 (`iam:read`): the page itself is gated server-side; if reached, show `<EmptyState>` with "You don't have permission to view team members. Contact your administrator." No retry.
- Empty response: `<EmptyState>` with copy "No team members yet." + `[+ Invite member]` action.

**Audit log entries written:** none (read-only).

**Backend endpoints called:**
- `GET /api/iam/users?search=&page=&per_page=&include_roles=true` (NEW — Phase B-backend, see § 8 item F3)

**Edge cases:**
- Members with > 1 role assigned: render the highest-priority role + "+1" indicator on hover.
- Members with email > 50 chars: truncate with ellipsis, full email in tooltip.
- Members whose `is_active=false` (disabled): row dimmed (opacity 0.5), `Disabled` pill in red, action menu still allows Re-enable.
- Race: search-typing while pagination loads; cancel previous request via AbortController.

---

### F4.2 — View team member detail

**Trigger:** user clicks a member row OR clicks `View detail` in the row's `…` menu.

**Steps:**

1. Right-edge slide-in drawer opens (480px wide, full-height; mobile: full-screen sheet from bottom).
2. Drawer header shows member avatar + name + email + close button.
3. Body sections (top → bottom):
   - **Overview**: name, email, plan, organisation, industry, created_at, last_login, is_active.
   - **Roles**: pill list of assigned roles. `[Change roles]` button (if `iam:manage`).
   - **Active sessions**: count + link to Sessions tab filtered by this user.
   - **Recent audit events**: 5 most recent `audit_log` entries where `user_id = this user`, mini-list with `View all` link to Audit tab filtered.
   - **Actions footer** (sticky bottom): `[Disable]` `[Remove]` `[Resend invitation]` (last only if pending invitation). All gated by `iam:manage`.
4. ESC closes drawer; click outside closes drawer; URL does not change.

**Wireframe (drawer):**

```
              ┌──────────────────────────────────┐
              │ ┌──┐ Binyam Yallew         ✕    │
              │ │BY│ byallew@gmail.com           │
              │ └──┘                             │
              ├──────────────────────────────────┤
              │ Overview                          │
              │   Plan         Free               │
              │   Organisation —                  │
              │   Industry     —                  │
              │   Joined       2 days ago         │
              │   Last login   2 minutes ago      │
              │   Status       ● Active           │
              │                                  │
              │ Roles                  [Change]  │
              │   [owner]                        │
              │                                  │
              │ Active sessions          1       │
              │   View in Sessions tab →         │
              │                                  │
              │ Recent audit events              │
              │   • role.assigned   1h ago       │
              │   • user.login      2m ago       │
              │   View all →                     │
              ├──────────────────────────────────┤
              │ [Disable]  [Remove]              │
              └──────────────────────────────────┘
```

**Success path:** drawer renders within 300 ms (no skeleton needed if data already cached from members list).

**Error paths:**
- 404 (member deleted between list-load and detail-click): toast "Member no longer exists" + close drawer.
- 403 (caller lost permission since list-load): drawer shows the member overview (read-only), action buttons hidden.

**Audit log entries written:** none.

**Backend endpoints called:**
- `GET /api/iam/users/<id>` (NEW — § 8 item F3)
- `GET /api/iam/audit?actor=<id>&per_page=5` (existing, with new `actor` filter from § 8 item F5)
- `GET /api/iam/sessions?user_id=<id>&active=true` (NEW — § 8 item S3)

**Edge cases:**
- Caller views their own detail: actions footer shows "[Sign out all other sessions]" instead of `[Disable]/[Remove]`. Cannot disable / remove self.
- Caller is the last owner: `[Disable]/[Remove]` are present but disabled (greyed out) with tooltip "Cannot remove the last platform owner. Promote another user to owner first."

---

### F4.3 — Invite new member

**Trigger:** Members tab → `[+ Invite member]` button (in header bar).

**Steps:**

1. `Invite Member` modal opens.
2. Form fields:
   - Email (required, validated client + server)
   - Role (dropdown, defaults to `viewer`, options: viewer / analyst / admin / owner / +custom roles)
   - Optional: Welcome message (textarea, 240 char limit)
3. Submit button labelled `[Send invitation]` (primary). `[Cancel]` (secondary).
4. On submit: button loads (spinner replaces label, disabled state).
5. On success: toast "Invitation sent to <email>", modal closes, members list refreshes (the new pending row appears with `(no role)` and "Pending" pill).

**Wireframe (modal, 480px desktop):**

```
            ┌──────────────────────────────────────┐
            │ Invite Member                    ✕   │
            ├──────────────────────────────────────┤
            │ Email                                │
            │ ┌──────────────────────────────────┐ │
            │ │ name@company.com                 │ │
            │ └──────────────────────────────────┘ │
            │                                      │
            │ Role                                 │
            │ ┌──────────────────────────────────┐ │
            │ │ Viewer                         ▼ │ │
            │ └──────────────────────────────────┘ │
            │ Read-only access to findings &       │
            │ reports.                             │
            │                                      │
            │ Welcome message (optional)           │
            │ ┌──────────────────────────────────┐ │
            │ │                                  │ │
            │ │                                  │ │
            │ └──────────────────────────────────┘ │
            ├──────────────────────────────────────┤
            │            [Cancel]  [Send invite]   │
            └──────────────────────────────────────┘
```

**Success path:** invitation row created in DB (`invitations` table — NEW, see § 8 item I1); email sent via Flask-Mail; modal closes; member list refreshes.

**Error paths:**
- Email already registered (existing user): inline error on the email field "This person is already a team member. Open their detail to change their role." Submit disabled.
- Email already pending invitation: inline warning "An invitation is already pending for this email. <Re-send>?". Submit becomes `[Re-send invitation]` (extends expiry, doesn't duplicate).
- SMTP failure (`app.email_enabled=False`): banner at top of modal "Email backend is not configured. The invitation token has been created but cannot be delivered automatically. Copy the link below and send it manually." with the invitation URL shown for owner-only.
- 403: shouldn't reach here since the button was hidden, but if it does, modal shows "You no longer have permission to invite members." + close.
- Invalid email format (client-side): inline `email` field error "Enter a valid email address." Submit disabled.
- Network error: modal stays open, toast "Failed to send invitation. Retry?", form values preserved.

**Audit log entries written:**
- `action='invitation.created'`, `resource='invite:<token-prefix>'`, `node_meta={'email': <email>, 'role': <role>}`. (Email logged once on creation, never on subsequent reads.)

**Backend endpoints called:**
- `POST /api/iam/invitations` (NEW — § 8 item I2): body `{email, role, message?}`; returns `{id, expires_at}`.

**Edge cases:**
- Inviting an email that matches a previously-disabled user: error "This email belongs to a disabled account. Re-enable the account instead." (We don't allow re-creating a disabled user via invitation; preserves audit history.)
- Sending bulk invites: out of scope for v1; one-at-a-time is the v1 contract.
- Custom role from the dropdown: roles created via Roles tab appear here automatically (no extra UI work).

---

### F4.4 — Accept invitation (recipient experience)

**Trigger:** recipient clicks the invitation link in their email. URL: `https://<host>/invite/<token>`. **NO authentication required** — the token is the auth.

**Steps:**

1. Page loads (standalone route `/invite/<token>`, NOT inside `/team`). Page mounts, fires `GET /api/iam/invitations/<token>` to validate the token.
2. **Valid token, not yet accepted:** show acceptance form.
   - Read-only fields: invited email, organisation, role being assigned, who invited them, optional welcome message.
   - Editable fields: full name (required), password (required, must satisfy current password policy if any — § F4.22).
   - Submit `[Accept invitation & create account]`.
3. On submit: `POST /api/iam/invitations/<token>/accept` with `{name, password}`. Creates User, assigns role, marks invitation accepted, returns JWT.
4. Auto-login: token stored, user redirected to `/?tab=dashboard`. Toast "Welcome to <organisation>".

**Wireframe (centred card, 480px wide):**

```
                    ┌────────────────────────────────┐
                    │                                │
                    │    ┌──────────────────────┐    │
                    │    │     AIPET X          │    │
                    │    └──────────────────────┘    │
                    │                                │
                    │  You've been invited to        │
                    │  Acme Corp on AIPET X.         │
                    │                                │
                    │  Invited by: Jane Smith        │
                    │  Email:      anna@acme.io      │
                    │  Role:       Analyst           │
                    │                                │
                    │  ┌──────────────────────────┐  │
                    │  │ "Welcome to the team!"   │  │
                    │  │              — Jane      │  │
                    │  └──────────────────────────┘  │
                    │                                │
                    │  Full name                     │
                    │  [ ___________________ ]       │
                    │                                │
                    │  Choose password               │
                    │  [ ___________________ ]       │
                    │  • 8+ chars                    │
                    │  • 1 uppercase, 1 number       │
                    │                                │
                    │  [Accept invitation & sign in] │
                    │                                │
                    └────────────────────────────────┘
```

**Success path:** account created; owner role NOT auto-assigned (this is the corner of F2's auto-grant rule — accept-invitation must NOT use F2's auto-grant; see § 7.4). Invitation marked `accepted_at`. Toast on landing.

**Error paths:**
- **Invalid token** (404 from server): page shows full-bleed error "This invitation link is invalid or has been revoked. Contact your administrator." No form. No retry.
- **Expired token** (token row found but `expires_at < NOW()`): same message but specifically "This invitation expired on <date>. Ask <inviter email> to send a new one."
- **Already accepted** (token marked accepted_at): "This invitation has already been used. Sign in below." + login link.
- **Password fails policy** (§ 4.22 enforcement): inline error listing which rules failed; submit disabled until satisfied.
- **Email collision** (a user with that email registered through `/register` between invite-send and accept): collision is detected server-side; server returns 409 "An account already exists for this email. Sign in to claim your invitation." Token remains valid; once they sign in, banner appears in dashboard offering to "Apply <role> from invitation by <inviter>".

**Audit log entries written:**
- `action='invitation.accepted'`, `resource='user:<new-user-id>'`, `node_meta={'invited_by': <inviter_id>, 'role': <role>}`.
- `action='role.assigned'`, `resource='user:<new-user-id>'`, `node_meta={'role': <role>, 'reason': 'invitation-accepted'}` (uses F2's `assign_role_to_user` helper).

**Backend endpoints called:**
- `GET /api/iam/invitations/<token>` (NEW — § 8 item I4 includes a fetch-public sub-route): returns sanitised invitation detail (no sensitive metadata).
- `POST /api/iam/invitations/<token>/accept` (NEW — § 8 item I3).

**Edge cases:**
- The recipient has the AIPET X dashboard open in another tab logged in as a different user when they click: the `/invite/<token>` page is auth-agnostic but the dashboard re-auth confuses; flow handles it by ignoring local JWT on the invite page.
- The invitation token URL is in the recipient's browser history. After accept, the URL responds 410 Gone (consumed). Bookmarking is a non-issue.

---

### F4.5 — Change member role

**Trigger:** Member detail drawer → `[Change roles]` OR Members table row → `…` menu → `Change role`.

**Steps:**

1. `Change Role` modal opens, listing the member's current role(s) with checkboxes for available roles.
2. User checks/unchecks roles.
3. Submit `[Save changes]`.
4. On success: toast "Roles updated", modal closes, member detail drawer refreshes the role pills.

**Wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Change Role for Anna Q           ✕   │
            │ anna@acme.io                          │
            ├──────────────────────────────────────┤
            │ Default roles                        │
            │  [□] Owner    Full platform access   │
            │  [□] Admin    Full security access   │
            │  [●] Analyst  Read, scan, analyse    │
            │  [□] Viewer   Read-only              │
            │                                      │
            │ Custom roles                         │
            │  [□] Compliance auditor              │
            │  [□] Incident responder              │
            ├──────────────────────────────────────┤
            │            [Cancel]  [Save changes]  │
            └──────────────────────────────────────┘
```

**Success path:** for each role checked-and-not-currently-assigned, call `POST /api/iam/users/<id>/roles {"role": ...}`. For each unchecked-and-currently-assigned, call `DELETE /api/iam/users/<id>/roles/<role-name>`. Operations sent in parallel via `Promise.all`. UI shows partial-success on partial-failure.

**Error paths:**
- Trying to remove the last owner role from the last owner: server returns 422 with `{error: "Cannot remove last owner role"}`. UI shows banner in modal "At least one user must have the Owner role." Cancel modal; no changes applied.
- Race: another admin changes the same user concurrently; latest write wins (no optimistic locking in v1). Audit log captures both writes; no data loss.
- Network error mid-batch: each role op is independent; UI shows which succeeded and which failed in a per-row indicator inside the modal; failed ops can be retried individually.

**Audit log entries written:**
- One `role.assigned` row per added role (existing endpoint).
- One `role.revoked` row per removed role (existing endpoint).

**Backend endpoints called:**
- `POST /api/iam/users/<id>/roles` (existing, BACKEND-READY).
- `DELETE /api/iam/users/<id>/roles/<role-name>` (existing, BACKEND-READY).

**Edge cases:**
- Custom roles deleted between modal open and submit: silently dropped from the to-add list; toast "Some custom roles were deleted by another admin and were not assigned."
- User has >5 roles: scroll inside the role list (modal max-height 70 vh).

---

### F4.6 — Disable member

**Trigger:** Member detail drawer → `[Disable]` OR row `…` menu → `Disable`.

**Steps:**

1. Confirmation dialog: "Disable Anna Q?" with copy "They won't be able to sign in. Their data and audit history are preserved. You can re-enable them at any time."
2. `[Cancel]` `[Disable]` (danger variant).
3. On confirm: `POST /api/iam/users/<id>/disable` (NEW — § 8 item F4).
4. Active sessions for this user are revoked server-side (depends on F4.20 infra; see § 8 item S2).
5. Member row updates: `is_active=false`, "Disabled" pill in red, action menu shows `[Re-enable]`.

**Wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Disable Anna Q?                      │
            ├──────────────────────────────────────┤
            │ They won't be able to sign in.       │
            │ Their data and audit history are     │
            │ preserved. You can re-enable them    │
            │ at any time.                         │
            │                                      │
            │ All active sessions will be revoked. │
            ├──────────────────────────────────────┤
            │            [Cancel]   [Disable]      │
            └──────────────────────────────────────┘
```

**Error paths:**
- Last owner attempt: server 422 "Cannot disable the last platform owner."
- Self-disable attempt: server 422 "You cannot disable your own account." (UI hides the button when `target_id == current_user_id`.)

**Audit log entries written:** `action='user.disabled'`, `resource='user:<id>'`, `node_meta={'reason': <optional>, 'sessions_revoked': N}`.

**Backend endpoints called:**
- `POST /api/iam/users/<id>/disable` (NEW — § 8 F4)
- internally: `IssuedToken.revoked_at = NOW()` for all live tokens of this user (S2 dep).

---

### F4.7 — Remove member (soft-delete + session revoke)

**Trigger:** Member detail drawer → `[Remove]`. NOT in the row `…` menu (Remove is a destructive action; require detail-drawer context).

**Steps:**

1. Confirmation dialog with `Type the member's email to confirm` input. Submit disabled until typed correctly. (Pattern: GitHub/Stripe destructive-action.)
2. `[Cancel]` `[Remove member]` (danger).
3. On confirm: `POST /api/iam/users/<id>/remove` (NEW — § 8 item F7).
4. User soft-deleted (`User.deleted_at = NOW()`); all sessions revoked; row vanishes from default Members list.
5. Toast "Anna Q removed."

**Wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Remove Anna Q                        │
            ├──────────────────────────────────────┤
            │ This action removes Anna's access    │
            │ permanently. Audit history and       │
            │ records they created stay intact     │
            │ but are attributed to "(deleted      │
            │ user)".                              │
            │                                      │
            │ Type their email to confirm:         │
            │ [ anna@acme.io                ]      │
            ├──────────────────────────────────────┤
            │            [Cancel]   [Remove]       │
            └──────────────────────────────────────┘
```

**Error paths:**
- Last owner attempt: 422 "Cannot remove the last platform owner."
- Self-remove attempt: 422 "Cannot remove your own account. Ask another owner."
- Email mismatch: client-side, submit disabled until match.
- Session revocation partial failure (rare): user is removed; toast warning "Removed Anna Q. <X> active sessions could not be force-expired and will expire naturally within 15 minutes."

**Audit log entries written:** `action='user.removed'`, `resource='user:<id>'`, `node_meta={'email': <denormalised email for posterity>, 'sessions_revoked': N}`.

**Backend endpoints called:**
- `POST /api/iam/users/<id>/remove` (NEW — § 8 item F7).

**Edge cases:**
- Admin views Members list with `?include_deleted=true`: soft-deleted users appear with "(removed)" pill and `[Restore]` action. Symmetric with AgentDevice soft-delete pattern (CLAUDE.md § Architecture / Soft-delete).

---

### F4.8 — View audit log (filters + pagination)

**Trigger:** Audit tab.

**Steps:**

1. Tab mounts, fires `GET /api/iam/audit?per_page=50&page=1` (current default; filters empty).
2. Filter row above table: Date range (since/until), Action (multi-select), Actor (user search-by-email), Resource (text contains), Status (success/blocked).
3. URL updates with filter params (deep-linkable).
4. Table renders with: Time (relative), Actor, Action (pill), Resource, Status (pill), Detail (`view` link).
5. Pagination footer.

**Wireframe (desktop):**

```
┌─ Team & Access › Audit log ──────────────[⬇ Export CSV]──┐
│ Filters                                                  │
│ Date  [Last 7 days ▼]   Action  [All actions ▼]          │
│ Actor [search by email] Status  [All ▼]                  │
│ Resource [contains...]                              ↻    │
├──────────────────────────────────────────────────────────┤
│ TIME       ACTOR        ACTION            RESOURCE  STAT │
├──────────────────────────────────────────────────────────┤
│ 2 min ago  Binyam Y     role.assigned      user:3   ●OK  │
│ 1 hr ago   PyTest       sso.configured    f2-test… ●OK  │
│ 3 hr ago   System       seed.ran           —       ●OK  │
│ 4 hr ago   Anna Q       login.failed       —       ⊘blk │
│ ...                                                      │
├──────────────────────────────────────────────────────────┤
│ Showing 1-50 of 127.    [<] 1 2 3 [>]    50 per page ▼   │
└──────────────────────────────────────────────────────────┘
```

**Click a row → Audit Event Detail drawer opens** (§ 4.8.1):

```
              ┌──────────────────────────────────┐
              │ Event detail                  ✕  │
              ├──────────────────────────────────┤
              │ Action      role.assigned        │
              │ Actor       Binyam Y (id=1)      │
              │ Resource    user:3               │
              │ Status      success              │
              │ Time        2026-04-28 21:11 UTC │
              │ IP          127.0.0.1            │
              │ User Agent  Mozilla/5.0 (X11; …) │
              │                                  │
              │ Structured detail (node_meta)    │
              │ ┌──────────────────────────────┐ │
              │ │ {                            │ │
              │ │   "role": "owner",           │ │
              │ │   "reason": "auto-on-        │ │
              │ │              registration"   │ │
              │ │ }                            │ │
              │ └──────────────────────────────┘ │
              │                                  │
              │ Related events (same actor)      │
              │  • user.login   2 min ago        │
              │  • role.assigned 1 hr ago        │
              └──────────────────────────────────┘
```

**Success path:** rows render. Filters update URL + refetch + maintain scroll position when paging.

**Error paths:**
- Network error: existing rows stay; toast retry.
- 403 (`audit:read`): tab is gated server-side; if reached, EmptyState "You don't have permission to view audit logs."
- Empty results given filter combo: EmptyState "No audit events match your filters." + `[Clear filters]`.

**Audit log entries written:** none (read-only).

**Backend endpoints called:**
- `GET /api/iam/audit?since=&until=&action=&actor=&resource=&status=&page=&per_page=` (existing endpoint **extended** in § 8 item F5 to accept the filter params).

**Edge cases:**
- Result set > 10 000 rows: server caps `per_page` at 200; page count computed from `total / per_page`.
- Action enum drift: the `action` filter dropdown is populated dynamically from a server-provided list of distinct action strings seen in the table (cached 5 min).
- `node_meta` is `null`: detail drawer shows "No structured detail" instead of an empty `{}`.
- Pre-existing weakness (F2 finding): a row with `timestamp = NULL` would crash the existing handler. Phase B-backend hardens this (§ 8).

---

### F4.9 — Export audit log to CSV

**Trigger:** Audit tab → `[⬇ Export CSV]` button (with current filter set applied).

**Steps:**

1. Click triggers `GET /api/iam/audit/export?<current filter params>`. Browser receives `Content-Type: text/csv; charset=utf-8` with `Content-Disposition: attachment; filename="aipet-audit-2026-04-28.csv"`.
2. CSV columns: timestamp_iso, actor_id, actor_email, action, resource, status, ip_address, user_agent, node_meta (JSON-encoded string).
3. Server streams the response (StreamingResponse pattern) so 100k-row exports don't spike memory.
4. Toast "Audit log export started" on click; "Audit log export complete (N rows)" on response close.

**Error paths:**
- Filter set returns 0 rows: server returns 204 + toast "No rows match — nothing to export."
- Network error mid-stream: browser shows partial download; UI toast "Export interrupted. Try again with a smaller date range."

**Audit log entries written:** `action='audit.exported'`, `resource='audit-log'`, `node_meta={'filter': <serialised filter>, 'rows_exported': N}` (written **after** stream completes, so the count is accurate).

**Backend endpoints called:**
- `GET /api/iam/audit/export?...&format=csv` (NEW — § 8 item F6).

**Edge cases:**
- Browser blocks pop-up if click was synthetic: link uses standard `<a download>` with `target="_self"` to avoid this.
- Mobile Safari "open in iCloud Drive" idiosyncrasy: just works; we test on iOS in click-through (§ 10).

---

### F4.10 — View permissions matrix

**Trigger:** Roles tab → header link `View permission matrix`.

**Steps:**

1. Renders a sticky-header table: rows = permissions (10 + custom), cols = roles (4 default + custom).
2. Cells are read-only filled circles for granted, hollow circles for not granted. Owner column is special-cased: every cell is filled (because owner bypass).

**Wireframe:**

```
┌─ Roles › Permission matrix ──────────────────────────────┐
│  PERMISSION       OWNER  ADMIN  ANALYST  VIEWER  AUDITOR │
├──────────────────────────────────────────────────────────┤
│  scan:create        ●      ●      ●        ○      ○     │
│  scan:read          ●      ●      ●        ●      ●     │
│  findings:read      ●      ●      ●        ●      ●     │
│  reports:read       ●      ●      ●        ●      ●     │
│  reports:create     ●      ●      ●        ○      ○     │
│  billing:manage     ●      ○      ○        ○      ○     │
│  iam:manage         ●      ●      ○        ○      ○     │
│  iam:read           ●      ●      ●        ●      ●     │
│  audit:read         ●      ●      ○        ○      ●     │
│  sso:manage         ●      ○      ○        ○      ○     │
│  policy:manage      ●      ○      ○        ○      ○     │
│  terminal:use       ●      ●      ●        ○      ○     │
└──────────────────────────────────────────────────────────┘
   ●  granted     ○  not granted
   Owner is granted everything by role-name bypass.
```

**Success path:** read-only matrix. To edit, click a role column → opens Edit Role modal (§ 4.12).

**Error paths:** 403 if missing `iam:read`; 401.

**Backend endpoints called:**
- `GET /api/iam/permission-matrix` (NEW — § 8 item H1) returns `{roles: [...], permissions: [...], grants: [{role_id, permission_id}]}`.

**Edge cases:**
- Custom role with 0 permissions: column shows all hollow circles. Distinct visual cue prompts to edit.
- Permission rows scroll horizontally on mobile.

---

### F4.11 — Create custom role

**Trigger:** Roles tab → `[+ Create role]`.

**Steps:**

1. Modal: name (required, lowercase + underscores, regex-validated), description (optional), permission grid (10 default + room for future).
2. Submit `[Create role]`.
3. On success: toast "Role <name> created", role appears in the list + matrix.

**Wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Create custom role               ✕   │
            ├──────────────────────────────────────┤
            │ Name (lowercase, no spaces)          │
            │ [ compliance_auditor          ]      │
            │                                      │
            │ Description (optional)               │
            │ [                              ]     │
            │ [                              ]     │
            │                                      │
            │ Permissions                          │
            │ [□] scan:create     [□] iam:manage   │
            │ [□] scan:read       [□] iam:read     │
            │ [□] findings:read   [●] audit:read   │
            │ [□] reports:read    [□] sso:manage   │
            │ [□] reports:create  [□] policy:manage│
            │ [□] billing:manage  [□] terminal:use │
            ├──────────────────────────────────────┤
            │            [Cancel]   [Create role]  │
            └──────────────────────────────────────┘
```

**Error paths:**
- Name already exists: 409 "A role named '<name>' already exists." Inline error.
- Reserved name (`owner` / `admin` / `analyst` / `viewer`): 422 "Role name is reserved." Inline error.
- Name regex fail: client-side error.

**Audit log entries written:** `action='role.created'`, `resource='role:<name>'`, `node_meta={'permissions': [<list>]}`.

**Backend endpoints called:**
- `POST /api/iam/roles` (existing, BACKEND-READY) — but `permissions` association is **not currently exposed** in this endpoint. **Needs extension** (§ 8 item G1).

---

### F4.12 — Edit custom role permissions

**Trigger:** Roles list → row → `Edit` (only available on custom roles; defaults are locked).

**Steps:**

1. Modal pre-filled with current permissions.
2. User toggles permissions.
3. Submit `[Save changes]`.

**Error paths:**
- Default-role edit attempt: 422 "Default roles cannot be modified." (UI prevents this by hiding the Edit button.)
- Concurrency: optimistic last-write-wins.

**Audit log entries written:** `action='role.permissions_changed'`, `resource='role:<name>'`, `node_meta={'added': [...], 'removed': [...]}`.

**Backend endpoints called:**
- `PATCH /api/iam/roles/<role_id>/permissions` (NEW — § 8 item G1) with `{add: [perm_names], remove: [perm_names]}`.

---

### F4.13 — Delete custom role

**Trigger:** Roles list → row → `Delete` (custom only).

**Steps:**

1. Confirmation dialog: "Delete role 'compliance_auditor'? Users with this role will lose its permissions immediately." `[Cancel]` `[Delete]` (danger).
2. On confirm: `DELETE /api/iam/roles/<role_id>`.

**Error paths:**
- Default-role delete attempt: 422 (UI hides the button).
- Role in use: server returns 200 with `{users_unassigned: N}`; toast "Role deleted. <N> users had this role and were unassigned."

**Audit log entries written:** `action='role.deleted'`, `resource='role:<name>'`, `node_meta={'users_unassigned': N}`.

**Backend endpoints called:**
- `DELETE /api/iam/roles/<role_id>` (NEW — § 8 item G2). Cascades to delete associated UserRole rows.

---

### F4.14 — Configure SSO SAML provider

**Trigger:** SSO tab → `[+ Add SSO provider]`.

**Steps:**

1. Modal: provider type (radio: SAML / OIDC — OIDC disabled in v1 with "v1.1 coming soon" tag), name (required, friendly label), entity ID (SAML metadata URL or upload XML), client_id (OIDC; hidden in SAML), client_secret (encrypted at rest), enabled toggle.
2. Submit `[Save & test]` (primary), `[Save without testing]` (secondary).
3. On `[Save & test]`: server saves config + immediately runs test-connection (§ 4.15) and shows result inline.

**Wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Add SSO provider                 ✕   │
            ├──────────────────────────────────────┤
            │ Provider type                        │
            │  [●] SAML 2.0    [○] OIDC (v1.1)     │
            │                                      │
            │ Name (label users will see)          │
            │ [ Acme Okta                  ]       │
            │                                      │
            │ SAML Metadata URL                    │
            │ [ https://acme.okta.com/app/…  ]     │
            │                                      │
            │ ↑ Or paste metadata XML directly:    │
            │ ┌──────────────────────────────────┐ │
            │ │                                  │ │
            │ │                                  │ │
            │ └──────────────────────────────────┘ │
            │                                      │
            │ [□] Enable for tenant after save     │
            ├──────────────────────────────────────┤
            │            [Cancel]  [Save & test]   │
            └──────────────────────────────────────┘
```

**Success path:** config saved (`SSOProvider` row, with `client_secret` encrypted-at-rest — § 8 item SSO1); test-connection runs; on success the inline test result shows ✓ and `[Enable for tenant]` becomes available.

**Error paths:**
- Metadata URL unreachable: test-connection returns failure with detail "Could not fetch metadata from <URL>: timed out / DNS failed / 404."
- Invalid SAML XML: "Metadata XML is malformed. Check the provider's IdP metadata export."
- Cert validation failure: "Signing certificate failed validation. Verify the IdP's signing certificate is current."

**Audit log entries written:** `action='sso.configured'`, `resource='sso:<provider-id>'`, `node_meta={'name': <name>, 'type': 'saml', 'enabled': <bool>}`. **Never** logs the client_secret.

**Backend endpoints called:**
- `POST /api/iam/sso` (existing, BACKEND-PARTIAL): extended to accept `provider_type`, `client_secret` (§ 8 item SSO1).

---

### F4.15 — Test SSO connection

**Trigger:** Save & test (§ 4.14) OR existing provider row → `Test connection`.

**Steps:**

1. Server fetches the metadata URL, parses XML, validates signing cert, attempts a synthetic AuthnRequest construction (no actual user redirect). Returns diagnostic JSON.
2. UI shows a result dialog with check-mark or error per step.

**Wireframe (test result dialog):**

```
            ┌──────────────────────────────────────┐
            │ Test connection: Acme Okta       ✕   │
            ├──────────────────────────────────────┤
            │ ✓ Metadata fetched (158 ms)          │
            │ ✓ XML parsed                         │
            │ ✓ Signing certificate valid          │
            │   Expires 2027-09-12                 │
            │ ✓ AuthnRequest construction OK       │
            │                                      │
            │ Connection healthy.                  │
            ├──────────────────────────────────────┤
            │                       [Close]        │
            └──────────────────────────────────────┘
```

**Error case wireframe:**

```
            ┌──────────────────────────────────────┐
            │ Test connection: Acme Okta       ✕   │
            ├──────────────────────────────────────┤
            │ ✓ Metadata fetched                   │
            │ ✓ XML parsed                         │
            │ ✗ Signing certificate                │
            │   Cert expired 2026-01-15.           │
            │   Ask the IdP admin to rotate.       │
            │ — AuthnRequest skipped               │
            │                                      │
            │ Connection failed at step 3 of 4.    │
            ├──────────────────────────────────────┤
            │                       [Close]        │
            └──────────────────────────────────────┘
```

**Backend endpoints called:**
- `POST /api/iam/sso/<id>/test` (NEW — § 8 item SSO3).

**Audit log entries written:** `action='sso.tested'`, `resource='sso:<id>'`, `node_meta={'result': 'success'|'failure', 'failure_step': <step>}`.

---

### F4.16 — Enable / disable SSO per tenant

**Trigger:** SSO tab → provider row → toggle in the "Enabled" column.

**Steps:** click toggle → confirm dialog (since this affects login for the entire tenant) → `PATCH /api/iam/sso/<id>` `{enabled: bool}`. Tenant-wide enabled SSO providers appear on the login page (v1.1 — until then, the toggle is informational; it does not yet route users).

**Audit log entries written:** `action='sso.enabled'` / `'sso.disabled'`, `resource='sso:<id>'`.

**Backend endpoints called:**
- `PATCH /api/iam/sso/<id>` (NEW — § 8 item SSO1 covers this in the SSO PATCH/DELETE addition).

---

### F4.17 — Set tenant 2FA enforcement policy

**Trigger:** Security policy tab → 2FA section → policy radio group.

**Steps:**

1. Three radio options: Off (no 2FA), Optional (users can enrol), Required (users must enrol within N days).
2. If Required: input field for grace period (days, default 7).
3. Submit `[Save policy]`.
4. On success: banner appears for affected users on next login: "Your administrator requires 2FA. Enrol within <N> days." (Banner only; enrolment screen ships in v1.1.)

**Wireframe:**

```
┌─ Security policy › Two-factor authentication (2FA) ──────┐
│                                                          │
│  Tenant policy                                           │
│   [○] Off                                                │
│       2FA is not available for users.                    │
│                                                          │
│   [●] Optional                                           │
│       Users can enrol if they want to.                   │
│                                                          │
│   [○] Required                                           │
│       Users must enrol within 7 days of next sign-in.    │
│       Grace period [ 7 ] days                            │
│                                                          │
│  Recovery codes per user [ 10 ]                          │
│                                                          │
│                                  [Save policy]           │
└──────────────────────────────────────────────────────────┘
```

**Audit log entries written:** `action='policy.2fa_changed'`, `resource='tenant'`, `node_meta={'old': <old>, 'new': <new>, 'grace_period_days': N}`.

**Backend endpoints called:**
- `PUT /api/iam/policy/2fa` (NEW — § 8 item P1).

**v1 reality:** banner shown to non-enrolled users when policy is Required. The actual enrolment flow + TOTP secret management ships v1.1 (§ 1.2 deferred items). This is honest — Phase B says so explicitly in the Save banner: "Enrolment is coming in the next release. Until then, this policy will warn users without enforcing block."

---

### F4.18 — View own active sessions

**Trigger:** Sessions tab. Default view: caller's own sessions. Toggle "Show all users' sessions" (admin only).

**Steps:**

1. List rows: device label (browser/OS extracted from User-Agent), IP (with geo lookup if available), issued, last_seen, expires_at, this-session indicator.
2. Each row has `[Revoke]` button (current session shows `(this session)` + `[Sign out]`).

**Wireframe:**

```
┌─ Team & Access › Sessions ────────[Show all users ▼]─────┐
│                                                          │
│  Your active sessions                                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │ DEVICE              IP          ISSUED    EXPIRES… │  │
│  ├────────────────────────────────────────────────────┤  │
│  │ Chrome 121 / macOS  127.0.0.1   2 min ago  in 13m  │  │
│  │  ●This session                          [Sign out] │  │
│  ├────────────────────────────────────────────────────┤  │
│  │ Safari 17 / iOS     1.2.3.4     3 hr ago   in 0m   │  │
│  │                                          [Revoke]  │  │
│  ├────────────────────────────────────────────────────┤  │
│  │ Chrome 119 / Win    81.2.69.4   2 days ago expired │  │
│  │                                              ─     │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  [Revoke all other sessions]                             │
└──────────────────────────────────────────────────────────┘
```

**Backend endpoints called:**
- `GET /api/iam/sessions?user_id=<id>&active=true` (NEW — § 8 item S3).

---

### F4.19 — Revoke a specific session

**Trigger:** session row → `[Revoke]`.

**Steps:** confirm dialog "Revoke this session? The user will be signed out on their next request." → `POST /api/iam/sessions/<jti>/revoke` → row updates to "Revoked just now".

**Audit log entries written:** `action='session.revoked'`, `resource='session:<jti>'`, `node_meta={'target_user_id': <user_id>, 'reason': 'manual'}`.

**Backend endpoints called:**
- `POST /api/iam/sessions/<jti>/revoke` (NEW — § 8 item S3).

---

### F4.20 — Revoke all sessions for a user

**Trigger:** Member detail drawer → `[Sign out all sessions]` (own user) OR `[Revoke all sessions]` (admin viewing another user).

**Steps:** confirm dialog "Revoke all <N> active sessions?" → `POST /api/iam/users/<id>/sessions/revoke_all` → toast "Revoked <N> sessions for <user>."

**Audit log entries written:** `action='session.revoked_all'`, `resource='user:<id>'`, `node_meta={'sessions_revoked': N, 'reason': 'manual'}`.

**Backend endpoints called:**
- `POST /api/iam/users/<id>/sessions/revoke_all` (NEW — § 8 item S3).

---

### F4.21 — Set IP allowlist for tenant

**Trigger:** Security policy tab → IP Allowlist section.

**Steps:**

1. Toggle: "Restrict access to specific IP ranges" (default off).
2. If on: textarea for CIDR list, one per line (e.g. `10.0.0.0/8`, `192.168.1.0/24`, `203.0.113.5/32`). Validation: each line must be a valid CIDR.
3. Optional: "Apply to" — checkboxes for "Dashboard logins" / "API endpoints" / "Both" (default Both).
4. Submit `[Save allowlist]`.
5. **Safety net** before save: server validates the **caller's current IP** matches the new allowlist. If it doesn't, modal "You'd lock yourself out. Add your current IP (1.2.3.4) to the allowlist first." with one-click "Add my IP".

**Wireframe:**

```
┌─ Security policy › IP Allowlist ─────────────────────────┐
│                                                          │
│  [●] Restrict access to specific IP ranges               │
│                                                          │
│  Allowed CIDRs (one per line)                            │
│  ┌──────────────────────────────────────────────────┐    │
│  │ 10.0.0.0/8                                       │    │
│  │ 203.0.113.0/24                                   │    │
│  │                                                  │    │
│  └──────────────────────────────────────────────────┘    │
│  All ranges valid ✓                                      │
│                                                          │
│  Apply to                                                │
│  [☑] Dashboard logins   [☑] API endpoints                │
│                                                          │
│                                          [Save policy]   │
└──────────────────────────────────────────────────────────┘
```

**Audit log entries written:** `action='policy.ip_allowlist_changed'`, `resource='tenant'`, `node_meta={'cidrs_old': [...], 'cidrs_new': [...], 'applies_to': [...]}`.

**Backend endpoints called:**
- `PUT /api/iam/policy/ip_allowlist` (NEW — § 8 item P2).

**Edge cases:**
- Caller is on a non-routable IP (e.g. ::1 in localhost dev): allowlist enforcement skips for IPv6 link-local addresses. Documented as known limitation.
- Allowlist shrinks below the caller's current IP: blocked at the safety-net step above.

---

### F4.22 — Set password policy

**Trigger:** Security policy tab → Password Policy section.

**Steps:**

1. Form: minimum length (slider 8-32, default 12), require uppercase (toggle), require digit (toggle), require special (toggle), max age days (number, default 90 — applies to password rotation), history-prevent-reuse (last N passwords, default 5).
2. Submit `[Save policy]`.

**Wireframe:**

```
┌─ Security policy › Password ─────────────────────────────┐
│                                                          │
│  Minimum length            [────●──── 12]    8 — 32      │
│                                                          │
│  [☑] Require an uppercase letter                         │
│  [☑] Require a digit                                     │
│  [☑] Require a special character                         │
│                                                          │
│  Maximum password age      [ 90 ] days                   │
│  Prevent reuse of last     [  5 ] passwords              │
│                                                          │
│  Effect                                                  │
│   • New users will see these requirements at signup.     │
│   • Existing users will be prompted at next sign-in if   │
│     their current password no longer meets the policy.   │
│                                                          │
│                                          [Save policy]   │
└──────────────────────────────────────────────────────────┘
```

**Audit log entries written:** `action='policy.password_changed'`, `resource='tenant'`, `node_meta={<full policy snapshot>}`.

**Backend endpoints called:**
- `PUT /api/iam/policy/password` (NEW — § 8 item P3).

**Edge cases:**
- Tightening the policy after-the-fact: existing users keep their current password until next change; the new policy applies on **next** password change. The "prompt at next sign-in" copy above is the v1 contract; enforcement-block at sign-in is v1.1 (deferred per § 1.2).

---

## 5. Component inventory

This section lists every React component the build creates or modifies. Components live under `dashboard/frontend/aipet-dashboard/src/components/team_access/` (new directory) unless noted otherwise.

### 5.1 New shared primitives (used across Team & Access AND new modules going forward)

These live under `src/components/ui/` (new directory). They become the canonical AIPET X UI primitives — Polish Pass 1 will migrate other modules to them over time.

| Name | Path | Props | State | Children | Consumes API | Loading/Empty/Error |
|---|---|---|---|---|---|---|
| `Card` | `ui/Card.jsx` | `{ children, padding?, hover?, onClick?, className? }` | none | any | no | no |
| `Button` | `ui/Button.jsx` | `{ variant: "primary" \| "secondary" \| "danger", size?, loading?, disabled?, onClick, children, leadingIcon?, trailingIcon? }` | none | inline | no | shows spinner replacing icon when `loading=true` |
| `IconButton` | `ui/IconButton.jsx` | `{ icon, label (a11y), variant?, size?, onClick }` | none | none | no | no |
| `Modal` | `ui/Modal.jsx` | `{ open, onClose, title, children, primaryAction?, secondaryAction?, closeOnScrim?, size? }` | none | header / body / footer | no | renders via Portal; focus trap; ESC to close |
| `Drawer` | `ui/Drawer.jsx` | `{ open, onClose, side?, width?, children, title? }` | none | header / body | no | mobile fullscreen sheet, desktop side-slide |
| `Table` | `ui/Table.jsx` | `{ columns, rows, loading?, error?, emptyState?, onRowClick?, sortBy?, onSortChange?, mobileCardKey? }` | sort/scroll | row cells | no | skeleton when `loading`, EmptyState when 0 rows, error banner |
| `EmptyState` | `ui/EmptyState.jsx` | `{ icon, title, description, action? }` | none | none | no | no |
| `Toast` | `ui/Toast.jsx` (refactor) | `{ message, level, onDismiss }` | timer | none | no | self-dismissing |
| `Toggle` | `ui/Toggle.jsx` | `{ checked, onChange, disabled?, label?, description? }` | none | none | no | no |
| `Pill` | `ui/Pill.jsx` | `{ label, variant: "neutral" \| "info" \| "success" \| "warning" \| "danger", size? }` | none | none | no | no |
| `Avatar` | `ui/Avatar.jsx` | `{ name, email?, size?, src? }` | none | none | no | renders initials if no `src` |
| `Spinner` | `ui/Spinner.jsx` | `{ size? }` | none | none | no | no |
| `RelativeTime` | `ui/RelativeTime.jsx` | `{ datetime, threshold? }` | re-renders every 60s | none | no | no |
| `CodeBlock` | `ui/CodeBlock.jsx` | `{ code, language?, copyable? }` | copy state | none | no | no — used for node_meta JSON view |
| `ConfirmDialog` | `ui/ConfirmDialog.jsx` | `{ open, title, message, confirmLabel, confirmVariant?, requireTypedConfirmation?, onConfirm, onCancel }` | typed-text state | none | no | confirm-button disabled until typed match if `requireTypedConfirmation` |
| `useApi` (hook) | `hooks/useApi.js` | `(method, path, options) => {data, loading, error, refetch, mutate}` | internal | n/a | yes | wraps axios + AbortController + token from context |
| `ToastContext` | `contexts/ToastContext.jsx` | `<ToastProvider>` + `useToast()` | toast queue | Toast | no | replaces prop-drilling |

**Decision:** `useApi` and `ToastContext` are introduced now (Phase C) because every Team & Access page uses them. Existing pages keep using prop-drilled `showToast` until Polish Pass 1 picks them up.

### 5.2 Team & Access page components

All under `src/components/team_access/`.

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `TeamAccessPage` | `TeamAccessPage.jsx` | `{ token }` | activeTab | `Tabs` + tab content | no (children fetch) |
| `TeamAccessTabs` | `TeamAccessTabs.jsx` | `{ active, onChange, visibleTabs }` | none | tab buttons | no |

#### 5.2.1 Members tab (F4.1, F4.2, F4.3, F4.5, F4.6, F4.7)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `MembersTab` | `members/MembersTab.jsx` | `{ token }` | search, page, sort, drawerMember, modalState | `MembersToolbar`, `MembersTable`, `MemberDetailDrawer`, `InviteMemberModal`, `ChangeRoleModal`, `ConfirmDialog` (×2 disable/remove) | yes — `useApi('GET','/api/iam/users')` |
| `MembersToolbar` | `members/MembersToolbar.jsx` | `{ search, onSearch, statusFilter, onStatusFilter, onInvite }` | none | inputs | no |
| `MembersTable` | `members/MembersTable.jsx` | `{ rows, loading, error, onRowClick, onAction, sortBy, onSort, mobile }` | none | `Table` + per-row `MemberRowActions` | no |
| `MemberRowActions` | `members/MemberRowActions.jsx` | `{ member, onAction }` | menu open | `IconButton` + dropdown items | no |
| `MemberDetailDrawer` | `members/MemberDetailDrawer.jsx` | `{ member, open, onClose, onAction }` | sub-data (sessions count, audit) | `Drawer` body w/ sections | yes — sessions + audit fetches |
| `InviteMemberModal` | `members/InviteMemberModal.jsx` | `{ open, onClose, onInvited }` | form fields, submitting | `Modal`, role dropdown | yes — `POST /api/iam/invitations` |
| `ChangeRoleModal` | `members/ChangeRoleModal.jsx` | `{ member, open, onClose, onSaved }` | role checkbox state | `Modal`, role list | yes — POST/DELETE role assignments |

#### 5.2.2 Roles tab (F4.10, F4.11, F4.12, F4.13)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `RolesTab` | `roles/RolesTab.jsx` | `{ token }` | view (list / matrix), modalState | `RolesList`, `PermissionMatrix`, `CreateRoleModal`, `EditRoleModal`, `ConfirmDialog` (delete) | yes — `GET /api/iam/roles`, `GET /api/iam/permission-matrix` |
| `RolesList` | `roles/RolesList.jsx` | `{ roles, onSelect, onCreate, onEdit, onDelete }` | none | `Table` | no |
| `PermissionMatrix` | `roles/PermissionMatrix.jsx` | `{ roles, permissions, grants }` | none | grid cells | no |
| `CreateRoleModal` | `roles/CreateRoleModal.jsx` | `{ open, onClose, onCreated }` | name, description, permission set | `Modal`, name input, permission grid | yes — `POST /api/iam/roles` (extended for permissions) |
| `EditRoleModal` | `roles/EditRoleModal.jsx` | `{ role, open, onClose, onSaved }` | permission diff | `Modal` | yes — `PATCH /api/iam/roles/<id>/permissions` |

#### 5.2.3 Audit tab (F4.8, F4.9)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `AuditTab` | `audit/AuditTab.jsx` | `{ token }` | filters, page, perPage, drawerEvent | `AuditFilters`, `AuditTable`, `AuditEventDrawer`, export trigger | yes — `GET /api/iam/audit` |
| `AuditFilters` | `audit/AuditFilters.jsx` | `{ filters, onChange, onClear }` | local input state | date range, action multi-select, actor input, status select | yes — `GET /api/iam/audit/actions` (distinct list) |
| `AuditTable` | `audit/AuditTable.jsx` | `{ rows, loading, onRowClick }` | none | `Table` | no |
| `AuditEventDrawer` | `audit/AuditEventDrawer.jsx` | `{ event, open, onClose }` | none | `Drawer` body, `CodeBlock` for node_meta | yes — fetches related events |
| `ExportCsvButton` | `audit/ExportCsvButton.jsx` | `{ filters }` | downloading | `Button` | yes — triggers `GET /api/iam/audit/export?format=csv` |

#### 5.2.4 Sessions tab (F4.18, F4.19, F4.20)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `SessionsTab` | `sessions/SessionsTab.jsx` | `{ token }` | viewSelf vs all, drawerSession | `SessionsList`, `RevokeSessionDialog` | yes — `GET /api/iam/sessions` |
| `SessionsList` | `sessions/SessionsList.jsx` | `{ sessions, onRevoke, onRevokeAll }` | none | `Table` w/ device extraction | no |
| `RevokeSessionDialog` | `sessions/RevokeSessionDialog.jsx` | `{ session, open, onClose, onRevoked }` | none | `ConfirmDialog` | yes — `POST /api/iam/sessions/<jti>/revoke` |

#### 5.2.5 SSO tab (F4.14, F4.15, F4.16)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `SsoTab` | `sso/SsoTab.jsx` | `{ token }` | providers, modalState | `SsoProvidersList`, `ConfigureSsoModal`, `TestConnectionDialog` | yes — `GET /api/iam/sso` |
| `SsoProvidersList` | `sso/SsoProvidersList.jsx` | `{ providers, onEdit, onTest, onToggleEnabled }` | none | `Table` | no |
| `ConfigureSsoModal` | `sso/ConfigureSsoModal.jsx` | `{ provider?, open, onClose, onSaved }` | form | `Modal`, type radio, fields | yes — `POST/PATCH /api/iam/sso` |
| `TestConnectionDialog` | `sso/TestConnectionDialog.jsx` | `{ providerId, open, onClose, result }` | none | `Modal`, step list | yes — `POST /api/iam/sso/<id>/test` |

#### 5.2.6 Security policy tab (F4.17, F4.21, F4.22)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `PolicyTab` | `policy/PolicyTab.jsx` | `{ token }` | sub-section | `TwoFactorPolicy`, `IpAllowlistPolicy`, `PasswordPolicyPanel` | yes — `GET /api/iam/policy` |
| `TwoFactorPolicy` | `policy/TwoFactorPolicy.jsx` | `{ value, onSave }` | form state | `Card`, radio | yes — `PUT /api/iam/policy/2fa` |
| `IpAllowlistPolicy` | `policy/IpAllowlistPolicy.jsx` | `{ value, onSave }` | textarea, validation | `Card`, textarea, lock-out warning | yes — `PUT /api/iam/policy/ip_allowlist` |
| `PasswordPolicyPanel` | `policy/PasswordPolicyPanel.jsx` | `{ value, onSave }` | form state | `Card`, slider, toggles | yes — `PUT /api/iam/policy/password` |

### 5.3 Standalone pages (NOT inside `/team`)

| Name | Path | Props | State | Children | Consumes API |
|---|---|---|---|---|---|
| `AcceptInvitePage` | `pages/AcceptInvitePage.jsx` | `{ token (URL param) }` | loaded invitation, form | `Card`, form, password validator | yes — `GET /api/iam/invitations/<token>`, `POST /api/iam/invitations/<token>/accept` |

### 5.4 Component count summary

- Shared primitives: **15** (incl. 1 hook + 1 context)
- Team & Access page components: **22**
- Standalone page components: **1**
- **Total new components: 38**

Plus refactor of `Toast` (existing) into the new primitive. Plus the existing App.js routing block currently commented out (lines 30423-30430) gets replaced with the new `TeamAccessPage` import + route.


---

## 6. Data contracts

This section is the contract between Phase C-I frontend code and the backend. Every endpoint the UI calls is specified here with: method + path, auth requirement, request schema, response schema, every error case with example bodies, and Phase A status (BACKEND-READY / PARTIAL / MISSING). Items marked PARTIAL or MISSING become the input to § 8.

**Conventions:**
- All endpoints prefix with the running base URL (currently `http://localhost:5001` in dev).
- All authenticated endpoints require `Authorization: Bearer <jwt>` unless noted.
- All POST/PUT/PATCH bodies are `Content-Type: application/json`.
- Error response shape is consistent: `{"error": "<short-code>", "message": "<human readable>", "fields": {<optional per-field errors>}, "required": "<for 403, the missing permission>"}`. (The shape varies slightly across existing endpoints — Phase B-backend normalises new endpoints to this shape and deliberately leaves existing endpoints alone unless touched for another reason.)

### 6.1 Members

#### 6.1.1 `GET /api/iam/users` — list members

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F3**.

**Auth:** JWT + permission `iam:read` (NEW permission, see § 8).

**Query params:**
- `search` (string, optional) — case-insensitive substring match on `email`, `name`.
- `page` (int, default 1)
- `per_page` (int, default 25, max 100)
- `sort` (string, default `email_asc`) — one of `email_asc | email_desc | last_login_desc | last_login_asc | created_at_desc`.
- `status` (string, default `all`) — `all | active | disabled | pending`.
- `include_roles` (bool, default true) — when true, joins UserRole+Role and embeds role names per user.
- `include_deleted` (bool, default false) — owner-only; surfaces soft-deleted users (consistent with AgentDevice soft-delete pattern).

**200 response:**
```json
{
  "members": [
    {
      "id": 1,
      "email": "byallew@gmail.com",
      "name": "Binyam Yallew",
      "plan": "free",
      "organisation": null,
      "industry": null,
      "created_at": "2026-04-26T20:07:45.657973Z",
      "last_login": "2026-04-28T21:09:03.000000Z",
      "is_active": true,
      "deleted_at": null,
      "roles": [{ "id": "<uuid>", "name": "owner" }],
      "active_session_count": 1
    }
  ],
  "total": 2,
  "pages": 1,
  "page": 1
}
```

**Error responses:**
- `401` — missing/expired JWT (existing axios interceptor handles).
- `403` — `{"error":"insufficient_permissions","required":"iam:read"}`.

**Side effects:** none.

#### 6.1.2 `GET /api/iam/users/<id>` — member detail

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F3**.

**Auth:** JWT + (`iam:read` OR caller-is-target-user). Caller can always view their own detail.

**200 response:**
```json
{
  "id": 1,
  "email": "byallew@gmail.com",
  "name": "Binyam Yallew",
  "plan": "free",
  "organisation": null,
  "industry": null,
  "created_at": "2026-04-26T20:07:45.657973Z",
  "last_login": "2026-04-28T21:09:03Z",
  "is_active": true,
  "deleted_at": null,
  "roles": [{ "id": "<uuid>", "name": "owner", "assigned_by": 1, "assigned_at": "2026-04-28T21:06:16Z" }],
  "active_sessions": 1,
  "recent_audit": [
    { "id":"<uuid>","action":"role.assigned","timestamp":"2026-04-28T20:10:55Z","status":"success" }
  ]
}
```

**Error responses:** 401, 403, 404 (`{"error":"user_not_found"}`).

#### 6.1.3 `POST /api/iam/users/<id>/disable` — disable a user

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F4**.

**Auth:** `iam:manage`.

**Request body:** `{"reason": "<optional free-text>"}`.

**Side effects:**
1. `User.is_active = False`.
2. All `IssuedToken` rows for this user where `revoked_at IS NULL` and `expires_at > NOW()` get `revoked_at = NOW()` and `revoked_reason = "user_disabled"`. (Depends on § 8 item S1 IssuedToken model.)
3. AuditLog row: `action='user.disabled'`, `resource='user:<id>'`, `node_meta={"reason":<text>,"sessions_revoked":N}`.

**200 response:** `{"message":"User disabled","sessions_revoked": <N>}`.

**Error responses:**
- `403` — `iam:manage` missing.
- `409` — `{"error":"already_disabled"}`.
- `422` — `{"error":"last_owner","message":"Cannot disable the last platform owner."}`.
- `422` — `{"error":"self_action","message":"Cannot disable your own account."}`.

#### 6.1.4 `POST /api/iam/users/<id>/enable` — re-enable a disabled user

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F4** (companion to disable).

**Auth:** `iam:manage`.

**200 response:** `{"message":"User re-enabled"}`. Sets `is_active=true`. Does NOT auto-restore prior sessions (those stay revoked).

**Audit:** `action='user.enabled'`, `node_meta={"reason":<optional>}`.

#### 6.1.5 `POST /api/iam/users/<id>/remove` — soft-delete a user

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F7** (depends on S1 + S2 from § 8).

**Auth:** `iam:manage`.

**Request body:** `{"reason": "<optional>"}`. (Soft-delete; not destructive — symmetric with `AgentDevice.soft_delete`.)

**Side effects:**
1. `User.deleted_at = NOW()`.
2. `User.is_active = False`.
3. All active sessions revoked (same logic as disable).
4. AuditLog: `action='user.removed'`, `resource='user:<id>'`, `node_meta={"reason":<text>,"email":<denormalised>,"sessions_revoked":N}`.

**200 response:** `{"message":"User removed","sessions_revoked": <N>}`.

**Error responses:** as disable, plus `404` for already-removed.

**Note on terminology:** "Remove" in the UI = soft-delete in the model. We do not expose a hard-delete in v1.

#### 6.1.6 `POST /api/iam/users/<id>/restore` — restore a soft-deleted user

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F7** (companion).

**Auth:** `iam:manage` + `include_deleted=true` was used to find the user.

**200 response:** `{"message":"User restored"}`.

**Audit:** `action='user.restored'`, `node_meta={"previously_deleted_at":<iso>}`.

### 6.2 Roles & permissions

#### 6.2.1 `GET /api/iam/roles` — existing, list roles

**Phase A status:** BACKEND-READY.

(Already specified in Phase A § 1.1. No changes.)

#### 6.2.2 `POST /api/iam/roles` — create role + permissions

**Phase A status:** BACKEND-PARTIAL. Phase B-backend item **G1** (extends to accept `permissions` list).

**Auth:** `iam:manage`.

**Request body:**
```json
{
  "name": "compliance_auditor",
  "description": "Read-only across audit log + reports",
  "permissions": ["audit:read", "findings:read", "reports:read", "iam:read"]
}
```

**201 response:** `{"id":"<uuid>","message":"Role created"}`.

**Error responses:**
- `400` — name missing or fails regex `^[a-z][a-z0-9_]{2,49}$`.
- `409` — name already exists.
- `422` — name is reserved (`owner|admin|analyst|viewer`).
- `422` — one or more permissions in the `permissions` list don't exist.

**Audit:** `action='role.created'`, `resource='role:<name>'`, `node_meta={"permissions":[<list>]}`.

#### 6.2.3 `PATCH /api/iam/roles/<id>/permissions` — add/remove permissions

**Phase A status:** BACKEND-MISSING. Phase B-backend item **G1**.

**Auth:** `iam:manage`.

**Request body:** `{"add": ["scan:read"], "remove": ["billing:manage"]}`.

**200 response:** `{"role":{...with updated permissions...}}`.

**Error responses:**
- `404` — role not found.
- `422` — `{"error":"default_role_locked","message":"Default roles cannot be modified."}` if target is owner/admin/analyst/viewer.
- `422` — unknown permission name.

**Audit:** `action='role.permissions_changed'`, `node_meta={"added":[...],"removed":[...]}`.

#### 6.2.4 `DELETE /api/iam/roles/<id>` — delete custom role

**Phase A status:** BACKEND-MISSING. Phase B-backend item **G2**.

**Auth:** `iam:manage`.

**Side effects:** Deletes the role; cascades to delete all UserRole rows referencing it.

**200 response:** `{"message":"Role deleted","users_unassigned": <N>}`.

**Error responses:**
- `422` — `{"error":"default_role_locked"}`.
- `404`.

**Audit:** `action='role.deleted'`, `resource='role:<name>'`, `node_meta={"users_unassigned":N}`.

#### 6.2.5 `GET /api/iam/permission-matrix` — full role × permission grid

**Phase A status:** BACKEND-MISSING. Phase B-backend item **H1** (formerly v1.1; promoted to v1 because it's the canonical view of "what can each role do").

**Auth:** `iam:read`.

**200 response:**
```json
{
  "roles": [
    { "id": "<uuid>", "name": "owner",   "is_default": true,  "owner_bypass": true },
    { "id": "<uuid>", "name": "admin",   "is_default": true,  "owner_bypass": false },
    ...
  ],
  "permissions": [
    { "name": "scan:create",   "resource": "scan",   "action": "create", "description": "..." },
    ...
  ],
  "grants": [
    { "role_id": "<owner-uuid>",   "permission_name": "scan:create" },
    ...
  ]
}
```

**Note:** the `owner_bypass` field surfaces the special-case in `iam/routes.py:53` so the UI can render the owner column with all-filled circles regardless of explicit grants.

#### 6.2.6 Existing `/users/<user_id>/roles` endpoints

**Phase A status:** BACKEND-READY (already verified in F2 closure as 200/201/200).

Re-listed for completeness:
- `GET /api/iam/users/<user_id>/roles` — list roles for a user.
- `POST /api/iam/users/<user_id>/roles` — assign role to user (`{"role":"<name>"}`).
- `DELETE /api/iam/users/<user_id>/roles/<role_name>` — revoke role.

**Hardening note (Phase B-backend item F8):** the GET endpoint currently has no permission gate (just `@jwt_required`); any authenticated user can view any other user's role list. Phase B-backend adds `iam:read` gating. Backward-compatible: existing callers (only the dashboard frontend) are admin/owner so will pass the gate.

### 6.3 Invitations

#### 6.3.1 `POST /api/iam/invitations` — send invitation

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I2**.

**Auth:** `iam:manage`.

**Request body:**
```json
{
  "email": "anna@acme.io",
  "role": "analyst",
  "message": "Welcome to the team!"
}
```

**Validation:**
- email valid format + lowercase
- email not already in `users` table → 409 `{"error":"email_exists"}`
- email not already in pending `invitations` → 409 with `{"error":"already_pending","invitation_id":"<id>"}` so UI can offer re-send
- role exists → 422 if not

**Side effects:**
1. INSERT into `invitations` table (NEW; Phase B-backend item **I1**).
2. Generates 64-char URL-safe token.
3. Sends email via Flask-Mail (PLB-4 wiring) with link to `https://<host>/invite/<token>`.
4. AuditLog: `action='invitation.created'`, `resource='invite:<token-prefix>'`, `node_meta={"email":<email>,"role":<role>}`.

**201 response:**
```json
{
  "id": "<uuid>",
  "email": "anna@acme.io",
  "role": "analyst",
  "expires_at": "2026-05-05T20:11:00Z",
  "delivery_status": "sent" | "smtp_disabled"
}
```

**Special case:** when `app.email_enabled=False`, INSERT proceeds, `delivery_status="smtp_disabled"`, response **also** includes `"manual_link":"https://<host>/invite/<token>"` (owner-only — gated server-side) so an owner can copy it manually. UI shows a banner per F4.3.

#### 6.3.2 `GET /api/iam/invitations/<token>` — fetch invitation (PUBLIC)

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I4**.

**Auth:** none. Token is the auth.

**200 response (sanitised):**
```json
{
  "email": "anna@acme.io",
  "role": "analyst",
  "role_description": "Read, scan, and analyse — no admin settings",
  "invited_by_name": "Binyam Yallew",
  "organisation": "Acme Corp",
  "message": "Welcome to the team!",
  "expires_at": "2026-05-05T20:11:00Z"
}
```

**Note:** does NOT expose `invited_by` user ID, the actual `created_at`, or any sensitive metadata. The recipient sees only what's needed to accept.

**Error responses:**
- `404` — `{"error":"invalid_token"}`.
- `410` — `{"error":"expired"}`.
- `410` — `{"error":"already_accepted"}`.

#### 6.3.3 `POST /api/iam/invitations/<token>/accept` — accept invitation

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I3**.

**Auth:** none. Token is the auth.

**Request body:** `{"name": "Anna Q", "password": "..."}`.

**Validation:**
- token valid + not expired + not already accepted (via the same paths as 6.3.2)
- password meets current tenant password policy (§ 4.22; v1 enforces only the 8-char minimum until 4.22's policy is set)
- email collision: if another user registered with this email between invite and accept, return 409 `{"error":"email_collision_signin"}`.

**Side effects:**
1. INSERT new User with the invited email; `is_active=True`; password bcrypt-hashed.
2. Mark invitation `accepted_at = NOW()`.
3. Use `assign_role_to_user(user.id, <invited_role>, assigned_by=<inviter_id>, reason='invitation-accepted')` — F2's helper. **Critically, this bypasses F2's auto-on-registration `owner` grant** (see § 7.4 for why).
4. Issue JWT.
5. AuditLogs: `invitation.accepted` + `role.assigned`.

**201 response:**
```json
{
  "message": "Welcome to AIPET X",
  "token": "<jwt>",
  "user": { ... User.to_dict() ... }
}
```

**Error responses:** 404/410 as above; 409 for email_collision_signin; 422 for password policy violation with field-level detail.

#### 6.3.4 `GET /api/iam/invitations` — list pending invitations

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I4**.

**Auth:** `iam:manage`.

**Query params:** `status` (default `pending`; options `pending|accepted|expired|all`), `page`, `per_page`.

**200 response:**
```json
{
  "invitations": [
    { "id":"<uuid>", "email":"anna@acme.io", "role":"analyst",
      "invited_by":1, "created_at":"...","expires_at":"...",
      "accepted_at":null }
  ],
  "total":1, "page":1, "pages":1
}
```

#### 6.3.5 `DELETE /api/iam/invitations/<id>` — revoke pending

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I4**.

**Auth:** `iam:manage`.

**Side effects:** mark invitation `revoked_at = NOW()`. Token cannot be used afterwards (acceptance returns 404).

**Audit:** `action='invitation.revoked'`.

#### 6.3.6 `POST /api/iam/invitations/<id>/resend` — re-send + extend expiry

**Phase A status:** BACKEND-MISSING. Phase B-backend item **I4**.

**Auth:** `iam:manage`.

**Side effects:** extends `expires_at` by 7 days; re-sends the same email.

**Audit:** `action='invitation.resent'`.

### 6.4 Audit log

#### 6.4.1 `GET /api/iam/audit` — paginated audit (filters added)

**Phase A status:** BACKEND-PARTIAL. Phase B-backend item **F5** (extends with filters) + **F8** (NULL timestamp hardening).

**Auth:** `audit:read`.

**Query params (all optional):**
- `since` (ISO8601 datetime)
- `until` (ISO8601 datetime)
- `action` (string; comma-separated for multi-select; matches exactly)
- `actor` (int user_id; or string email — server resolves)
- `resource` (string contains)
- `status` (success|blocked|error)
- `page` (default 1)
- `per_page` (default 50, max 200)

**200 response:**
```json
{
  "logs": [
    {
      "id":"<uuid>","user_id":1,"actor_email":"byallew@gmail.com",
      "actor_name":"Binyam Yallew","action":"role.assigned",
      "resource":"user:3","ip_address":"127.0.0.1",
      "timestamp":"2026-04-28T20:10:55Z","status":"success",
      "node_meta":{"role":"owner","reason":"auto-on-registration"}
    }
  ],
  "total":13,"pages":1,"page":1
}
```

**Important changes from existing endpoint:**
1. Response now includes `node_meta` (existing endpoint omits it).
2. Response now includes `actor_email` and `actor_name` (joined from users table; null when actor was deleted).
3. Filter params are added (existing ignores them).
4. Handler null-coalesces `timestamp.isoformat() if timestamp else null` — fixes the F2-discovered weakness.

#### 6.4.2 `GET /api/iam/audit/actions` — distinct action list (for filter dropdown)

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F5**.

**Auth:** `audit:read`.

**200 response:** `{"actions":["role.assigned","role.revoked","sso.configured","user.disabled",...]}` (deduped, sorted, cached server-side 5 min).

#### 6.4.3 `GET /api/iam/audit/export` — CSV export (streaming)

**Phase A status:** BACKEND-MISSING. Phase B-backend item **F6**.

**Auth:** `audit:read`.

**Query params:** same as 6.4.1.

**Response headers:**
```
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="aipet-audit-2026-04-28.csv"
Transfer-Encoding: chunked
```

**Response body (streamed):**
```
timestamp_iso,actor_id,actor_email,action,resource,status,ip_address,user_agent,node_meta_json
2026-04-28T20:10:55Z,1,byallew@gmail.com,role.assigned,user:3,success,127.0.0.1,Mozilla/5.0...,"{\"role\":\"owner\",\"reason\":\"auto-on-registration\"}"
...
```

**204 response** when 0 rows match (with no body and `Content-Disposition` omitted).

**Audit:** `action='audit.exported'`, written **after** the stream closes, with `node_meta={"filter":<serialised>,"rows_exported":N}`. (Written post-stream so the count is accurate.)

### 6.5 Sessions (depends on IssuedToken model — § 8 item S1)

#### 6.5.1 `GET /api/iam/sessions` — list sessions

**Phase A status:** BACKEND-MISSING. Phase B-backend item **S3**.

**Auth:** JWT. Default scope: caller's own sessions. Param `user_id=<id>` requires `iam:manage` (cross-user). Param `all_users=true` requires `iam:manage`.

**Query params:** `user_id`, `all_users`, `active=true|false|all` (default `active`), `page`, `per_page`.

**200 response:**
```json
{
  "sessions": [
    {
      "jti": "<jwt-id>",
      "user_id": 2,
      "user_email": "test@aipet.io",
      "ip_address": "127.0.0.1",
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64)...",
      "device_label": "Chrome 121 / Linux",
      "issued_at": "2026-04-28T21:09:03Z",
      "last_seen_at": "2026-04-28T21:11:20Z",
      "expires_at": "2026-04-28T21:24:03Z",
      "revoked_at": null,
      "is_current": true
    }
  ],
  "total": 1, "pages": 1, "page": 1
}
```

**Note:** `device_label` is server-derived from `user_agent` (simple regex parse; `ua-parser-js` not used to avoid dependency creep — Phase B-backend includes a 60-line parser).

#### 6.5.2 `POST /api/iam/sessions/<jti>/revoke` — revoke single session

**Phase A status:** BACKEND-MISSING. Phase B-backend item **S3**.

**Auth:** caller is the session owner OR `iam:manage`.

**200 response:** `{"message":"Session revoked"}`.

**Audit:** `action='session.revoked'`, `resource='session:<jti>'`, `node_meta={"target_user_id":<id>,"reason":"manual"}`.

#### 6.5.3 `POST /api/iam/users/<id>/sessions/revoke_all` — bulk revoke

**Phase A status:** BACKEND-MISSING. Phase B-backend item **S3**.

**Auth:** caller is the user OR `iam:manage`.

**Request body:** `{"except_current": true|false}` — when self-revoking and `true`, current session stays alive; UI default for "Sign out all other sessions" button.

**200 response:** `{"sessions_revoked": <N>}`.

**Audit:** `action='session.revoked_all'`, `node_meta={"sessions_revoked":N,"except_current":<bool>}`.

### 6.6 SSO

#### 6.6.1 `GET /api/iam/sso` — list providers

**Phase A status:** BACKEND-PARTIAL (existing endpoint omits provider_type and never returns secrets). Phase B-backend item **SSO1** extends.

**Auth:** `sso:manage`.

**200 response:**
```json
{
  "providers": [
    {
      "id":"<uuid>","name":"Acme Okta","provider_type":"saml",
      "tenant_id":"<idp-tenant>","metadata_url":"https://...",
      "enabled":false,"created_at":"...",
      "last_test_at":"...","last_test_status":"success" | "failure" | null,
      "last_test_failure_step": null
    }
  ]
}
```

**Note:** `client_id` and `client_secret` are NEVER in the response. Only the existence is implied by `provider_type`.

#### 6.6.2 `POST /api/iam/sso` — create provider

**Phase A status:** BACKEND-PARTIAL. Phase B-backend item **SSO1** (provider_type, encrypted secret).

**Auth:** `sso:manage`.

**Request body:**
```json
{
  "name": "Acme Okta",
  "provider_type": "saml",
  "metadata_url": "https://acme.okta.com/app/.../sso/saml/metadata",
  "metadata_xml": null,
  "client_id": null,
  "client_secret": null,
  "enabled": false
}
```

(For OIDC v1.1 the client_id and client_secret become required and metadata_xml stays null.)

**Validation:**
- `name` required + length ≤ 50
- `provider_type` in `["saml","oidc"]` (only "saml" accepted in v1)
- exactly one of `metadata_url` or `metadata_xml` provided for SAML
- `client_secret` if provided: encrypted at rest using app-level secret (env var `IAM_SECRET_KEY`)

**201 response:** `{"id":"<uuid>","message":"SSO provider created"}`.

**Audit:** `action='sso.configured'`, `resource='sso:<id>'`, `node_meta={"name":<name>,"type":"saml","enabled":<bool>}`. **Never** logs client_secret or metadata XML body.

#### 6.6.3 `PATCH /api/iam/sso/<id>` — update provider

**Phase A status:** BACKEND-MISSING. Phase B-backend item **SSO1**.

**Auth:** `sso:manage`.

**Request body:** any subset of the create fields. `enabled` toggle is the most common case.

**Audit:** `action='sso.updated'` or `'sso.enabled'`/`'sso.disabled'` (when only `enabled` changes), `node_meta={"changed_fields":[...]}` (without sensitive values).

#### 6.6.4 `DELETE /api/iam/sso/<id>` — delete provider

**Phase A status:** BACKEND-MISSING. Phase B-backend item **SSO1**.

**Auth:** `sso:manage`.

**Audit:** `action='sso.deleted'`.

#### 6.6.5 `POST /api/iam/sso/<id>/test` — test connection

**Phase A status:** BACKEND-MISSING. Phase B-backend item **SSO3**.

**Auth:** `sso:manage`.

**Side effects:** server fetches metadata_url, parses XML, validates signing cert, attempts AuthnRequest construction (no actual user redirect). Persists `last_test_at` + `last_test_status` + `last_test_failure_step` on the provider row.

**200 response:**
```json
{
  "result": "success" | "failure",
  "steps": [
    { "name":"metadata_fetch","status":"ok","detail":"158 ms","duration_ms":158 },
    { "name":"xml_parse","status":"ok" },
    { "name":"signing_cert","status":"failure","detail":"Expired 2026-01-15" },
    { "name":"authn_construction","status":"skipped" }
  ],
  "failure_step": "signing_cert"
}
```

**Audit:** `action='sso.tested'`, `node_meta={"result":<result>,"failure_step":<step or null>}`.

### 6.7 Security policy

The policy endpoints back the Security Policy tab (F4.17, F4.21, F4.22). All read from / write to a single `tenant_policy` row (Phase B-backend item **P0** — a one-row config table; multi-tenancy migration scopes this per-tenant, see § 7).

#### 6.7.1 `GET /api/iam/policy` — read full policy

**Phase A status:** BACKEND-MISSING. Phase B-backend item **P0**.

**Auth:** `policy:read` (NEW permission, granted to all four default roles by Phase B-backend seed extension).

**200 response:**
```json
{
  "two_factor": {
    "mode":"optional" | "off" | "required",
    "grace_period_days":7,
    "recovery_codes_per_user":10
  },
  "ip_allowlist": {
    "enabled":false,
    "cidrs":[],
    "applies_to":["dashboard_login","api_endpoints"]
  },
  "password": {
    "min_length":12,
    "require_uppercase":true,
    "require_digit":true,
    "require_special":true,
    "max_age_days":90,
    "history_prevent_reuse":5
  },
  "updated_at":"...","updated_by":1
}
```

#### 6.7.2 `PUT /api/iam/policy/2fa` / `PUT /api/iam/policy/ip_allowlist` / `PUT /api/iam/policy/password`

**Phase A status:** BACKEND-MISSING. Phase B-backend items **P1**, **P2**, **P3**.

**Auth:** `policy:manage`.

**Side effects:**
- Update fields in `tenant_policy` row.
- AuditLog: `action='policy.<area>_changed'`, `node_meta` includes `old` and `new` snapshots.
- For IP allowlist: server validates **caller's current IP** is still allowed; returns 422 if not, with `current_ip` echo so UI can offer one-click "Add my IP".

**200 response:** `{"message":"Policy updated"}`.

**Error responses (IP allowlist specifically):**
- `422` — `{"error":"would_lock_out","current_ip":"1.2.3.4","message":"The new allowlist would block your current IP."}`.

### 6.8 Existing IAM endpoints (BACKEND-READY, no changes)

For completeness:

- `GET /api/iam/roles` ✅
- `GET /api/iam/audit` (gets extended in § 6.4.1, but the existing 200 path is BACKEND-READY)
- `GET /api/iam/sso` (gets extended; existing 200 path is BACKEND-READY)
- `POST /api/iam/users/<id>/roles` ✅ (verified 201 in F2)
- `DELETE /api/iam/users/<id>/roles/<role_name>` ✅ (verified 200 in F2)

### 6.9 Endpoints summary

| Endpoint | Phase A status | Phase B-backend item | Phase that needs it |
|---|---|---|---|
| `GET /api/iam/users` | MISSING | F3 | C |
| `GET /api/iam/users/<id>` | MISSING | F3 | C |
| `POST /api/iam/users/<id>/disable` | MISSING | F4 | E |
| `POST /api/iam/users/<id>/enable` | MISSING | F4 | E |
| `POST /api/iam/users/<id>/remove` | MISSING | F7 | E |
| `POST /api/iam/users/<id>/restore` | MISSING | F7 | E |
| `POST /api/iam/users/<id>/sessions/revoke_all` | MISSING | S3 | E |
| `GET /api/iam/users/<id>/roles` | READY (gating) | F8 | C |
| `POST /api/iam/users/<id>/roles` | READY | — | C |
| `DELETE /api/iam/users/<id>/roles/<r>` | READY | — | C |
| `GET /api/iam/roles` | READY | — | C |
| `POST /api/iam/roles` | PARTIAL | G1 | G |
| `PATCH /api/iam/roles/<id>/permissions` | MISSING | G1 | G |
| `DELETE /api/iam/roles/<id>` | MISSING | G2 | G |
| `GET /api/iam/permission-matrix` | MISSING | H1 | G |
| `POST /api/iam/invitations` | MISSING | I2 | D |
| `GET /api/iam/invitations` | MISSING | I4 | D |
| `GET /api/iam/invitations/<token>` (PUBLIC) | MISSING | I4 | D |
| `POST /api/iam/invitations/<token>/accept` | MISSING | I3 | D |
| `DELETE /api/iam/invitations/<id>` | MISSING | I4 | D |
| `POST /api/iam/invitations/<id>/resend` | MISSING | I4 | D |
| `GET /api/iam/audit` | PARTIAL | F5 + F8 | F |
| `GET /api/iam/audit/actions` | MISSING | F5 | F |
| `GET /api/iam/audit/export` | MISSING | F6 | F |
| `GET /api/iam/sessions` | MISSING | S3 | E |
| `POST /api/iam/sessions/<jti>/revoke` | MISSING | S3 | E |
| `GET /api/iam/sso` | PARTIAL | SSO1 | H |
| `POST /api/iam/sso` | PARTIAL | SSO1 | H |
| `PATCH /api/iam/sso/<id>` | MISSING | SSO1 | H |
| `DELETE /api/iam/sso/<id>` | MISSING | SSO1 | H |
| `POST /api/iam/sso/<id>/test` | MISSING | SSO3 | H |
| `GET /api/iam/policy` | MISSING | P0 | I |
| `PUT /api/iam/policy/2fa` | MISSING | P1 | I |
| `PUT /api/iam/policy/ip_allowlist` | MISSING | P2 | I |
| `PUT /api/iam/policy/password` | MISSING | P3 | I |

**Total: 36 endpoints. 5 BACKEND-READY, 5 BACKEND-PARTIAL, 26 BACKEND-MISSING.**

---

## 7. Multi-tenancy migration path

v1 ships single-tenant honestly (current data model). This section is the documented migration path the multi-tenancy work follows once it's prioritised. Every component, query, and flow specified above has explicit multi-tenant notes here.

### 7.1 Per-table changes

| Table | New column(s) | Index | Default | Migration strategy |
|---|---|---|---|---|
| `tenants` (NEW) | id (uuid PK), name, slug (unique), created_at, owner_user_id | (slug) | n/a | Bootstrap with one tenant `default`; assign all existing User+Role rows to it. |
| `users` | tenant_id (uuid FK NOT NULL) | (tenant_id, email unique) | `default` tenant uuid | UPDATE existing rows in migration; tighten NOT NULL after backfill. |
| `roles` | tenant_id (uuid FK NULL ALLOWED for default roles) | (tenant_id, name unique) | NULL for owner/admin/analyst/viewer (system roles); per-tenant for custom | System roles stay tenant_id=NULL; custom roles get a tenant_id. |
| `user_roles` | (no new columns; transitively scoped via users + roles tenant_ids) | (user_id, role_id) unique | n/a | No migration; integrity is the join's responsibility. |
| `permissions` | (no change — permissions are global) | n/a | n/a | n/a |
| `audit_log` | tenant_id (uuid FK) | (tenant_id, timestamp DESC) | derived from user_id at insert | Backfill via JOIN on users; tighten NOT NULL post-backfill. |
| `sso_providers` | tenant_id (uuid FK NOT NULL) | (tenant_id) | `default` | Migration UPDATE; NOT NULL. |
| `invitations` (NEW from § 6.3.1) | tenant_id from creation; no migration needed | (tenant_id, status) | n/a | Born tenant-scoped. |
| `issued_tokens` (NEW from § 8 S1) | tenant_id from creation | (tenant_id, jti) | n/a | Born tenant-scoped. |
| `tenant_policy` | tenant_id is the PK (one row per tenant) | n/a | n/a | INSERT one default row per tenant on tenant creation. |

### 7.2 Per-query changes

Every IAM query gets a `WHERE tenant_id = <caller's tenant>` clause. The `require_permission` decorator gets a companion `@require_tenant_scope` decorator that:

1. Reads `caller.tenant_id` from the User row.
2. Sets `g.tenant_id` for the request lifetime.
3. Adds an automatic filter to all SQLAlchemy queries via a session-level event listener (similar to soft-delete's `Query.filter()` pattern).

**Performance note:** the (tenant_id, *) composite indexes above are essential — without them, a multi-tenant audit log gets slow above ~100k rows.

### 7.3 Per-flow changes for multi-tenant

| Flow | What changes |
|---|---|
| F4.1 List members | Query scoped to `users.tenant_id = caller.tenant_id`. `?all_tenants=true` requires a new `platform_admin` role (super-admin across tenants); not exposed to customers in v1.1+. |
| F4.2 Member detail | Same — scoped. |
| F4.3 Invite member | Invitation row gets `tenant_id = caller.tenant_id`. Recipient's resulting User gets the same tenant_id. |
| F4.4 Accept invitation | New User created in invitation's tenant. |
| F4.5 Change role | Role lookup scoped to `(tenant_id IS NULL OR tenant_id = caller.tenant)`. Default roles (system) are global. Custom roles are per-tenant. |
| F4.6 / F4.7 Disable / Remove | Scoped lookup. Cannot disable/remove cross-tenant. |
| F4.8 Audit log | Scoped to `audit_log.tenant_id = caller.tenant_id`. Cross-tenant audit visibility is `platform_admin` only. |
| F4.9 CSV export | Same — scoped. |
| F4.10 Permission matrix | Default roles always shown; custom roles only those in caller's tenant. |
| F4.11/12/13 Custom role CRUD | Tenant-scoped; cannot affect default roles or other tenants' custom roles. |
| F4.14 Configure SSO | Tenant-scoped; one tenant's SSO has zero impact on others. |
| F4.15/16 Test / enable SSO | Tenant-scoped. |
| F4.17 2FA policy | Tenant-scoped (one `tenant_policy` row per tenant). |
| F4.18 / F4.19 / F4.20 Sessions | Tenant-scoped via user_id transitively. |
| F4.21 IP allowlist | Tenant-scoped. Important: enforcement at the `before_request` hook reads policy by the caller's tenant_id (which it derives from the JWT `sub` → User → tenant_id, before the request even reaches the route — pre-auth tenant resolution is the trickier piece). |
| F4.22 Password policy | Tenant-scoped — different tenants can have different policies. The accept-invitation flow reads the policy by invitation's tenant_id. |

### 7.4 First-user-of-fresh-tenant gets owner; others default lower

This is **the key behavioural change** that lands with multi-tenancy. F2's current rule is "every new register gets owner" — works for single-tenant. Multi-tenant rule:

- **Tenant creation flow** (Phase B-multi-tenant): a new tenant is created when:
  - A user signs up via `/register` with no invitation → creates a fresh tenant + assigns owner (current F2 behaviour, refactored).
  - A user accepts an invitation → joins the inviter's tenant + gets the invited role (NOT owner). **This is why F4.4 explicitly bypasses F2's auto-grant.**
  - (Future: an admin creates a sub-tenant from the parent tenant — out of scope.)
- The seed catalog (F1) is global; runs once at app start; not per-tenant.
- The `tenant_policy` row is created with defaults at tenant-creation time.

### 7.5 Cross-tenant access (admins viewing other tenants' data)

Out of scope for the user-facing UI. Internal `platform_admin` role would use a separate admin console (not part of Team & Access). The audit log captures every cross-tenant access for accountability.

### 7.6 Estimated effort for multi-tenancy migration

| Item | Hours | Confidence |
|---|---|---|
| Schema migration: tenants table + tenant_id columns + indexes + Alembic revision | 2 | high |
| Backfill SQL: assign all existing rows to a `default` tenant | 1 | high |
| `@require_tenant_scope` decorator + SQLAlchemy session event listener | 2 | medium |
| Refactor every IAM endpoint to consult `g.tenant_id` | 3 | medium |
| Refactor F2 register flow: tenant creation + first-user-owner; invitation flow: join-existing-tenant | 2 | high |
| `tenant_policy` table + per-tenant policy load + IP allowlist `before_request` hook | 2 | medium |
| Tests: 30+ new tests covering tenant isolation; ~3 days for ~30 tests but parallelisable | 4 | medium |
| Click-through verification: full Team & Access flow with two tenants | 2 | medium |

**Total: ~16 hours ±6, medium confidence.** Roughly 2 backend-engineer-days.

**Critical sequencing note:** multi-tenancy migration MUST land before the first paying multi-customer deploy. v1 (single-tenant) is fine for a solo dev account or a single-customer staging environment; it leaks data across tenants if multiple customers share an instance.

---

## 8. Backend additions required (Phase B-backend)

This is the build-readiness gate for Phase C-I. Every backend addition needed before Phase C can begin a UI flow is listed here. Estimates given as `<hours> ±<range>, <confidence>`.

### 8.1 Foundational (must ship before Phase C starts)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **F0** | Extend `seed_default_roles()` to add 2 new permissions (`iam:read`, `policy:read`, `policy:manage`) and grant them appropriately to defaults. Idempotent extension of F1's seed. | 0.5 ±0.2, high | none | C, all |
| **F3** | `GET /api/iam/users` (list, with search/sort/pagination) + `GET /api/iam/users/<id>` (detail with joined roles + active_session_count). Permission `iam:read`. | 3 ±1, high | none | C |
| **F5** | Extend `GET /api/iam/audit` with filter query params (since/until/action/actor/resource/status). Add `GET /api/iam/audit/actions` (distinct list, cached). Include `node_meta`, `actor_email`, `actor_name` in response. | 2 ±0.5, high | none | F |
| **F6** | `GET /api/iam/audit/export?format=csv` streaming response. | 1.5 ±0.5, high | none | F |
| **F8** | Permission gate on `GET /api/iam/users/<id>/roles` (currently jwt-only). Null-coalesce on `audit_log.timestamp` in `get_audit_log` handler (F2-discovered weakness) AND add DB-level default `DEFAULT NOW()` to the timestamp column via Alembic. | 1 ±0.3, high | yes (Alembic) | C, F |
| **G1** | Extend `POST /api/iam/roles` to accept `permissions` list. Add `PATCH /api/iam/roles/<id>/permissions`. Validate permissions exist; default-role lock; reserved-name check. | 2 ±0.5, high | none | G |
| **G2** | `DELETE /api/iam/roles/<id>` with cascade-unassign. Default-role lock. | 1 ±0.3, high | none | G |
| **H1** | `GET /api/iam/permission-matrix` returning roles × permissions with grants list. | 1 ±0.3, high | none | G |

**Foundational subtotal: ~12 hours ±3, high confidence.** This is the minimum backend work before Phase C-I can run.

### 8.2 Members lifecycle (Phase E)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **F4** | `POST /api/iam/users/<id>/disable` + `POST /api/iam/users/<id>/enable`. Last-owner-safety + self-action protections. Triggers session revocation (depends on S2). | 1.5 ±0.5, medium | none (uses existing `is_active`) | E |
| **F7** | `POST /api/iam/users/<id>/remove` + `POST /api/iam/users/<id>/restore`. User soft-delete (new `deleted_at` column, mirrors AgentDevice pattern). Last-owner safety. | 2 ±0.5, medium | yes (Alembic: User.deleted_at) | E |

**Members lifecycle subtotal: ~3.5 hours ±1, medium confidence.** Depends on S* for full session-revoke behaviour.

### 8.3 Sessions / token blocklist (Phase E prerequisite)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **S1** | `IssuedToken` model: jti, user_id, ip, user_agent, issued_at, last_seen_at, expires_at, revoked_at, revoked_reason. Hook into JWT issuance (login + register + reset-password + accept-invitation). | 2 ±0.5, medium | yes (new table) | E, F4, F7 |
| **S2** | `flask_jwt_extended.token_in_blocklist_loader` consulting `IssuedToken.revoked_at IS NOT NULL`. Hook into `@jwt_required` so revoked tokens 401. | 1 ±0.3, medium | none | E, F4, F7 |
| **S3** | `GET /api/iam/sessions` + `POST /api/iam/sessions/<jti>/revoke` + `POST /api/iam/users/<id>/sessions/revoke_all`. Includes a 60-line user-agent parser (no new dependency). | 2.5 ±0.5, medium | none | E |

**Sessions subtotal: ~5.5 hours ±1.3, medium confidence.** S1+S2 land first; S3 depends on them.

### 8.4 Invitations (Phase D)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **I1** | `Invitation` model: id, email, role_name, token (unique, 64 chars), invited_by, message, created_at, expires_at, accepted_at, revoked_at. Alembic migration. | 1 ±0.3, high | yes | D |
| **I2** | `POST /api/iam/invitations` — generate token, INSERT, send email via Flask-Mail. Handle `app.email_enabled=False` per F4.3 spec. | 1.5 ±0.5, medium | none | D |
| **I3** | `POST /api/iam/invitations/<token>/accept` — atomic User creation + role assignment via F2's `assign_role_to_user` helper, bypassing F2's auto-grant. Email collision handling. | 2 ±0.5, medium | none | D |
| **I4** | `GET /api/iam/invitations` (list pending) + `GET /api/iam/invitations/<token>` (PUBLIC fetch) + `DELETE /api/iam/invitations/<id>` (revoke) + `POST /api/iam/invitations/<id>/resend`. | 2 ±0.5, medium | none | D |

**Invitations subtotal: ~6.5 hours ±1.8, medium confidence.**

### 8.5 SSO (Phase H)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **SSO1** | Extend `SSOProvider` model with `provider_type` (enum), `client_secret` (encrypted at rest using app-level `IAM_SECRET_KEY` env var), `last_test_at`, `last_test_status`, `last_test_failure_step`. Add `PATCH /api/iam/sso/<id>` and `DELETE /api/iam/sso/<id>` endpoints. Extend POST/GET to handle the new fields without leaking secrets. | 3 ±1, medium | yes (Alembic, with at-rest encryption helper) | H |
| **SSO3** | `POST /api/iam/sso/<id>/test` — fetch metadata URL, parse XML (use `defusedxml` to be safe), validate signing cert (`cryptography`), construct AuthnRequest stub, return diagnostic JSON. ~120-line implementation. | 4 ±2, low | none (consumes secret env var) | H |

**SSO subtotal: ~7 hours ±3, medium confidence.** Note SSO1 and SSO3 depend on `cryptography` dependency (already in requirements via bcrypt's transitive, but check). `defusedxml` would be a new dep — small.

### 8.6 Security policy (Phase I)

| ID | Addition | Hours | Schema | Blocks |
|---|---|---|---|---|
| **P0** | `tenant_policy` model: single-row table in v1 (one row scoped per-tenant in v1.1). Fields per § 6.7.1. Default row inserted at app boot (idempotent) by extending the seed function. `GET /api/iam/policy`. | 2 ±0.5, medium | yes (new table) | I |
| **P1** | `PUT /api/iam/policy/2fa` — write 2FA mode + grace_period_days. Optionally trigger banner-on-next-login for affected users (banner display is frontend; backend just stores). | 1 ±0.3, medium | none | I |
| **P2** | `PUT /api/iam/policy/ip_allowlist` — CIDR validation + caller-IP-still-included safety net + `before_request` hook to enforce on subsequent requests. | 2.5 ±1, low | none (uses P0 row) | I |
| **P3** | `PUT /api/iam/policy/password` — store policy. Apply to register / reset-password / accept-invitation handlers (3 call sites). | 2 ±0.5, medium | none | I |

**Policy subtotal: ~7.5 hours ±2.3, medium-low confidence.** P2 has the most uncertainty — IP allowlist enforcement order-of-operations interacts with rate limiting and Sentry, and the lockout safety net needs careful testing.

### 8.7 Aggregate Phase B-backend totals

| Subgroup | Hours | Confidence |
|---|---|---|
| Foundational (F0/F3/F5/F6/F8/G1/G2/H1) | 12 ±3 | high |
| Members lifecycle (F4/F7) | 3.5 ±1 | medium |
| Sessions (S1/S2/S3) | 5.5 ±1.3 | medium |
| Invitations (I1-I4) | 6.5 ±1.8 | medium |
| SSO (SSO1/SSO3) | 7 ±3 | medium-low |
| Policy (P0-P3) | 7.5 ±2.3 | medium-low |
| **Total Phase B-backend** | **42 hours ±13, medium confidence** | |

**Plus 30-50 % testing overhead** (tests written alongside each item) → **~55-65 hours total backend work** before all Phase C-I UI work can begin.

**However**, the foundational subgroup (12 hours) is enough to start Phase C. The other subgroups gate later phases: Phase D blocks on invitations (I1-I4), Phase E blocks on sessions (S1-S3) + members lifecycle (F4/F7), etc.

### 8.8 Phase B-backend critical path

The fastest path to "everything green" with maximum parallelism:

```
Week 1
  Mon: F0, F3 (members list+detail), F5 (audit filters), F6 (audit CSV)
  Tue: F8 (gating + null hardening), G1+G2 (role CRUD), H1 (matrix)
       -> Phase C unblocked, Phase F unblocked, Phase G unblocked

Week 2
  Wed: I1 (Invitation model), I2 (send invitation)
  Thu: I3 (accept), I4 (list/revoke/resend)
       -> Phase D unblocked

  Fri: S1 (IssuedToken model), S2 (blocklist hook)
       -> Foundation for sessions

Week 3
  Mon: S3 (sessions endpoints), F4 (disable/enable), F7 (remove/restore)
       -> Phase E unblocked

  Tue: SSO1 (provider model + CRUD)
  Wed: SSO3 (test connection)
       -> Phase H unblocked

  Thu: P0 (tenant_policy + GET), P1 (2fa PUT), P3 (password PUT)
  Fri: P2 (IP allowlist + before_request hook)
       -> Phase I unblocked
```

**~3 calendar weeks** of focused backend work to fully unblock Phase C-I. **~1 day** to unblock just Phase C.

