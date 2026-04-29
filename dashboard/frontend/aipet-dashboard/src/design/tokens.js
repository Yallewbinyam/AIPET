// ===============================================================
// AIPET X — design tokens (Phase B § 2)
//
// Single source of truth for colour, typography, spacing, radius,
// motion. Existing components use inline `style={{...}}` with
// per-file C constants; new primitives consume these tokens
// instead so the look stays coherent across new pages and existing
// pages can converge gradually.
//
// Imported by every primitive in src/ui/. Do NOT inline these
// values elsewhere -- the only escape hatch is tweaking a token
// here so the change is global.
// ===============================================================

// ── Colour palette ────────────────────────────────────────────
// Built from the existing `C = { text, muted, card, border }`
// pattern that pages like RiskScoreTable already use, extended
// with status colours and an accent for primary action surfaces.
export const COLORS = {
  text:        "#e6edf3",
  textMuted:   "#7d8590",
  textSubtle:  "#48515a",
  bgDeep:      "#080c10",
  bgCard:      "#0d1117",
  bgRaised:    "#161b22",
  border:      "#21262d",
  borderHover: "#30363d",

  accent:        "#3fb6ff",   // primary actions, links, focus rings
  accentSoft:    "#1f6feb33", // accent at ~20% opacity for hover wash
  accentBorder:  "#3fb6ff80",

  success:     "#00ff88",
  successSoft: "#00ff8822",
  warn:        "#f5c518",
  warnSoft:    "#f5c51822",
  danger:      "#ff4444",
  dangerSoft:  "#ff444422",
  info:        "#3fb6ff",
  infoSoft:    "#3fb6ff22",
};

// ── Typography ────────────────────────────────────────────────
// Tighter letter-spacing on display text, slightly compressed
// rhythm. Existing components use 11/12/13 for body; these tokens
// keep that floor and add display sizes.
export const TYPO = {
  family:        "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  familyMono:    "'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace",
  sizeXs:        11,
  sizeSm:        12,
  sizeBase:      13,
  sizeMd:        14,
  sizeLg:        16,
  sizeXl:        20,
  sizeH2:        24,
  sizeH1:        30,
  weightNormal:  400,
  weightMedium:  500,
  weightSemi:    600,
  weightBold:    700,
  trackTight:    "-0.01em",
  trackNormal:   "0",
  trackWide:     "0.04em",
  leadingTight:  1.25,
  leadingNormal: 1.45,
};

// ── Spacing (px) ──────────────────────────────────────────────
// Base unit 4. Keeps to a small palette so layouts stay rhythmic.
export const SPACE = {
  xxs: 2,
  xs:  4,
  sm:  6,
  md:  8,
  lg:  12,
  xl:  16,
  xxl: 20,
  xxxl: 24,
  huge: 32,
  giga: 48,
};

// ── Radius ────────────────────────────────────────────────────
export const RADIUS = {
  sm:   4,
  md:   6,
  lg:   8,
  xl:   12,
  pill: 999,
};

// ── Motion ────────────────────────────────────────────────────
// 200ms is the Phase B § 2 target. Ease-out for entrances,
// ease-in-out for state toggles.
export const MOTION = {
  fast:    "120ms cubic-bezier(0.4, 0, 0.2, 1)",
  base:    "200ms cubic-bezier(0.4, 0, 0.2, 1)",
  slow:    "320ms cubic-bezier(0.4, 0, 0.2, 1)",
  easeOut: "cubic-bezier(0.16, 1, 0.3, 1)",
};

// ── Z-index scale ─────────────────────────────────────────────
export const Z = {
  base:    0,
  raised:  1,
  sticky:  10,
  drawer:  100,
  modal:   1000,
  toast:   2000,
};

// ── Shadows ───────────────────────────────────────────────────
export const SHADOW = {
  card:    "0 1px 2px rgba(0,0,0,0.3)",
  raised:  "0 4px 12px rgba(0,0,0,0.4)",
  overlay: "0 16px 48px rgba(0,0,0,0.6)",
};

// Convenience export: the single C constant existing components
// expect. New code should import COLORS directly; this is just to
// ease migration if anyone copy-pastes from a legacy component.
export const C = {
  text:   COLORS.text,
  muted:  COLORS.textMuted,
  card:   COLORS.bgCard,
  border: COLORS.border,
};
