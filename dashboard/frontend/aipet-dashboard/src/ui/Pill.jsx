import React from "react";
import { COLORS, TYPO, RADIUS, SPACE } from "../design/tokens";

// Status pill / role badge. `tone` selects a colour pair; pass
// raw hex via `color`/`background` to override.
const TONES = {
  neutral: { fg: COLORS.textMuted, bg: COLORS.bgRaised, bd: COLORS.border },
  accent:  { fg: COLORS.accent,    bg: COLORS.accentSoft, bd: COLORS.accentBorder },
  success: { fg: COLORS.success,   bg: COLORS.successSoft, bd: COLORS.success },
  warn:    { fg: COLORS.warn,      bg: COLORS.warnSoft,    bd: COLORS.warn },
  danger:  { fg: COLORS.danger,    bg: COLORS.dangerSoft,  bd: COLORS.danger },
  info:    { fg: COLORS.info,      bg: COLORS.infoSoft,    bd: COLORS.info },
};

export default function Pill({
  children, tone = "neutral",
  color, background, borderColor,
  size = "sm",
  style,
  ...rest
}) {
  const t = TONES[tone] ?? TONES.neutral;
  const fg = color ?? t.fg;
  const bg = background ?? t.bg;
  const bd = borderColor ?? t.bd;
  const fontSize = size === "xs" ? TYPO.sizeXs : size === "md" ? TYPO.sizeSm : TYPO.sizeXs;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: SPACE.xs,
        color: fg,
        background: bg,
        border: `1px solid ${bd}`,
        borderRadius: RADIUS.pill,
        padding: `${SPACE.xxs}px ${SPACE.md}px`,
        fontSize,
        fontWeight: TYPO.weightSemi,
        letterSpacing: TYPO.trackWide,
        textTransform: "uppercase",
        whiteSpace: "nowrap",
        lineHeight: 1.4,
        ...style,
      }}
      {...rest}
    >
      {children}
    </span>
  );
}
