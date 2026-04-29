import React, { useState } from "react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../design/tokens";
import Spinner from "./Spinner";

// Variants and sizes are positional in the visual hierarchy:
//   primary   = high-emphasis, accent-filled (one per card)
//   secondary = outlined, neutral; the default for most actions
//   ghost     = no border, used inline (drawer headers, table)
//   danger    = destructive (Remove member, Revoke key)
const VARIANTS = {
  primary: {
    fg: "#0b1620",
    bg: COLORS.accent,
    bd: COLORS.accent,
    hoverBg: "#5cc4ff",
    hoverBd: "#5cc4ff",
  },
  secondary: {
    fg: COLORS.text,
    bg: "transparent",
    bd: COLORS.border,
    hoverBg: COLORS.bgRaised,
    hoverBd: COLORS.borderHover,
  },
  ghost: {
    fg: COLORS.textMuted,
    bg: "transparent",
    bd: "transparent",
    hoverBg: COLORS.bgRaised,
    hoverBd: "transparent",
  },
  danger: {
    fg: "#fff",
    bg: COLORS.danger,
    bd: COLORS.danger,
    hoverBg: "#ff6666",
    hoverBd: "#ff6666",
  },
};

const SIZES = {
  sm: { px: SPACE.lg, py: SPACE.sm,  fs: TYPO.sizeSm,   minH: 30 },
  md: { px: SPACE.xl, py: SPACE.md,  fs: TYPO.sizeBase, minH: 36 },
  lg: { px: SPACE.xxl, py: SPACE.lg, fs: TYPO.sizeMd,   minH: 44 },
};

export default function Button({
  children,
  onClick,
  variant = "secondary",
  size = "md",
  disabled = false,
  loading = false,
  leadingIcon,
  trailingIcon,
  type = "button",
  fullWidth = false,
  style,
  ...rest
}) {
  const [hover, setHover] = useState(false);
  const v = VARIANTS[variant] ?? VARIANTS.secondary;
  const s = SIZES[size] ?? SIZES.md;
  const isDisabled = disabled || loading;

  return (
    <button
      type={type}
      disabled={isDisabled}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onClick={isDisabled ? undefined : onClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: SPACE.md,
        background: hover && !isDisabled ? v.hoverBg : v.bg,
        color: v.fg,
        border: `1px solid ${hover && !isDisabled ? v.hoverBd : v.bd}`,
        borderRadius: RADIUS.md,
        padding: `${s.py}px ${s.px}px`,
        fontSize: s.fs,
        fontWeight: TYPO.weightMedium,
        fontFamily: TYPO.family,
        letterSpacing: TYPO.trackTight,
        minHeight: s.minH,
        width: fullWidth ? "100%" : undefined,
        cursor: isDisabled ? "not-allowed" : "pointer",
        opacity: isDisabled ? 0.55 : 1,
        transition: MOTION.base,
        outline: "none",
        ...style,
      }}
      {...rest}
    >
      {loading ? <Spinner size="sm" color={v.fg} /> : leadingIcon}
      {children}
      {!loading && trailingIcon}
    </button>
  );
}
