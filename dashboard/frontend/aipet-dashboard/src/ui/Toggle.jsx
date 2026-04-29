import React from "react";
import { COLORS, TYPO, SPACE, MOTION } from "../design/tokens";

// Switch-style binary toggle. Standalone control; the consumer
// handles state. The visible label (when given) is part of the
// hit target so a11y stays clean.
export default function Toggle({
  checked = false,
  onChange,
  disabled = false,
  label,
  ariaLabel,
  size = "md",
  style,
}) {
  const trackW = size === "sm" ? 32 : 40;
  const trackH = size === "sm" ? 18 : 22;
  const knob   = trackH - 4;

  const handle = () => { if (!disabled && onChange) onChange(!checked); };

  return (
    <label
      onClick={handle}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: SPACE.md,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        userSelect: "none",
        ...style,
      }}
    >
      <span
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel || label || "toggle"}
        style={{
          position: "relative",
          width: trackW,
          height: trackH,
          background: checked ? COLORS.accent : COLORS.bgRaised,
          border: `1px solid ${checked ? COLORS.accent : COLORS.border}`,
          borderRadius: 999,
          transition: MOTION.base,
          flex: "none",
        }}
      >
        <span
          style={{
            position: "absolute",
            top: 1,
            left: checked ? trackW - knob - 3 : 1,
            width: knob,
            height: knob,
            borderRadius: "50%",
            background: checked ? "#0b1620" : COLORS.text,
            transition: `left ${MOTION.base}, background ${MOTION.base}`,
          }}
        />
      </span>
      {label && (
        <span style={{ color: COLORS.text, fontSize: TYPO.sizeSm }}>
          {label}
        </span>
      )}
    </label>
  );
}
