import React from "react";
import { COLORS, TYPO, RADIUS } from "../design/tokens";

const SIZES = { xs: 20, sm: 28, md: 36, lg: 48, xl: 64 };

// Deterministic colour from the input string -- same name always
// gets the same accent hue. 360-degree wheel, dialled to 60%
// saturation / 28% lightness so the bg never fights with the
// glyph or the surrounding card.
function _hueFor(text) {
  if (!text) return 210;
  let h = 0;
  for (let i = 0; i < text.length; i += 1) {
    h = (h * 31 + text.charCodeAt(i)) % 360;
  }
  return h;
}

function _initialsFor(name, email) {
  const src = (name || email || "?").trim();
  if (!src) return "?";
  const words = src.split(/\s+/).filter(Boolean);
  if (words.length === 1) {
    return src.slice(0, 2).toUpperCase();
  }
  return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}

export default function Avatar({ name, email, size = "md", style }) {
  const px = typeof size === "number" ? size : (SIZES[size] ?? SIZES.md);
  const initials = _initialsFor(name, email);
  const hue = _hueFor(email || name || "?");
  const fontSize = Math.max(10, Math.floor(px * 0.42));
  return (
    <span
      aria-label={name || email || "user avatar"}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: px,
        height: px,
        borderRadius: RADIUS.pill,
        background: `hsl(${hue}, 60%, 28%)`,
        color: COLORS.text,
        fontFamily: TYPO.family,
        fontSize,
        fontWeight: TYPO.weightSemi,
        letterSpacing: TYPO.trackTight,
        userSelect: "none",
        flex: "none",
        ...style,
      }}
    >
      {initials}
    </span>
  );
}
