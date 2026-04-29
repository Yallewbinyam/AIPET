import React from "react";
import { COLORS, MOTION } from "../design/tokens";

const SIZES = { xs: 12, sm: 16, md: 20, lg: 28, xl: 40 };

// CSS keyframe injected once per page load. Avoids needing a
// global stylesheet -- existing AIPET X components don't ship one.
let _styleInjected = false;
function _ensureKeyframes() {
  if (_styleInjected || typeof document === "undefined") return;
  const style = document.createElement("style");
  style.setAttribute("data-aipet-ui", "spinner");
  style.textContent = `@keyframes aipet-spin { to { transform: rotate(360deg); } }`;
  document.head.appendChild(style);
  _styleInjected = true;
}

export default function Spinner({ size = "md", color = COLORS.accent, label }) {
  _ensureKeyframes();
  const px = typeof size === "number" ? size : (SIZES[size] ?? SIZES.md);
  return (
    <span
      role="status"
      aria-label={label || "Loading"}
      style={{
        display: "inline-block",
        width: px,
        height: px,
        border: `${Math.max(2, Math.floor(px / 10))}px solid ${COLORS.border}`,
        borderTopColor: color,
        borderRadius: "50%",
        animation: `aipet-spin 800ms linear infinite`,
        verticalAlign: "middle",
        transition: MOTION.base,
      }}
    />
  );
}
