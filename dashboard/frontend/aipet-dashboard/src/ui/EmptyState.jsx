import React from "react";
import { COLORS, TYPO, SPACE } from "../design/tokens";

// Used by Table (no rows), tab placeholders ("coming soon"),
// and any panel without data yet. Optional icon is a node so
// callers pass a lucide-react glyph or a custom emoji.
export default function EmptyState({
  icon,
  title,
  message,
  action,
  size = "md",
  style,
}) {
  const compact = size === "sm";
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        textAlign: "center",
        padding: compact ? `${SPACE.xl}px ${SPACE.lg}px`
                         : `${SPACE.giga}px ${SPACE.xxl}px`,
        gap: SPACE.lg,
        color: COLORS.textMuted,
        ...style,
      }}
    >
      {icon && (
        <div
          style={{
            width: compact ? 36 : 56,
            height: compact ? 36 : 56,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: COLORS.textSubtle,
            opacity: 0.7,
          }}
        >
          {icon}
        </div>
      )}
      {title && (
        <div
          style={{
            color: COLORS.text,
            fontSize: compact ? TYPO.sizeMd : TYPO.sizeLg,
            fontWeight: TYPO.weightSemi,
            letterSpacing: TYPO.trackTight,
          }}
        >
          {title}
        </div>
      )}
      {message && (
        <div
          style={{
            maxWidth: 380,
            fontSize: TYPO.sizeSm,
            lineHeight: TYPO.leadingNormal,
          }}
        >
          {message}
        </div>
      )}
      {action && <div style={{ marginTop: SPACE.sm }}>{action}</div>}
    </div>
  );
}
