import React from "react";
import { CheckCircle2, AlertCircle, Info, AlertTriangle, X } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, SHADOW, MOTION } from "../design/tokens";

// Pure presentational toast card. AIPET X already has a global
// toast system in App.js (showToast prop, App.js:2959); this
// primitive is here for callers that want to render a
// notification inline (e.g. a dismissible banner inside a panel)
// without going through the global stream. No timer logic, no
// portal -- consumers control mount/unmount.

const TONES = {
  success: { fg: COLORS.success, bd: COLORS.success, Icon: CheckCircle2 },
  error:   { fg: COLORS.danger,  bd: COLORS.danger,  Icon: AlertCircle },
  warning: { fg: COLORS.warn,    bd: COLORS.warn,    Icon: AlertTriangle },
  info:    { fg: COLORS.info,    bd: COLORS.info,    Icon: Info },
};

export default function Toast({
  message,
  type = "info",
  onClose,
  style,
}) {
  const tone = TONES[type] ?? TONES.info;
  const Icon = tone.Icon;
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        display: "flex",
        alignItems: "center",
        gap: SPACE.md,
        background: COLORS.bgRaised,
        color: COLORS.text,
        border: `1px solid ${tone.bd}`,
        borderLeft: `3px solid ${tone.bd}`,
        borderRadius: RADIUS.md,
        padding: `${SPACE.md}px ${SPACE.lg}px`,
        boxShadow: SHADOW.raised,
        fontSize: TYPO.sizeSm,
        fontFamily: TYPO.family,
        minWidth: 240,
        maxWidth: 480,
        transition: MOTION.base,
        ...style,
      }}
    >
      <Icon size={18} color={tone.fg} style={{ flex: "none" }} />
      <span style={{ flex: 1, lineHeight: TYPO.leadingNormal }}>{message}</span>
      {onClose && (
        <button
          aria-label="Dismiss"
          onClick={onClose}
          style={{
            background: "transparent",
            border: "none",
            color: COLORS.textMuted,
            cursor: "pointer",
            padding: SPACE.xs,
            display: "flex",
            alignItems: "center",
            transition: MOTION.fast,
          }}
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}
