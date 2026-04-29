import React, { useState } from "react";
import { Copy, Check } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../design/tokens";

// Read-only, single-or-multi-line monospace block with an optional
// copy button. No syntax highlighting (out of scope for v1; we'll
// reach for prismjs only when we have a real diff/large blob).
export default function CodeBlock({
  children,
  copyable = false,
  inline = false,
  language,
  style,
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(String(children));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard blocked -- silently no-op; caller can show its own toast
    }
  };

  const baseStyle = {
    fontFamily: TYPO.familyMono,
    fontSize: TYPO.sizeSm,
    color: COLORS.text,
    background: COLORS.bgDeep,
    border: `1px solid ${COLORS.border}`,
    borderRadius: RADIUS.sm,
    transition: MOTION.fast,
  };

  if (inline) {
    return (
      <code
        style={{
          ...baseStyle,
          padding: `${SPACE.xxs}px ${SPACE.sm}px`,
          ...style,
        }}
      >
        {children}
      </code>
    );
  }

  return (
    <div style={{ position: "relative", ...style }}>
      <pre
        style={{
          ...baseStyle,
          margin: 0,
          padding: `${SPACE.lg}px ${SPACE.xl}px`,
          overflowX: "auto",
          whiteSpace: "pre",
          lineHeight: TYPO.leadingNormal,
        }}
        data-language={language}
      >
        {children}
      </pre>
      {copyable && (
        <button
          aria-label="Copy"
          onClick={handleCopy}
          style={{
            position: "absolute",
            top: SPACE.md,
            right: SPACE.md,
            background: COLORS.bgRaised,
            border: `1px solid ${COLORS.border}`,
            borderRadius: RADIUS.sm,
            color: copied ? COLORS.success : COLORS.textMuted,
            cursor: "pointer",
            padding: SPACE.sm,
            display: "flex",
            alignItems: "center",
            transition: MOTION.fast,
          }}
        >
          {copied ? <Check size={14} /> : <Copy size={14} />}
        </button>
      )}
    </div>
  );
}
