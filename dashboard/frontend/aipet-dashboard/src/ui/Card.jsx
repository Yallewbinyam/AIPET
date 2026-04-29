import React from "react";
import { COLORS, TYPO, SPACE, RADIUS, SHADOW } from "../design/tokens";

// Container surface used by panels and table wrappers. Optional
// header row (title + actions) and footer slot. Padding can be
// dialled per-card via the `padding` prop -- 0 to render flush
// content like tables that own their own padding.
export default function Card({
  title,
  subtitle,
  actions,
  footer,
  padding = SPACE.xxl,
  style,
  bodyStyle,
  children,
  ...rest
}) {
  const hasHeader = Boolean(title || subtitle || actions);
  return (
    <section
      style={{
        background: COLORS.bgCard,
        border: `1px solid ${COLORS.border}`,
        borderRadius: RADIUS.lg,
        boxShadow: SHADOW.card,
        color: COLORS.text,
        fontFamily: TYPO.family,
        ...style,
      }}
      {...rest}
    >
      {hasHeader && (
        <header
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: SPACE.lg,
            padding: `${SPACE.lg}px ${SPACE.xl}px`,
            borderBottom: `1px solid ${COLORS.border}`,
          }}
        >
          <div style={{ minWidth: 0 }}>
            {title && (
              <h3
                style={{
                  margin: 0,
                  color: COLORS.text,
                  fontSize: TYPO.sizeLg,
                  fontWeight: TYPO.weightSemi,
                  letterSpacing: TYPO.trackTight,
                  lineHeight: TYPO.leadingTight,
                }}
              >
                {title}
              </h3>
            )}
            {subtitle && (
              <p
                style={{
                  margin: `${SPACE.xs}px 0 0`,
                  color: COLORS.textMuted,
                  fontSize: TYPO.sizeSm,
                  lineHeight: TYPO.leadingNormal,
                }}
              >
                {subtitle}
              </p>
            )}
          </div>
          {actions && (
            <div style={{ display: "flex", gap: SPACE.md, flexShrink: 0 }}>
              {actions}
            </div>
          )}
        </header>
      )}
      <div style={{ padding, ...bodyStyle }}>{children}</div>
      {footer && (
        <footer
          style={{
            padding: `${SPACE.lg}px ${SPACE.xl}px`,
            borderTop: `1px solid ${COLORS.border}`,
            color: COLORS.textMuted,
            fontSize: TYPO.sizeSm,
          }}
        >
          {footer}
        </footer>
      )}
    </section>
  );
}
