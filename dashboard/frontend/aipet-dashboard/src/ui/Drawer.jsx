import React, { useEffect } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, SHADOW, MOTION, Z } from "../design/tokens";

const SIZES = { sm: 320, md: 420, lg: 560, xl: 720 };

let _styleInjected = false;
function _ensureKeyframes() {
  if (_styleInjected || typeof document === "undefined") return;
  const style = document.createElement("style");
  style.setAttribute("data-aipet-ui", "drawer");
  style.textContent = `
    @keyframes aipet-slide-from-right { from { transform: translateX(100%); } to { transform: translateX(0); } }
    @keyframes aipet-slide-from-left  { from { transform: translateX(-100%); } to { transform: translateX(0); } }
    @keyframes aipet-fade-in          { from { opacity: 0; } to { opacity: 1; } }
  `;
  document.head.appendChild(style);
  _styleInjected = true;
}

// Side panel. Right-side by default; member detail / log entry
// detail / form panes all use the right slot. Left slot is
// reserved for future nav-style usage.
export default function Drawer({
  open,
  onClose,
  title,
  subtitle,
  side = "right",
  size = "md",
  dismissible = true,
  children,
  footer,
  ariaLabel,
}) {
  _ensureKeyframes();

  useEffect(() => {
    if (!open) return undefined;
    const handler = (e) => { if (e.key === "Escape" && dismissible) onClose && onClose(); };
    window.addEventListener("keydown", handler);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", handler);
      document.body.style.overflow = prev;
    };
  }, [open, dismissible, onClose]);

  if (!open || typeof document === "undefined") return null;

  const width = typeof size === "number" ? size : (SIZES[size] ?? SIZES.md);
  const slideAnim = side === "left" ? "aipet-slide-from-left" : "aipet-slide-from-right";

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel || title || "Drawer"}
      onClick={() => dismissible && onClose && onClose()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.5)",
        zIndex: Z.drawer,
        display: "flex",
        justifyContent: side === "left" ? "flex-start" : "flex-end",
        animation: `aipet-fade-in ${MOTION.base}`,
      }}
    >
      <aside
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: width,
          height: "100%",
          background: COLORS.bgCard,
          color: COLORS.text,
          borderLeft: side === "right" ? `1px solid ${COLORS.border}` : "none",
          borderRight: side === "left" ? `1px solid ${COLORS.border}` : "none",
          boxShadow: SHADOW.overlay,
          fontFamily: TYPO.family,
          display: "flex",
          flexDirection: "column",
          animation: `${slideAnim} ${MOTION.base} ${MOTION.easeOut}`,
          borderTopLeftRadius: side === "right" ? RADIUS.lg : 0,
          borderBottomLeftRadius: side === "right" ? RADIUS.lg : 0,
        }}
      >
        {(title || subtitle || dismissible) && (
          <header
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: SPACE.lg,
              padding: `${SPACE.xl}px ${SPACE.xxl}px`,
              borderBottom: `1px solid ${COLORS.border}`,
            }}
          >
            <div style={{ minWidth: 0, flex: 1 }}>
              {title && (
                <h3
                  style={{
                    margin: 0,
                    fontSize: TYPO.sizeXl,
                    fontWeight: TYPO.weightSemi,
                    letterSpacing: TYPO.trackTight,
                    color: COLORS.text,
                  }}
                >
                  {title}
                </h3>
              )}
              {subtitle && (
                <p
                  style={{
                    margin: `${SPACE.xs}px 0 0`,
                    fontSize: TYPO.sizeSm,
                    color: COLORS.textMuted,
                  }}
                >
                  {subtitle}
                </p>
              )}
            </div>
            {dismissible && (
              <button
                aria-label="Close"
                onClick={onClose}
                style={{
                  background: "transparent",
                  border: "none",
                  color: COLORS.textMuted,
                  cursor: "pointer",
                  padding: SPACE.sm,
                  display: "flex",
                  alignItems: "center",
                }}
              >
                <X size={18} />
              </button>
            )}
          </header>
        )}
        <div style={{
          padding: `${SPACE.xl}px ${SPACE.xxl}px`,
          overflowY: "auto",
          flex: 1,
        }}>
          {children}
        </div>
        {footer && (
          <footer
            style={{
              display: "flex",
              justifyContent: "flex-end",
              gap: SPACE.md,
              padding: `${SPACE.xl}px ${SPACE.xxl}px`,
              borderTop: `1px solid ${COLORS.border}`,
            }}
          >
            {footer}
          </footer>
        )}
      </aside>
    </div>,
    document.body,
  );
}
