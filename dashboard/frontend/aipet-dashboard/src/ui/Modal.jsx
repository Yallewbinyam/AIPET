import React, { useEffect } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, SHADOW, MOTION, Z } from "../design/tokens";

const SIZES = { sm: 380, md: 520, lg: 720, xl: 920 };

let _styleInjected = false;
function _ensureKeyframes() {
  if (_styleInjected || typeof document === "undefined") return;
  const style = document.createElement("style");
  style.setAttribute("data-aipet-ui", "modal");
  style.textContent = `
    @keyframes aipet-fade-in   { from { opacity: 0; } to { opacity: 1; } }
    @keyframes aipet-scale-in  { from { opacity: 0; transform: scale(0.96); } to { opacity: 1; transform: scale(1); } }
  `;
  document.head.appendChild(style);
  _styleInjected = true;
}

// Centred dialog. ESC + backdrop click both close (overridable
// per consumer with `dismissible={false}`). Lock body scroll
// while open so a long modal doesn't double-scroll on iOS.
export default function Modal({
  open,
  onClose,
  title,
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
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", handler);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, dismissible, onClose]);

  if (!open || typeof document === "undefined") return null;

  const width = typeof size === "number" ? size : (SIZES[size] ?? SIZES.md);

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel || title || "Dialog"}
      onClick={() => dismissible && onClose && onClose()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.6)",
        zIndex: Z.modal,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: SPACE.xl,
        animation: `aipet-fade-in ${MOTION.base}`,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: width,
          maxHeight: "90vh",
          display: "flex",
          flexDirection: "column",
          background: COLORS.bgCard,
          color: COLORS.text,
          border: `1px solid ${COLORS.border}`,
          borderRadius: RADIUS.lg,
          boxShadow: SHADOW.overlay,
          fontFamily: TYPO.family,
          animation: `aipet-scale-in ${MOTION.base} ${MOTION.easeOut}`,
        }}
      >
        {(title || dismissible) && (
          <header
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: `${SPACE.lg}px ${SPACE.xl}px`,
              borderBottom: `1px solid ${COLORS.border}`,
            }}
          >
            <h3
              style={{
                margin: 0,
                fontSize: TYPO.sizeLg,
                fontWeight: TYPO.weightSemi,
                letterSpacing: TYPO.trackTight,
              }}
            >
              {title}
            </h3>
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
        <div style={{ padding: SPACE.xl, overflowY: "auto", flex: 1 }}>
          {children}
        </div>
        {footer && (
          <footer
            style={{
              display: "flex",
              justifyContent: "flex-end",
              gap: SPACE.md,
              padding: `${SPACE.lg}px ${SPACE.xl}px`,
              borderTop: `1px solid ${COLORS.border}`,
            }}
          >
            {footer}
          </footer>
        )}
      </div>
    </div>,
    document.body,
  );
}
