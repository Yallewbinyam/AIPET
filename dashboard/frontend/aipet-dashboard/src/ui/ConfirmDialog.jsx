import React from "react";
import Modal from "./Modal";
import Button from "./Button";
import { COLORS, TYPO, SPACE } from "../design/tokens";

// Yes/no confirmation. Prefer over window.confirm() because (a)
// styled, (b) keyboard-trapped, (c) consistent. The destructive
// variant flips the primary action to red so users understand
// which path the action takes.
export default function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title = "Are you sure?",
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = false,
  loading = false,
  children,
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      dismissible={!loading}
      footer={
        <>
          <Button
            variant="ghost"
            size="md"
            onClick={onClose}
            disabled={loading}
          >
            {cancelLabel}
          </Button>
          <Button
            variant={destructive ? "danger" : "primary"}
            size="md"
            loading={loading}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {message && (
        <p
          style={{
            margin: 0,
            color: COLORS.text,
            fontSize: TYPO.sizeBase,
            lineHeight: TYPO.leadingNormal,
          }}
        >
          {message}
        </p>
      )}
      {children && (
        <div style={{ marginTop: message ? SPACE.lg : 0 }}>{children}</div>
      )}
    </Modal>
  );
}
