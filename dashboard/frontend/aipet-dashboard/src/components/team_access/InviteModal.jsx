import React, { useEffect, useState } from "react";
import { Send } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../../design/tokens";
import Modal from "../../ui/Modal";
import Button from "../../ui/Button";

// Short-form modal for POST /api/iam/invitations. Owned by
// InvitationsTab -- the parent provides the role list (already
// fetched via useApi for performance) and a showToast callback.
//
// Error handling mirrors MembersTab's hardened pattern: split
// network reject from HTTP non-2xx, coerce body.error to a
// guaranteed string, and route the result through showToast --
// never as a React child. The friendly-copy map lives here so
// users see "That email already has an account..." rather than
// the raw "user_exists" code.

const DEFAULT_EXPIRES_DAYS = 7;
const MIN_EXPIRES_DAYS     = 1;
const MAX_EXPIRES_DAYS     = 30;

// V1 policy: hide the `owner` role from the picker. Inviting a
// new owner needs a stronger confirm flow that is filed for v2.
const HIDDEN_ROLES = new Set(["owner"]);

// Backend error codes mapped to user-facing copy. Anything not
// listed falls through to body.message || body.error verbatim.
const FRIENDLY_BY_CODE = {
  invalid_email:           "That doesn't look like a valid email.",
  invalid_role:            "Pick a role for the invite.",
  role_not_found:          "That role no longer exists; pick another.",
  invalid_expires_in_days: "Expiry must be 1–30 days.",
  user_exists:             "That email already has an account; assign a role directly.",
};

function _inputStyle(invalid) {
  return {
    width: "100%",
    background: COLORS.bgDeep,
    color: COLORS.text,
    border: `1px solid ${invalid ? COLORS.danger : COLORS.border}`,
    borderRadius: RADIUS.md,
    padding: `${SPACE.md}px ${SPACE.lg}px`,
    fontSize: TYPO.sizeBase,
    fontFamily: TYPO.family,
    minHeight: 38,
    outline: "none",
    transition: MOTION.fast,
    boxSizing: "border-box",
  };
}

function _Label({ htmlFor, children }) {
  return (
    <label
      htmlFor={htmlFor}
      style={{
        display: "block",
        color: COLORS.textMuted,
        fontSize: TYPO.sizeSm,
        marginBottom: SPACE.sm,
        fontWeight: TYPO.weightMedium,
      }}
    >
      {children}
    </label>
  );
}

function _FieldError({ children }) {
  if (!children) return null;
  return (
    <div style={{
      color: COLORS.danger,
      fontSize: TYPO.sizeSm,
      marginTop: SPACE.xs,
    }}>
      {children}
    </div>
  );
}

export default function InviteModal({
  open, onClose, roles, showToast, onSuccess,
}) {
  const safeToast = showToast || (() => {});
  const visibleRoles = (roles || []).filter((r) => !HIDDEN_ROLES.has(r.name));

  const [email,           setEmail]           = useState("");
  const [roleName,        setRoleName]        = useState("");
  const [expiresInDays,   setExpiresInDays]   = useState(DEFAULT_EXPIRES_DAYS);
  const [errors,          setErrors]          = useState({});
  const [busy,            setBusy]            = useState(false);

  // Reset every time the modal re-opens. Default to "viewer" if
  // present, otherwise the first visible role -- matches the spec
  // and avoids a blank submit when the list shape evolves.
  useEffect(() => {
    if (!open) return;
    setEmail("");
    setExpiresInDays(DEFAULT_EXPIRES_DAYS);
    setErrors({});
    setBusy(false);
    const viewer = visibleRoles.find((r) => r.name === "viewer");
    setRoleName(viewer ? viewer.name
                       : (visibleRoles[0]?.name || ""));
  // visibleRoles isn't stable identity-wise, so keying off `open`
  // and the role names string is enough to reset on each show.
  }, [open, (roles || []).map((r) => r.name).join(",")]);

  const _validate = () => {
    const next = {};
    const e = email.trim();
    if (!e || !e.includes("@")) {
      next.email = "Enter a valid email address.";
    }
    if (!roleName) {
      next.roleName = "Pick a role.";
    }
    const days = Number(expiresInDays);
    if (!Number.isInteger(days) || days < MIN_EXPIRES_DAYS || days > MAX_EXPIRES_DAYS) {
      next.expiresInDays = `Must be an integer between ${MIN_EXPIRES_DAYS} and ${MAX_EXPIRES_DAYS}.`;
    }
    return next;
  };

  // Modal-local request helper. Same hardened shape as MembersTab
  // but DOES NOT auto-toast errors -- the caller below maps
  // body.error to a friendly message before showing the toast.
  const _request = async (body) => {
    let resp;
    try {
      const token = localStorage.getItem("aipet_token");
      resp = await fetch("/api/iam/invitations", {
        method:  "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });
    } catch (netErr) {
      const e = new Error("Network error — please retry.");
      e.kind = "network";
      throw e;
    }
    const respBody = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const raw = respBody.message || respBody.error;
      const fallback = (typeof raw === "string" && raw.length > 0)
        ? raw
        : `Request failed (${resp.status})`;
      const e = new Error(fallback);
      e.kind   = "http";
      e.status = resp.status;
      e.body   = respBody;
      throw e;
    }
    return respBody;
  };

  const handleSubmit = async (ev) => {
    ev.preventDefault();
    const v = _validate();
    if (Object.keys(v).length > 0) {
      setErrors(v);
      return;
    }
    setErrors({});
    setBusy(true);
    try {
      const body = await _request({
        email:           email.trim(),
        role_name:       roleName,
        expires_in_days: Number(expiresInDays),
      });
      // Success copy depends on whether SMTP delivered the mail.
      // Backend returns email_delivered=false when SMTP is down
      // but the row still persists; admin can resend later.
      const msg = body.email_delivered
        ? `Invitation sent to ${body.email}.`
        : `Invitation created for ${body.email}, but email delivery failed. You can resend once SMTP is restored.`;
      // Hand off to the parent; it pushes the toast and refetches.
      // Modal closes here so the success surface is the table row,
      // not a banner inside a still-open form.
      onClose();
      if (onSuccess) await onSuccess(msg);
    } catch (err) {
      // Map backend error code → friendly copy. Falls through to
      // err.message which the hardened helper guarantees is a
      // string. Special-case duplicate_pending so the user knows
      // to use Resend instead of trying again.
      const code = err.body?.error;
      let toastMsg;
      if (code === "duplicate_pending") {
        toastMsg = `An invitation to ${email.trim()} is already pending. Use Resend on the existing row.`;
      } else if (code && FRIENDLY_BY_CODE[code]) {
        toastMsg = FRIENDLY_BY_CODE[code];
      } else {
        toastMsg = err.message || "Could not send invitation.";
      }
      safeToast(toastMsg, "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={busy ? () => {} : onClose}
      dismissible={!busy}
      title="Invite team member"
      size="md"
      footer={
        <>
          <Button variant="ghost" size="md" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="md"
            type="submit"
            form="aipet-invite-form"
            loading={busy}
            leadingIcon={<Send size={14} />}
          >
            Send invitation
          </Button>
        </>
      }
    >
      <form
        id="aipet-invite-form"
        onSubmit={handleSubmit}
        style={{ display: "grid", rowGap: SPACE.lg }}
      >
        <p style={{
          margin: 0,
          color: COLORS.textMuted,
          fontSize: TYPO.sizeSm,
          lineHeight: TYPO.leadingNormal,
        }}>
          The invitee will receive an email with a single-use link that lets
          them set a password and join the team. Links expire after the
          configured number of days.
        </p>

        <div>
          <_Label htmlFor="aipet-invite-email">Email</_Label>
          <input
            id="aipet-invite-email"
            type="email"
            autoComplete="off"
            disabled={busy}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="teammate@example.com"
            style={_inputStyle(!!errors.email)}
          />
          <_FieldError>{errors.email}</_FieldError>
        </div>

        <div>
          <_Label htmlFor="aipet-invite-role">Role</_Label>
          <select
            id="aipet-invite-role"
            disabled={busy || visibleRoles.length === 0}
            value={roleName}
            onChange={(e) => setRoleName(e.target.value)}
            style={_inputStyle(!!errors.roleName)}
          >
            {visibleRoles.length === 0 && (
              <option value="">No roles available</option>
            )}
            {visibleRoles.map((r) => (
              <option key={r.id} value={r.name}>{r.name}</option>
            ))}
          </select>
          <_FieldError>{errors.roleName}</_FieldError>
        </div>

        <div>
          <_Label htmlFor="aipet-invite-expires">Expires in (days)</_Label>
          <input
            id="aipet-invite-expires"
            type="number"
            min={MIN_EXPIRES_DAYS}
            max={MAX_EXPIRES_DAYS}
            disabled={busy}
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
            style={_inputStyle(!!errors.expiresInDays)}
          />
          <_FieldError>{errors.expiresInDays}</_FieldError>
        </div>
      </form>
    </Modal>
  );
}
