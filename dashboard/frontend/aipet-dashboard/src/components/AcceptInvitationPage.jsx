import React, { useState } from "react";
import {
  Shield, Check, AlertTriangle, XCircle, Clock, Ban, MailWarning,
} from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, SHADOW, MOTION } from "../design/tokens";
import Button from "../ui/Button";

// Public Accept Invitation page. Reachable WITHOUT a JWT --
// rendered by App.js's no-token branch when pathname is
// "/accept-invitation" and the URL carries ?token=...
//
// State machine:
//   READY            -- default; form enabled
//   SUBMITTING       -- form disabled, button spinner
//   SUCCESS          -- 201 received; auto-login after a beat
//   INVALID_TOKEN    -- 404 invitation_not_found  (terminal)
//   EXPIRED          -- 400 expired               (terminal)
//   REVOKED          -- 400 revoked               (terminal)
//   ACCEPTED         -- 400 already_accepted      (terminal)
//   EMAIL_COLLISION  -- 409 email_collision       (terminal)
//   NETWORK_ERROR    -- transient; form re-enabled, banner shown
//
// Recon-time deviation: the originally spec'd probe-on-mount is
// dropped. Backend validation order (missing_token -> missing_name
// -> weak_password -> token lookup) means a {token, name:"", pw:""}
// probe always returns missing_name without disambiguating the
// row's status. A valid-shape probe would create the user on a
// happy-path token. PLB-13 tracks adding a public GET .../info
// endpoint to remove the round-trip cost in v2.
//
// No global Toast on this page (no toast container at this level).
// All errors render as the terminal-state card or as an inline
// red banner above the form.

const STATE = {
  READY:           "READY",
  SUBMITTING:      "SUBMITTING",
  SUCCESS:         "SUCCESS",
  INVALID_TOKEN:   "INVALID_TOKEN",
  EXPIRED:         "EXPIRED",
  REVOKED:         "REVOKED",
  ACCEPTED:        "ACCEPTED",
  EMAIL_COLLISION: "EMAIL_COLLISION",
  NETWORK_ERROR:   "NETWORK_ERROR",
};

const MIN_PASSWORD_LEN = 8;

// Map a backend error response to a UI state. Anything we don't
// recognise stays as NETWORK_ERROR-style transient so the user
// can retry rather than getting locked out.
function _stateFromError(status, body) {
  const code = body?.error;
  if (status === 404 && code === "invitation_not_found") return STATE.INVALID_TOKEN;
  if (status === 400 && code === "expired")              return STATE.EXPIRED;
  if (status === 400 && code === "revoked")              return STATE.REVOKED;
  if (status === 400 && code === "already_accepted")     return STATE.ACCEPTED;
  if (status === 409 && code === "email_collision")      return STATE.EMAIL_COLLISION;
  return null;
}

function _inputStyle(invalid, disabled) {
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
    opacity: disabled ? 0.6 : 1,
  };
}

function _Header() {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: SPACE.md,
      marginBottom: SPACE.xxl,
      justifyContent: "center",
    }}>
      <Shield size={28} color={COLORS.accent} />
      <span style={{
        color: COLORS.text,
        fontSize: TYPO.sizeXl,
        fontWeight: TYPO.weightBold,
        letterSpacing: TYPO.trackTight,
      }}>
        AIPET X
      </span>
    </div>
  );
}

function _PageShell({ children }) {
  return (
    <div style={{
      minHeight: "100vh",
      background: COLORS.bgDeep,
      color: COLORS.text,
      fontFamily: TYPO.family,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: SPACE.xl,
    }}>
      <div style={{
        width: "100%",
        maxWidth: 420,
        background: COLORS.bgCard,
        border: `1px solid ${COLORS.border}`,
        borderRadius: RADIUS.lg,
        boxShadow: SHADOW.overlay,
        padding: `${SPACE.huge}px ${SPACE.xxl}px`,
      }}>
        <_Header />
        {children}
      </div>
    </div>
  );
}

function _TerminalCard({ tone, Icon, title, message, primaryLabel, primaryHref }) {
  const colour = COLORS[tone] || COLORS.textMuted;
  return (
    <_PageShell>
      <div style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        textAlign: "center",
        gap: SPACE.lg,
      }}>
        <div style={{
          width: 56, height: 56, borderRadius: "50%",
          background: COLORS[`${tone}Soft`] || COLORS.bgRaised,
          display: "flex", alignItems: "center", justifyContent: "center",
          color: colour,
        }}>
          <Icon size={28} />
        </div>
        <h2 style={{
          margin: 0,
          color: COLORS.text,
          fontSize: TYPO.sizeXl,
          fontWeight: TYPO.weightSemi,
          letterSpacing: TYPO.trackTight,
        }}>
          {title}
        </h2>
        <p style={{
          margin: 0,
          color: COLORS.textMuted,
          fontSize: TYPO.sizeMd,
          lineHeight: TYPO.leadingNormal,
        }}>
          {message}
        </p>
        <Button
          variant="primary"
          size="md"
          fullWidth
          onClick={() => { window.location.href = primaryHref; }}
          style={{ marginTop: SPACE.lg }}
        >
          {primaryLabel}
        </Button>
      </div>
    </_PageShell>
  );
}

export default function AcceptInvitationPage({ inviteToken, onLogin }) {
  const [state,    setState]    = useState(STATE.READY);
  const [name,     setName]     = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [errors,   setErrors]   = useState({});
  // Banner copy for transient NETWORK_ERROR state. Cleared on next
  // submit attempt so the user can retry without dismissing.
  const [banner,   setBanner]   = useState("");

  const _validate = () => {
    const next = {};
    if (!name.trim()) {
      next.name = "Enter your name.";
    }
    if (!password) {
      next.password = "Choose a password.";
    } else if (password.length < MIN_PASSWORD_LEN) {
      next.password = `Password must be at least ${MIN_PASSWORD_LEN} characters.`;
    }
    if (confirm !== password) {
      next.confirm = "Passwords do not match.";
    }
    return next;
  };

  const handleSubmit = async (ev) => {
    ev.preventDefault();
    const v = _validate();
    if (Object.keys(v).length > 0) {
      setErrors(v);
      return;
    }
    setErrors({});
    setBanner("");
    setState(STATE.SUBMITTING);

    let resp;
    try {
      resp = await fetch("/api/auth/accept-invitation", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token:    inviteToken,
          name:     name.trim(),
          password: password,
        }),
      });
    } catch (netErr) {
      setBanner("Network error — please retry.");
      setState(STATE.NETWORK_ERROR);
      return;
    }

    const body = await resp.json().catch(() => ({}));

    if (resp.ok) {
      // Backend returns { message, token, user, role }. Persist
      // the JWT under the same localStorage key the rest of the
      // app uses, then hand off to App.js's handleLogin so the
      // dashboard mounts in this same tab.
      try {
        if (body.token) localStorage.setItem("aipet_token", body.token);
      } catch {
        // localStorage can throw in private mode; we still call
        // onLogin with the token since App.js stores it in state.
      }
      setState(STATE.SUCCESS);
      // Brief beat so the user sees the success card before the
      // dashboard mounts -- avoids a jarring flash.
      setTimeout(() => {
        if (onLogin) onLogin(body.token, body.user);
      }, 700);
      return;
    }

    // Map backend error to a state. weak_password is the only
    // 4xx that should return the user to the form rather than a
    // terminal card -- they can fix it on the spot.
    if (resp.status === 400 && body?.error === "weak_password") {
      setErrors({
        password: typeof body.message === "string" && body.message.length > 0
          ? body.message
          : `Password must be at least ${MIN_PASSWORD_LEN} characters.`,
      });
      setState(STATE.READY);
      return;
    }

    const next = _stateFromError(resp.status, body);
    if (next) {
      setState(next);
      return;
    }

    // Unrecognised 4xx/5xx: treat as transient, keep the form
    // alive so the user can try again. Coerce body.message to a
    // string so a non-string payload never reaches the banner.
    const raw = body?.message || body?.error;
    const msg = (typeof raw === "string" && raw.length > 0)
      ? raw
      : `Request failed (${resp.status}). Please try again.`;
    setBanner(msg);
    setState(STATE.NETWORK_ERROR);
  };

  // ── Terminal-state rendering ────────────────────────────────
  if (state === STATE.INVALID_TOKEN) {
    return (
      <_TerminalCard
        tone="danger" Icon={XCircle}
        title="This invitation is invalid"
        message="The invitation link is malformed or has already been used. If you believe this is an error, contact the person who invited you."
        primaryLabel="Go to sign in" primaryHref="/"
      />
    );
  }
  if (state === STATE.EXPIRED) {
    return (
      <_TerminalCard
        tone="warn" Icon={Clock}
        title="This invitation has expired"
        message="Ask the person who invited you to send a new one."
        primaryLabel="Go to sign in" primaryHref="/"
      />
    );
  }
  if (state === STATE.REVOKED) {
    return (
      <_TerminalCard
        tone="danger" Icon={Ban}
        title="This invitation was revoked"
        message="An administrator revoked this invitation. Contact the inviter for details."
        primaryLabel="Go to sign in" primaryHref="/"
      />
    );
  }
  if (state === STATE.ACCEPTED) {
    return (
      <_TerminalCard
        tone="info" Icon={Check}
        title="This invitation has already been used"
        message="If this is your account, sign in instead."
        primaryLabel="Sign in" primaryHref="/"
      />
    );
  }
  if (state === STATE.EMAIL_COLLISION) {
    return (
      <_TerminalCard
        tone="warn" Icon={MailWarning}
        title="An account with this email already exists"
        message="Sign in with your existing credentials. Your administrator can apply the invited role to your account."
        primaryLabel="Sign in" primaryHref="/"
      />
    );
  }

  if (state === STATE.SUCCESS) {
    return (
      <_PageShell>
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
          gap: SPACE.lg,
        }}>
          <div style={{
            width: 56, height: 56, borderRadius: "50%",
            background: COLORS.successSoft,
            display: "flex", alignItems: "center", justifyContent: "center",
            color: COLORS.success,
          }}>
            <Check size={28} />
          </div>
          <h2 style={{
            margin: 0,
            color: COLORS.text,
            fontSize: TYPO.sizeXl,
            fontWeight: TYPO.weightSemi,
            letterSpacing: TYPO.trackTight,
          }}>
            Welcome to AIPET X
          </h2>
          <p style={{
            margin: 0,
            color: COLORS.textMuted,
            fontSize: TYPO.sizeMd,
          }}>
            Signing you in…
          </p>
        </div>
      </_PageShell>
    );
  }

  // ── READY / SUBMITTING / NETWORK_ERROR (form rendered) ───────
  const submitting = state === STATE.SUBMITTING;

  return (
    <_PageShell>
      <h2 style={{
        margin: `0 0 ${SPACE.sm}px`,
        color: COLORS.text,
        fontSize: TYPO.sizeXl,
        fontWeight: TYPO.weightSemi,
        letterSpacing: TYPO.trackTight,
        textAlign: "center",
      }}>
        Accept your invitation
      </h2>
      <p style={{
        margin: `0 0 ${SPACE.xxl}px`,
        color: COLORS.textMuted,
        fontSize: TYPO.sizeSm,
        textAlign: "center",
        lineHeight: TYPO.leadingNormal,
      }}>
        Set your name and password, and you'll be signed in.
      </p>

      {state === STATE.NETWORK_ERROR && banner && (
        <div style={{
          display: "flex",
          alignItems: "flex-start",
          gap: SPACE.md,
          background: COLORS.dangerSoft,
          border: `1px solid ${COLORS.danger}`,
          borderRadius: RADIUS.md,
          padding: `${SPACE.md}px ${SPACE.lg}px`,
          marginBottom: SPACE.lg,
          color: COLORS.danger,
          fontSize: TYPO.sizeSm,
        }}>
          <AlertTriangle size={16} style={{ flex: "none", marginTop: 2 }} />
          <span style={{ flex: 1, lineHeight: TYPO.leadingNormal }}>
            {banner}
          </span>
        </div>
      )}

      <form onSubmit={handleSubmit} style={{ display: "grid", rowGap: SPACE.lg }}>
        <div>
          <label
            htmlFor="aipet-accept-name"
            style={{
              display: "block",
              color: COLORS.textMuted,
              fontSize: TYPO.sizeSm,
              marginBottom: SPACE.sm,
              fontWeight: TYPO.weightMedium,
            }}
          >
            Your name
          </label>
          <input
            id="aipet-accept-name"
            type="text"
            autoComplete="name"
            disabled={submitting}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Jane Doe"
            style={_inputStyle(!!errors.name, submitting)}
          />
          {errors.name && (
            <div style={{
              color: COLORS.danger, fontSize: TYPO.sizeSm, marginTop: SPACE.xs,
            }}>{errors.name}</div>
          )}
        </div>

        <div>
          <label
            htmlFor="aipet-accept-password"
            style={{
              display: "block",
              color: COLORS.textMuted,
              fontSize: TYPO.sizeSm,
              marginBottom: SPACE.sm,
              fontWeight: TYPO.weightMedium,
            }}
          >
            Password
          </label>
          <input
            id="aipet-accept-password"
            type="password"
            autoComplete="new-password"
            disabled={submitting}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 8 characters"
            style={_inputStyle(!!errors.password, submitting)}
          />
          {errors.password && (
            <div style={{
              color: COLORS.danger, fontSize: TYPO.sizeSm, marginTop: SPACE.xs,
            }}>{errors.password}</div>
          )}
        </div>

        <div>
          <label
            htmlFor="aipet-accept-confirm"
            style={{
              display: "block",
              color: COLORS.textMuted,
              fontSize: TYPO.sizeSm,
              marginBottom: SPACE.sm,
              fontWeight: TYPO.weightMedium,
            }}
          >
            Confirm password
          </label>
          <input
            id="aipet-accept-confirm"
            type="password"
            autoComplete="new-password"
            disabled={submitting}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Re-type the password"
            style={_inputStyle(!!errors.confirm, submitting)}
          />
          {errors.confirm && (
            <div style={{
              color: COLORS.danger, fontSize: TYPO.sizeSm, marginTop: SPACE.xs,
            }}>{errors.confirm}</div>
          )}
        </div>

        <Button
          variant="primary"
          size="lg"
          type="submit"
          loading={submitting}
          fullWidth
          style={{ marginTop: SPACE.sm }}
        >
          Accept invitation
        </Button>
      </form>
    </_PageShell>
  );
}
