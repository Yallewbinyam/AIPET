import React, { useEffect, useMemo, useState } from "react";
import {
  Mail, RefreshCw, UserPlus, Send, XCircle,
} from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../../design/tokens";
import Table from "../../ui/Table";
import Pill from "../../ui/Pill";
import Button from "../../ui/Button";
import ConfirmDialog from "../../ui/ConfirmDialog";
import RelativeTime from "../../ui/RelativeTime";
import EmptyState from "../../ui/EmptyState";
import useApi from "../../ui/useApi";
import { roleTone } from "./MemberDetailDrawer";
import InviteModal from "./InviteModal";

// Invitations tab for Phase F. Shape mirrors MembersTab so the
// patterns survive once the audit log + roles tabs land. Backend
// at iam/routes.py owns five admin endpoints; this file owns the
// list, the row actions, and the modal trigger. The modal lives
// in InviteModal.jsx.

const RESEND_MAX = 3;

const FILTERS = [
  { value: "pending",  label: "Pending"  },
  { value: "accepted", label: "Accepted" },
  { value: "revoked",  label: "Revoked"  },
  { value: "expired",  label: "Expired"  },
  { value: "all",      label: "All"      },
];

function _invitationTone(status) {
  switch (status) {
    case "pending":  return "warn";
    case "accepted": return "success";
    case "revoked":  return "danger";
    case "expired":  return "neutral";
    default:         return "neutral";
  }
}

function _emptyMessage(filter, hasError) {
  if (hasError) return null;
  switch (filter) {
    case "pending":
      return "No pending invitations. Click Invite member to invite someone.";
    case "accepted": return "No accepted invitations yet.";
    case "revoked":  return "No revoked invitations.";
    case "expired":  return "No expired invitations.";
    case "all":      return "No invitations at all yet.";
    default:         return "No invitations match that filter.";
  }
}

export default function InvitationsTab({ showToast }) {
  const safeToast = showToast || (() => {});

  const [statusFilter, setStatusFilter] = useState("pending");

  // useApi auto-refetches when the URL string changes, so changing
  // the filter rebuilds the query without manual plumbing.
  const listUrl = `/iam/invitations?status=${encodeURIComponent(statusFilter)}`;
  const { data: listResp, loading, error, refetch } = useApi(listUrl);

  // Roles list feeds the InviteModal's role picker. Loaded once
  // here so the modal opens instantly without a flash of "Loading
  // roles…". Phase C MembersTab uses the same pattern.
  const { data: rolesResp } = useApi("/iam/roles");
  const roles = Array.isArray(rolesResp) ? rolesResp
                                         : (rolesResp?.roles || []);

  const invitations = listResp?.invitations || [];
  const total = listResp?.total ?? 0;

  const [inviteOpen, setInviteOpen] = useState(false);
  const [confirm, setConfirm]       = useState(null); // {kind, invitation}
  const [busy, setBusy]             = useState(null); // 'resend' | 'revoke' | 'create'

  // Surface a hook-level error (initial fetch failed) once -- the
  // EmptyState below also renders the message persistently.
  useEffect(() => {
    if (error) safeToast(error.message || "Failed to load invitations", "error");
  }, [error, safeToast]);

  // Same hardened helper shape as MembersTab._request -- split
  // network reject from HTTP non-2xx so a missing server gets the
  // spec'd "Network error -- please retry." copy and an HTTP error
  // surfaces body.message verbatim. Coerces non-string error
  // bodies to "Request failed (<status>)" so a {"error":{...}}
  // payload never reaches the global Toast as a React child.
  const _request = async (opts, successMsg) => {
    let resp;
    try {
      const token = localStorage.getItem("aipet_token");
      resp = await fetch(`/api${opts.url}`, {
        method:  opts.method,
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
    } catch (netErr) {
      safeToast("Network error — please retry.", "error");
      throw netErr;
    }
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const raw = body.message || body.error;
      const msg = (typeof raw === "string" && raw.length > 0)
        ? raw
        : `Request failed (${resp.status})`;
      safeToast(msg, "error");
      const err = new Error(msg);
      err.status = resp.status;
      err.body   = body;
      throw err;
    }
    if (successMsg) safeToast(successMsg, "success");
    return body;
  };

  const handleResend = async (inv) => {
    setBusy("resend");
    try {
      await _request({
        url:    `/iam/invitations/${inv.id}/resend`,
        method: "POST",
        body:   {},
      }, `Invitation resent to ${inv.email}`);
      await refetch();
    } catch (e) {
      // 404 is the only soft-recovery path: the row vanished server-
      // side (e.g. another admin hard-deleted it). Refetch so the
      // table self-heals; toast was already shown by _request.
      if (e && e.status === 404) await refetch();
    } finally {
      setBusy(null);
    }
  };

  const handleRevokeClick = (inv) => {
    setConfirm({ kind: "revoke", invitation: inv });
  };

  const performConfirmed = async () => {
    if (!confirm) return;
    const { invitation } = confirm;
    setBusy("revoke");
    try {
      await _request({
        url:    `/iam/invitations/${invitation.id}/revoke`,
        method: "POST",
        body:   {},
      }, "Invitation revoked");
      await refetch();
      setConfirm(null);
    } catch (e) {
      // Same 404 self-heal as resend; otherwise leave the dialog
      // open so the user can read the toast and click Cancel.
      if (e && e.status === 404) {
        await refetch();
        setConfirm(null);
      }
    } finally {
      setBusy(null);
    }
  };

  const handleInviteSuccess = async (msg) => {
    // Modal already closed itself. Push success toast here so the
    // copy can mention email_delivered. Then refetch the list so
    // the new pending row shows immediately.
    safeToast(msg, "success");
    await refetch();
  };

  // Memoised so column definitions don't reshape on every render
  // (Table re-sorts on column identity changes).
  const columns = useMemo(() => ([
    { key: "email", header: "Email", sortable: true,
      accessor: (row) => (row.email || "").toLowerCase(),
      render: (row) => (
        <span style={{ color: COLORS.text, fontWeight: TYPO.weightMedium }}>
          {row.email}
        </span>
      ),
    },
    { key: "role", header: "Role",
      render: (row) => row.role
        ? <Pill tone={roleTone(row.role)}>{row.role}</Pill>
        : <span style={{ color: COLORS.textSubtle }}>—</span>,
    },
    { key: "status", header: "Status",
      render: (row) => <Pill tone={_invitationTone(row.status)}>{row.status}</Pill>,
    },
    { key: "invited_at", header: "Sent", sortable: true,
      accessor: (row) => row.invited_at ? Date.parse(row.invited_at) : 0,
      render: (row) => <RelativeTime value={row.invited_at} />,
    },
    { key: "resends", header: "Resends",
      render: (row) => (
        <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          {row.resend_count}/{RESEND_MAX}
        </span>
      ),
    },
    { key: "expires_at", header: "Expires", sortable: true,
      accessor: (row) => row.expires_at ? Date.parse(row.expires_at) : 0,
      render: (row) => <RelativeTime value={row.expires_at} fallback="—" />,
    },
    { key: "actions", header: "",
      render: (row) => row.status === "pending" ? (
        <div style={{ display: "flex", gap: SPACE.md, justifyContent: "flex-end" }}>
          <Button
            variant="ghost"
            size="sm"
            leadingIcon={<Send size={12} />}
            disabled={busy !== null}
            loading={busy === "resend"}
            onClick={() => handleResend(row)}
          >
            Resend
          </Button>
          <Button
            variant="ghost"
            size="sm"
            leadingIcon={<XCircle size={12} />}
            disabled={busy !== null}
            onClick={() => handleRevokeClick(row)}
          >
            Revoke
          </Button>
        </div>
      ) : null,
    },
  // Disable react-hooks/exhaustive-deps -- handlers close over
  // stable state setters; including them here causes column
  // identity to change every render and re-resorts the table.
  ]), [busy]);

  return (
    <div style={{ padding: SPACE.xl }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: SPACE.lg,
        marginBottom: SPACE.lg,
        flexWrap: "wrap",
      }}>
        <div style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          {loading ? "Loading…"
                   : `${total} ${statusFilter} invitation${total === 1 ? "" : "s"}`}
        </div>
        <div style={{ display: "flex", gap: SPACE.md, alignItems: "center" }}>
          <label style={{ display: "inline-flex", alignItems: "center", gap: SPACE.sm }}>
            <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>Filter:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              disabled={loading}
              style={{
                background: COLORS.bgDeep,
                color: COLORS.text,
                border: `1px solid ${COLORS.border}`,
                borderRadius: RADIUS.md,
                padding: `${SPACE.sm}px ${SPACE.lg}px`,
                fontSize: TYPO.sizeSm,
                fontFamily: TYPO.family,
                outline: "none",
                transition: MOTION.fast,
                minWidth: 110,
              }}
            >
              {FILTERS.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </label>
          <Button
            variant="ghost"
            size="sm"
            leadingIcon={<RefreshCw size={14} />}
            onClick={() => refetch()}
            disabled={loading}
          >
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            leadingIcon={<UserPlus size={14} />}
            onClick={() => setInviteOpen(true)}
          >
            Invite member
          </Button>
        </div>
      </div>

      <Table
        columns={columns}
        data={invitations}
        rowKey="id"
        loading={loading}
        defaultSortKey="invited_at"
        defaultSortDir="desc"
        empty={
          error ? (
            <EmptyState
              icon={<Mail size={36} />}
              title="Could not load invitations"
              message={error.message || "Please retry."}
              action={
                <Button variant="secondary" size="sm" onClick={() => refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<Mail size={36} />}
              title={statusFilter === "pending" ? "No pending invitations" : "Nothing here"}
              message={_emptyMessage(statusFilter, false)}
              action={statusFilter === "pending" ? (
                <Button
                  variant="primary"
                  size="sm"
                  leadingIcon={<UserPlus size={14} />}
                  onClick={() => setInviteOpen(true)}
                >
                  Invite member
                </Button>
              ) : null}
            />
          )
        }
      />

      <InviteModal
        open={inviteOpen}
        onClose={() => setInviteOpen(false)}
        roles={roles}
        showToast={safeToast}
        onSuccess={handleInviteSuccess}
      />

      <ConfirmDialog
        open={!!confirm && confirm.kind === "revoke"}
        onClose={() => (busy ? null : setConfirm(null))}
        onConfirm={performConfirmed}
        loading={busy === "revoke"}
        destructive
        title="Revoke invitation?"
        message={
          confirm
            ? `Revoke the invitation to ${confirm.invitation.email}? They will no longer be able to accept it. Reversing this means inviting again.`
            : ""
        }
        confirmLabel="Revoke"
      />
    </div>
  );
}
