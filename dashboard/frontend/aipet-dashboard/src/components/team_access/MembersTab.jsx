import React, { useEffect, useMemo, useState } from "react";
import { Users, RefreshCw } from "lucide-react";
import { COLORS, TYPO, SPACE } from "../../design/tokens";
import Table from "../../ui/Table";
import Pill from "../../ui/Pill";
import Avatar from "../../ui/Avatar";
import Button from "../../ui/Button";
import ConfirmDialog from "../../ui/ConfirmDialog";
import RelativeTime from "../../ui/RelativeTime";
import EmptyState from "../../ui/EmptyState";
import useApi from "../../ui/useApi";
import MemberDetailDrawer, {
  primaryRoleName, roleTone, statusTone, statusLabel,
} from "./MemberDetailDrawer";

// MembersTab owns the data fetch (members + roles), table render,
// confirm-dialog state, and action requests. The drawer is a
// sibling presentational component; it gets a member + callbacks.

export default function MembersTab({ showToast }) {
  const safeToast = showToast || (() => {});

  const { data: membersResp, loading, error, refetch } = useApi("/iam/members");
  const { data: rolesResp } = useApi("/iam/roles");

  const members = membersResp?.members || [];
  // /api/iam/roles returns a bare list of role objects; tolerate
  // a wrapped { roles: [...] } shape too for forward-compat.
  const roles = Array.isArray(rolesResp) ? rolesResp
                                         : (rolesResp?.roles || []);

  const [selectedId, setSelectedId] = useState(null);
  const [confirm, setConfirm]       = useState(null); // {kind, member}
  const [busy, setBusy]             = useState(null); // 'toggle' | 'remove' | 'role'

  const selected = useMemo(
    () => members.find((m) => m.id === selectedId) || null,
    [members, selectedId],
  );

  // Initial-load failures route through showToast as well as the
  // table's empty state -- the former is the noisy channel
  // (drives attention), the latter is the persistent UI.
  useEffect(() => {
    if (error) safeToast(error.message || "Failed to load members", "error");
  }, [error, safeToast]);

  const _request = async (opts, successMsg) => {
    // fetch() rejecting (no HTTP response) is structurally
    // different from a non-2xx HTTP response. Split the two so we
    // can use the spec'd "Network error -- please retry." copy for
    // the former and surface the backend's own message for the
    // latter. Both paths converge on a single red toast and a
    // throw(Error) so callers' empty `catch { }` blocks still
    // swallow cleanly without re-introducing "[object Object]".
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
      // Same string-coercion guarantee as useApi._normalizeError --
      // body.error may be an object on some routes. Without the
      // typeof check, throw new Error(obj) yields the literal
      // string "[object Object]" via String(obj) and we'd toast
      // that.
      const raw = body.message || body.error;
      const msg = (typeof raw === "string" && raw.length > 0)
        ? raw
        : `Request failed (${resp.status})`;
      safeToast(msg, "error");
      throw new Error(msg);
    }
    if (successMsg) safeToast(successMsg, "success");
    return body;
  };

  const handleChangeRole = async (newRole) => {
    if (!selected) return;
    setBusy("role");
    try {
      await _request({
        url:    `/iam/users/${selected.id}/role`,
        method: "PUT",
        body:   { role: newRole },
      }, `Role updated to ${newRole}`);
      await refetch();
    } catch { /* toast already shown */ }
    finally { setBusy(null); }
  };

  const handleToggleActive = (isActive) => {
    setConfirm({ kind: isActive ? "disable" : "enable", member: selected });
  };

  const handleRemove = () => {
    setConfirm({ kind: "remove", member: selected });
  };

  const performConfirmed = async () => {
    if (!confirm) return;
    const { kind, member } = confirm;
    const opMap = {
      disable: { url: `/iam/users/${member.id}/disable`, busy: "toggle", msg: "Member disabled" },
      enable:  { url: `/iam/users/${member.id}/enable`,  busy: "toggle", msg: "Member enabled" },
      remove:  { url: `/iam/users/${member.id}/remove`,  busy: "remove", msg: "Member removed" },
    };
    const op = opMap[kind];
    setBusy(op.busy);
    try {
      await _request({ url: op.url, method: "POST" }, op.msg);
      await refetch();
      // For remove, close the drawer since the row is now soft-gone.
      if (kind === "remove") setSelectedId(null);
      setConfirm(null);
    } catch { /* keep dialog open so user can read the toast / retry */ }
    finally { setBusy(null); }
  };

  const columns = [
    { key: "user", header: "Member", sortable: true,
      accessor: (row) => (row.name || row.email || "").toLowerCase(),
      render: (row) => (
        <div style={{ display: "flex", alignItems: "center", gap: SPACE.md }}>
          <Avatar name={row.name} email={row.email} size="sm" />
          <div style={{ minWidth: 0 }}>
            <div style={{ color: COLORS.text, fontWeight: TYPO.weightMedium }}>
              {row.name || row.email}
            </div>
            {row.name && (
              <div style={{ color: COLORS.textMuted, fontSize: TYPO.sizeXs }}>
                {row.email}
              </div>
            )}
          </div>
        </div>
      ),
    },
    { key: "email", header: "Email", sortable: true,
      accessor: (row) => (row.email || "").toLowerCase(),
      render: (row) => (
        <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          {row.email}
        </span>
      ),
    },
    { key: "role", header: "Role",
      render: (row) => {
        const name = primaryRoleName(row);
        return name ? <Pill tone={roleTone(name)}>{name}</Pill>
                    : <span style={{ color: COLORS.textSubtle }}>—</span>;
      },
    },
    { key: "status", header: "Status",
      render: (row) => <Pill tone={statusTone(row)}>{statusLabel(row)}</Pill>,
    },
    { key: "last_login", header: "Last login", sortable: true,
      accessor: (row) => row.last_login ? Date.parse(row.last_login) : 0,
      render: (row) => <RelativeTime value={row.last_login} fallback="never" />,
    },
  ];

  return (
    <div style={{ padding: SPACE.xl }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: SPACE.lg,
        marginBottom: SPACE.lg,
      }}>
        <div style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          {loading ? "Loading…"
                   : `${members.length} member${members.length === 1 ? "" : "s"}`}
        </div>
        <Button
          variant="ghost"
          size="sm"
          leadingIcon={<RefreshCw size={14} />}
          onClick={() => refetch()}
          disabled={loading}
        >
          Refresh
        </Button>
      </div>

      <Table
        columns={columns}
        data={members}
        rowKey="id"
        loading={loading}
        defaultSortKey="user"
        onRowClick={(row) => setSelectedId(row.id)}
        empty={
          error ? (
            <EmptyState
              icon={<Users size={36} />}
              title="Could not load members"
              message={error.message || "Please retry."}
              action={<Button variant="secondary" size="sm" onClick={() => refetch()}>Retry</Button>}
            />
          ) : (
            <EmptyState
              icon={<Users size={36} />}
              title="No members yet"
              message="Invite teammates to collaborate."
            />
          )
        }
      />

      <MemberDetailDrawer
        member={selected}
        roles={roles}
        busy={busy}
        onClose={() => setSelectedId(null)}
        onChangeRole={handleChangeRole}
        onToggleActive={handleToggleActive}
        onRemove={handleRemove}
      />

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        onConfirm={performConfirmed}
        loading={busy === "toggle" || busy === "remove"}
        destructive={confirm?.kind === "remove" || confirm?.kind === "disable"}
        title={
          confirm?.kind === "remove"  ? "Remove member?"  :
          confirm?.kind === "disable" ? "Disable member?" :
          confirm?.kind === "enable"  ? "Enable member?"  : ""
        }
        message={
          confirm?.kind === "remove"
            ? `Remove ${confirm?.member?.email}? Their access is revoked immediately. Their record stays for audit; an admin can restore them later.`
          : confirm?.kind === "disable"
            ? `Disable ${confirm?.member?.email}? They lose access until re-enabled.`
          : confirm?.kind === "enable"
            ? `Re-enable ${confirm?.member?.email}? Their access resumes immediately.`
            : ""
        }
        confirmLabel={
          confirm?.kind === "remove"  ? "Remove" :
          confirm?.kind === "disable" ? "Disable" : "Enable"
        }
      />
    </div>
  );
}
