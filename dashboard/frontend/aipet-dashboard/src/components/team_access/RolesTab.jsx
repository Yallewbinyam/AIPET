import React, { useEffect, useMemo } from "react";
import { Shield, RefreshCw } from "lucide-react";
import { COLORS, TYPO, SPACE } from "../../design/tokens";
import Table from "../../ui/Table";
import Pill from "../../ui/Pill";
import Button from "../../ui/Button";
import EmptyState from "../../ui/EmptyState";
import useApi from "../../ui/useApi";
import { roleTone } from "./MemberDetailDrawer";

// Phase D — read-only roles table. Backend GET /api/iam/roles
// returns a bare list of {id, name, description, permissions:[]}.
// Tier 1 v1 ships read-only; create/edit/delete come in v1.1.

// Permission chips are capped to keep the row scannable. The
// "+N more" pill is non-interactive in v1 -- click-to-expand
// to a permission popover is a v2 nicety.
const MAX_PERM_CHIPS = 5;

export default function RolesTab({ showToast }) {
  const safeToast = showToast || (() => {});

  const { data: rolesResp, loading, error, refetch } = useApi("/iam/roles");

  // Roles endpoint returns a bare list; tolerate a future
  // {roles: [...]} wrapper too so the tab survives a backend
  // shape evolution without crashing.
  const roles = Array.isArray(rolesResp)
    ? rolesResp
    : (rolesResp?.roles || []);

  // Surface a hook-level error once -- the EmptyState below also
  // renders a persistent message for the same condition.
  useEffect(() => {
    if (error) safeToast(error.message || "Failed to load roles", "error");
  }, [error, safeToast]);

  const columns = useMemo(() => ([
    { key: "name", header: "Name", sortable: true,
      accessor: (row) => (row.name || "").toLowerCase(),
      render: (row) => (
        <Pill tone={roleTone(row.name)}>{row.name}</Pill>
      ),
    },
    { key: "description", header: "Description",
      render: (row) => (
        <span style={{
          color: row.description ? COLORS.text : COLORS.textSubtle,
          fontSize: TYPO.sizeSm,
          lineHeight: TYPO.leadingNormal,
        }}>
          {row.description || "—"}
        </span>
      ),
    },
    { key: "permissions", header: "Permissions",
      render: (row) => {
        const perms = row.permissions || [];
        if (perms.length === 0) {
          return <span style={{ color: COLORS.textSubtle }}>none</span>;
        }
        const shown   = perms.slice(0, MAX_PERM_CHIPS);
        const hidden  = perms.length - shown.length;
        return (
          <div style={{
            display: "flex",
            flexWrap: "wrap",
            gap: SPACE.xs,
            alignItems: "center",
          }}>
            {shown.map((p) => (
              <Pill key={p} tone="neutral">{p}</Pill>
            ))}
            {hidden > 0 && (
              <Pill tone="neutral" title={perms.slice(MAX_PERM_CHIPS).join(", ")}>
                +{hidden} more
              </Pill>
            )}
          </div>
        );
      },
    },
    { key: "perm_count", header: "Count", sortable: true,
      accessor: (row) => (row.permissions || []).length,
      render: (row) => (
        <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          {(row.permissions || []).length}
        </span>
      ),
    },
  ]), []);

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
          {loading ? "Loading…" : `${roles.length} role${roles.length === 1 ? "" : "s"}`}
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
        data={roles}
        rowKey="id"
        loading={loading}
        defaultSortKey="name"
        defaultSortDir="asc"
        empty={
          error ? (
            <EmptyState
              icon={<Shield size={36} />}
              title="Could not load roles"
              message={error.message || "Please retry."}
              action={
                <Button variant="secondary" size="sm" onClick={() => refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<Shield size={36} />}
              title="No roles configured"
              message="The default role set should auto-seed at startup. If this is empty, ask an administrator to re-run the seeding script."
            />
          )
        }
      />

      <p style={{
        margin: `${SPACE.lg}px 0 0`,
        color: COLORS.textSubtle,
        fontSize: TYPO.sizeXs,
        lineHeight: TYPO.leadingNormal,
      }}>
        Tier 1 v1 ships read-only. Custom roles, permission edits, and per-tenant
        role overrides are tracked for v1.1.
      </p>
    </div>
  );
}
