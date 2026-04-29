import React, { useEffect, useMemo } from "react";
import { KeyRound, RefreshCw, Check } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS } from "../../design/tokens";
import Pill from "../../ui/Pill";
import Button from "../../ui/Button";
import Spinner from "../../ui/Spinner";
import EmptyState from "../../ui/EmptyState";
import useApi from "../../ui/useApi";
import { roleTone } from "./MemberDetailDrawer";

// Phase G — read-only permission matrix. Backend
// GET /api/iam/permission-matrix returns {roles, permissions,
// grants}. Cells are ticked where (role_id, permission_id) appears
// in `grants`. Tier 1 v1 ships read-only; PATCH grant add/remove
// is on the v1.1 roadmap alongside custom-role CRUD.

// Display order overrides the backend's alphabetical sort so the
// table reads most-privileged → least-privileged top-to-bottom.
const ROLE_ORDER = ["owner", "admin", "analyst", "viewer"];

function _sortedRoles(roles) {
  // Stable: known roles by ROLE_ORDER, unknown roles appended in
  // alpha order so a future custom role appears in a predictable
  // slot.
  const known   = ROLE_ORDER
    .map((name) => roles.find((r) => r.name === name))
    .filter(Boolean);
  const unknown = roles
    .filter((r) => !ROLE_ORDER.includes(r.name))
    .sort((a, b) => a.name.localeCompare(b.name));
  return [...known, ...unknown];
}

// Permission names follow the convention <resource>:<action>.
// Splitting them stacks "resource" above "action" in each header
// cell so columns stay narrow without rotating the label.
function _splitPermName(name) {
  const idx = (name || "").indexOf(":");
  if (idx < 0) return { resource: name || "", action: "" };
  return {
    resource: (name || "").slice(0, idx),
    action:   (name || "").slice(idx + 1),
  };
}

export default function PermissionsTab({ showToast }) {
  const safeToast = showToast || (() => {});

  const { data, loading, error, refetch } = useApi("/iam/permission-matrix");

  useEffect(() => {
    if (error) safeToast(error.message || "Failed to load permission matrix", "error");
  }, [error, safeToast]);

  const roles       = data?.roles       || [];
  const permissions = data?.permissions || [];
  const grants      = data?.grants      || [];

  const sortedRoles = useMemo(() => _sortedRoles(roles), [roles]);

  // O(1) cell lookup. Backend returns {role_id, permission_id}
  // pairs; key the set on a "rid:pid" string.
  const grantSet = useMemo(() => {
    const s = new Set();
    for (const g of grants) {
      s.add(`${g.role_id}:${g.permission_id}`);
    }
    return s;
  }, [grants]);

  // Tier 1 v1 ships exactly four roles + ten permissions, but the
  // tab is shaped to grow with the backend without code changes.
  const totalCells = sortedRoles.length * permissions.length;
  const grantedCount = grants.length;

  if (loading) {
    return (
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: `${SPACE.giga}px ${SPACE.xl}px`,
      }}>
        <Spinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: SPACE.xl }}>
        <EmptyState
          icon={<KeyRound size={36} />}
          title="Could not load permission matrix"
          message={error.message || "Please retry."}
          action={
            <Button variant="secondary" size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }

  if (sortedRoles.length === 0 || permissions.length === 0) {
    return (
      <div style={{ padding: SPACE.xl }}>
        <EmptyState
          icon={<KeyRound size={36} />}
          title="Permission catalogue empty"
          message="The default role + permission set should auto-seed at startup. If this is empty, ask an administrator to re-run the seeding script."
        />
      </div>
    );
  }

  // Cell rendering helpers. The granted glyph carries colour but
  // also a screen-reader-friendly aria-label so a sighted user
  // sees a checkmark and an assistive-tech user hears
  // "granted" / "not granted".
  const _GrantedCell = () => (
    <span
      role="img"
      aria-label="granted"
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        color: COLORS.success,
      }}
    >
      <Check size={16} strokeWidth={2.5} />
    </span>
  );
  const _UngrantedCell = () => (
    <span
      role="img"
      aria-label="not granted"
      style={{ color: COLORS.textSubtle, fontSize: TYPO.sizeSm }}
    >
      ·
    </span>
  );

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
          {sortedRoles.length} role{sortedRoles.length === 1 ? "" : "s"}
          {" × "}
          {permissions.length} permission{permissions.length === 1 ? "" : "s"}
          {" — "}
          <span style={{ color: COLORS.text, fontWeight: TYPO.weightMedium }}>
            {grantedCount}/{totalCells}
          </span>{" "}
          granted
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

      {/* Horizontal scroll wrapper for narrow viewports. The matrix
          can outgrow a phone-width screen; scrolling the table is
          the v1 fallback. Sticky left column would be ideal v2. */}
      <div style={{
        overflowX: "auto",
        border: `1px solid ${COLORS.border}`,
        borderRadius: RADIUS.lg,
        background: COLORS.bgCard,
      }}>
        <table style={{
          width: "100%",
          borderCollapse: "separate",
          borderSpacing: 0,
          fontFamily: TYPO.family,
          minWidth: 640,
        }}>
          <thead>
            <tr>
              <th
                scope="col"
                style={{
                  textAlign: "left",
                  padding: `${SPACE.lg}px ${SPACE.xl}px`,
                  background: COLORS.bgRaised,
                  borderBottom: `1px solid ${COLORS.border}`,
                  color: COLORS.textMuted,
                  fontSize: TYPO.sizeXs,
                  fontWeight: TYPO.weightSemi,
                  letterSpacing: TYPO.trackWide,
                  textTransform: "uppercase",
                  whiteSpace: "nowrap",
                  position: "sticky",
                  top: 0,
                  zIndex: 1,
                }}
              >
                Role
              </th>
              {permissions.map((p) => {
                const parts = _splitPermName(p.name);
                return (
                  <th
                    key={p.id}
                    scope="col"
                    style={{
                      textAlign: "center",
                      padding: `${SPACE.md}px ${SPACE.md}px`,
                      background: COLORS.bgRaised,
                      borderBottom: `1px solid ${COLORS.border}`,
                      color: COLORS.text,
                      fontSize: TYPO.sizeXs,
                      fontWeight: TYPO.weightSemi,
                      letterSpacing: TYPO.trackWide,
                      whiteSpace: "nowrap",
                      position: "sticky",
                      top: 0,
                      zIndex: 1,
                    }}
                    title={p.name}
                  >
                    <div style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      gap: 2,
                      lineHeight: TYPO.leadingTight,
                    }}>
                      <span style={{
                        color: COLORS.textMuted,
                        textTransform: "lowercase",
                        fontWeight: TYPO.weightMedium,
                      }}>
                        {parts.resource}
                      </span>
                      <span style={{ color: COLORS.text }}>
                        {parts.action || "—"}
                      </span>
                    </div>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {sortedRoles.map((role) => {
              const isOwner = role.name === "owner";
              return (
                <tr key={role.id}
                    style={{
                      // Subtle tint on the owner row to signal the
                      // role-name bypass; non-owner rows stay flat.
                      background: isOwner ? COLORS.accentSoft : "transparent",
                    }}
                >
                  <th
                    scope="row"
                    style={{
                      textAlign: "left",
                      padding: `${SPACE.lg}px ${SPACE.xl}px`,
                      borderBottom: `1px solid ${COLORS.border}`,
                      whiteSpace: "nowrap",
                    }}
                  >
                    <div style={{
                      display: "flex",
                      alignItems: "center",
                      gap: SPACE.md,
                    }}>
                      <Pill tone={roleTone(role.name)}>{role.name}</Pill>
                    </div>
                  </th>
                  {permissions.map((p) => {
                    const granted = grantSet.has(`${role.id}:${p.id}`);
                    return (
                      <td
                        key={p.id}
                        style={{
                          textAlign: "center",
                          padding: `${SPACE.md}px ${SPACE.md}px`,
                          borderBottom: `1px solid ${COLORS.border}`,
                          verticalAlign: "middle",
                        }}
                      >
                        {granted ? <_GrantedCell /> : <_UngrantedCell />}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p style={{
        margin: `${SPACE.lg}px 0 0`,
        color: COLORS.textSubtle,
        fontSize: TYPO.sizeXs,
        lineHeight: TYPO.leadingNormal,
        maxWidth: 760,
      }}>
        <strong style={{ color: COLORS.textMuted }}>owner</strong> has full
        access via a role-name bypass in <code style={{
          fontFamily: TYPO.familyMono,
          color: COLORS.textMuted,
        }}>require_permission()</code> — the bypass is checked before the
        grants table. The matrix above shows the explicit grants exactly as
        stored; the bypass would also grant access to any future permission
        added to the catalogue, even if no grant row is added for the owner.
        Tier 1 v1 ships read-only; grant edits land in v1.1.
      </p>
    </div>
  );
}
