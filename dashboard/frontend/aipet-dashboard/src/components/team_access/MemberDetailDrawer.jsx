import React, { useEffect, useState } from "react";
import { UserMinus, UserCheck, UserX } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../../design/tokens";
import Drawer from "../../ui/Drawer";
import Pill from "../../ui/Pill";
import Avatar from "../../ui/Avatar";
import Button from "../../ui/Button";
import RelativeTime from "../../ui/RelativeTime";

// Right-side drawer for a single member. Owned by MembersTab,
// which passes the action callbacks. Kept presentational --
// network calls, confirm-dialog state, and refetch live in the
// parent so this file stays focused on layout.

function _primaryRoleName(member) {
  const roles = member?.roles || [];
  if (roles.length === 0) return null;
  const owner = roles.find((r) => r.name === "owner");
  return (owner || roles[0]).name;
}

function _roleTone(roleName) {
  switch (roleName) {
    case "owner":   return "accent";
    case "admin":   return "info";
    case "analyst": return "success";
    case "viewer":  return "neutral";
    default:        return "neutral";
  }
}

function _statusTone(member) {
  if (member.removed_at) return "danger";
  if (member.is_active === false) return "warn";
  return "success";
}

function _statusLabel(member) {
  if (member.removed_at) return "Removed";
  if (member.is_active === false) return "Disabled";
  return "Active";
}

function _Field({ label, value }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: SPACE.md }}>
      <dt style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>{label}</dt>
      <dd style={{ margin: 0, color: COLORS.text, fontSize: TYPO.sizeSm }}>{value}</dd>
    </div>
  );
}

function _RoleSelect({ currentRole, roles, disabled, onChange }) {
  const [picked, setPicked] = useState(currentRole || "");
  useEffect(() => { setPicked(currentRole || ""); }, [currentRole]);

  const handleChange = (e) => {
    const next = e.target.value;
    setPicked(next);
    if (next && next !== currentRole) onChange(next);
  };

  return (
    <label style={{ display: "grid", rowGap: SPACE.sm }}>
      <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>Role</span>
      <select
        value={picked}
        disabled={disabled}
        onChange={handleChange}
        style={{
          background: COLORS.bgDeep,
          color: COLORS.text,
          border: `1px solid ${COLORS.border}`,
          borderRadius: RADIUS.md,
          padding: `${SPACE.md}px ${SPACE.lg}px`,
          fontSize: TYPO.sizeBase,
          fontFamily: TYPO.family,
          minHeight: 38,
          outline: "none",
          transition: MOTION.fast,
        }}
      >
        {roles.map((r) => (
          <option key={r.id} value={r.name}>{r.name}</option>
        ))}
      </select>
    </label>
  );
}

export default function MemberDetailDrawer({
  member, roles, busy,
  onClose, onChangeRole, onToggleActive, onRemove,
}) {
  if (!member) return null;
  const currentRole = _primaryRoleName(member);
  const isActive    = member.is_active !== false && !member.removed_at;
  const isRemoved   = !!member.removed_at;

  return (
    <Drawer
      open
      onClose={busy ? undefined : onClose}
      dismissible={!busy}
      size="md"
      title={member.name || member.email}
      subtitle={member.email}
    >
      <div style={{
        display: "flex", alignItems: "center",
        gap: SPACE.lg, marginBottom: SPACE.xxl,
      }}>
        <Avatar name={member.name} email={member.email} size="lg" />
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", gap: SPACE.md, flexWrap: "wrap" }}>
            <Pill tone={_roleTone(currentRole)}>{currentRole || "no role"}</Pill>
            <Pill tone={_statusTone(member)}>{_statusLabel(member)}</Pill>
          </div>
          <div style={{
            color: COLORS.textMuted,
            fontSize: TYPO.sizeSm,
            marginTop: SPACE.md,
          }}>
            Joined <RelativeTime value={member.created_at} muted={false} />
          </div>
        </div>
      </div>

      <dl style={{ margin: 0, display: "grid", rowGap: SPACE.lg }}>
        <_Field label="Last login" value={
          <RelativeTime value={member.last_login} fallback="never" muted={false} />
        }/>
        <_Field label="Plan" value={member.plan || "—"} />
        <_Field label="Organisation" value={member.organisation || "—"} />
        {isRemoved && (
          <_Field label="Removed at" value={
            <RelativeTime value={member.removed_at} muted={false} />
          }/>
        )}
      </dl>

      <hr style={{
        border: 0,
        borderTop: `1px solid ${COLORS.border}`,
        margin: `${SPACE.xxl}px 0`,
      }}/>

      <div style={{ display: "grid", rowGap: SPACE.lg }}>
        <_RoleSelect
          currentRole={currentRole}
          roles={roles}
          disabled={isRemoved || busy}
          onChange={onChangeRole}
        />

        <div style={{ display: "flex", gap: SPACE.md, flexWrap: "wrap" }}>
          <Button
            variant="secondary"
            size="md"
            loading={busy === "toggle"}
            disabled={isRemoved || (busy && busy !== "toggle")}
            leadingIcon={isActive ? <UserX size={14}/> : <UserCheck size={14}/>}
            onClick={() => onToggleActive(isActive)}
          >
            {isActive ? "Disable" : "Enable"}
          </Button>
          <Button
            variant="danger"
            size="md"
            loading={busy === "remove"}
            disabled={isRemoved || (busy && busy !== "remove")}
            leadingIcon={<UserMinus size={14}/>}
            onClick={onRemove}
          >
            Remove
          </Button>
        </div>
      </div>
    </Drawer>
  );
}

// Internal helpers re-exported for MembersTab's table columns.
export { _primaryRoleName as primaryRoleName,
         _roleTone        as roleTone,
         _statusTone      as statusTone,
         _statusLabel     as statusLabel };
