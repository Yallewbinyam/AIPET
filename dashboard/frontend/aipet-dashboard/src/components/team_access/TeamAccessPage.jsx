import React, { useState } from "react";
import { Users, Shield, FileText, Mail, KeyRound } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../../design/tokens";
import MembersTab from "./MembersTab";
import RolesTab from "./RolesTab";
import AuditTab from "./AuditTab";
import InvitationsTab from "./InvitationsTab";
import PermissionsTab from "./PermissionsTab";

// Tab id -> { label, Icon, Component }. Matters in two places:
// the tab bar's render order and the TeamAccessPage state's
// default. Members + Invitations are write surfaces; Roles,
// Audit, and Permissions are read-only.
const TABS = [
  { id: "members",     label: "Members",     Icon: Users,    Component: MembersTab },
  { id: "roles",       label: "Roles",       Icon: Shield,   Component: RolesTab },
  { id: "permissions", label: "Permissions", Icon: KeyRound, Component: PermissionsTab },
  { id: "audit",       label: "Audit",       Icon: FileText, Component: AuditTab },
  { id: "invitations", label: "Invitations", Icon: Mail,     Component: InvitationsTab },
];

function _TabButton({ tab, active, onClick }) {
  const { Icon, label } = tab;
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: SPACE.md,
        background: "transparent",
        color: active ? COLORS.text : COLORS.textMuted,
        border: "none",
        borderBottom: `2px solid ${active ? COLORS.accent : "transparent"}`,
        padding: `${SPACE.lg}px ${SPACE.xl}px`,
        fontSize: TYPO.sizeBase,
        fontWeight: TYPO.weightMedium,
        fontFamily: TYPO.family,
        letterSpacing: TYPO.trackTight,
        cursor: "pointer",
        outline: "none",
        transition: MOTION.fast,
      }}
    >
      <Icon size={16} />
      {label}
    </button>
  );
}

export default function TeamAccessPage({ token, showToast }) {
  const [activeTab, setActiveTab] = useState("members");
  const tab = TABS.find((t) => t.id === activeTab) ?? TABS[0];
  const TabBody = tab.Component;

  return (
    <div
      style={{
        padding: `${SPACE.xxl}px ${SPACE.xxxl}px`,
        fontFamily: TYPO.family,
        color: COLORS.text,
        maxWidth: 1280,
        margin: "0 auto",
      }}
    >
      <header style={{ marginBottom: SPACE.xxl }}>
        <h1
          style={{
            margin: 0,
            fontSize: TYPO.sizeH1,
            fontWeight: TYPO.weightSemi,
            letterSpacing: TYPO.trackTight,
            color: COLORS.text,
          }}
        >
          Team &amp; Access
        </h1>
        <p
          style={{
            margin: `${SPACE.sm}px 0 0`,
            fontSize: TYPO.sizeMd,
            color: COLORS.textMuted,
            lineHeight: TYPO.leadingNormal,
            maxWidth: 720,
          }}
        >
          Manage your team members, roles, and audit history.
        </p>
      </header>

      <nav
        role="tablist"
        aria-label="Team &amp; Access sections"
        style={{
          display: "flex",
          gap: SPACE.xs,
          borderBottom: `1px solid ${COLORS.border}`,
          marginBottom: SPACE.xxl,
          background: COLORS.bgCard,
          borderRadius: `${RADIUS.lg}px ${RADIUS.lg}px 0 0`,
          overflowX: "auto",
        }}
      >
        {TABS.map((t) => (
          <_TabButton
            key={t.id}
            tab={t}
            active={t.id === activeTab}
            onClick={() => setActiveTab(t.id)}
          />
        ))}
      </nav>

      <section
        role="tabpanel"
        aria-label={tab.label}
        style={{
          background: COLORS.bgCard,
          border: `1px solid ${COLORS.border}`,
          borderRadius: RADIUS.lg,
          minHeight: 320,
        }}
      >
        <TabBody token={token} showToast={showToast} />
      </section>
    </div>
  );
}
