import React from "react";
import { Construction } from "lucide-react";
import EmptyState from "../../ui/EmptyState";

// Phase F placeholder. POST/GET/resend/revoke for /api/iam/invitations
// (backend live as of commit 4bf89755).
export default function InvitationsTab() {
  return (
    <EmptyState
      icon={<Construction size={36} />}
      title="Coming soon"
      message="The Invitations tab is in development. Invite, resend, and revoke flows land in Phase F."
    />
  );
}
