import React from "react";
import { Construction } from "lucide-react";
import EmptyState from "../../ui/EmptyState";

// Phase D placeholder. Will host the permission matrix
// (GET /api/iam/permission-matrix) plus per-role detail panel.
export default function RolesTab() {
  return (
    <EmptyState
      icon={<Construction size={36} />}
      title="Coming soon"
      message="The Roles tab is in development. The permission matrix (read-only in v1) and role-detail drawer land in Phase D."
    />
  );
}
