import React from "react";
import { Construction } from "lucide-react";
import EmptyState from "../../ui/EmptyState";

// Phase E placeholder. Wires up GET /api/iam/audit + filters +
// CSV export. Backend endpoints are already live (see commit
// 68533b9c).
export default function AuditTab() {
  return (
    <EmptyState
      icon={<Construction size={36} />}
      title="Coming soon"
      message="The Audit tab is in development. Filtered audit log + CSV export land in Phase E."
    />
  );
}
