import React, { useEffect, useMemo, useState } from "react";
import {
  FileText, RefreshCw, Download, ChevronLeft, ChevronRight, RotateCcw,
} from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../../design/tokens";
import Table from "../../ui/Table";
import Pill from "../../ui/Pill";
import Button from "../../ui/Button";
import EmptyState from "../../ui/EmptyState";
import RelativeTime from "../../ui/RelativeTime";
import useApi from "../../ui/useApi";

// Phase E — read-only audit log explorer. Backend
// GET /api/iam/audit and GET /api/iam/audit/export. Tier 1 v1
// ships filter + paginate + CSV; the underlying audit data is
// already populated by mutations across iam, auth, and the
// access flows.

const PER_PAGE = 25;

// Initial filter shape. Keeping action+resource as strings (not
// undefined) keeps controlled inputs stable.
const EMPTY_FILTERS = {
  action:   "",
  resource: "",
  since:    "",
  until:    "",
};

function _statusTone(status) {
  switch ((status || "").toLowerCase()) {
    case "success": return "success";
    case "blocked": return "warn";
    case "failed":  return "danger";
    default:        return "neutral";
  }
}

// Append a half-day to a YYYY-MM-DD date input so the user's
// "until" picks the END of the chosen day (else "until=2026-04-29"
// drops every event after 00:00 on the 29th).
function _expandUntil(dateStr) {
  if (!dateStr) return "";
  return `${dateStr}T23:59:59`;
}
function _expandSince(dateStr) {
  if (!dateStr) return "";
  return `${dateStr}T00:00:00`;
}

function _buildAuditUrl(filters, page) {
  const qp = new URLSearchParams();
  qp.set("page",     String(page));
  qp.set("per_page", String(PER_PAGE));
  if (filters.action)   qp.set("action",   filters.action);
  if (filters.resource) qp.set("resource", filters.resource);
  if (filters.since)    qp.set("since",    _expandSince(filters.since));
  if (filters.until)    qp.set("until",    _expandUntil(filters.until));
  return `/iam/audit?${qp.toString()}`;
}

function _buildExportUrl(filters) {
  const qp = new URLSearchParams();
  if (filters.action)   qp.set("action",   filters.action);
  if (filters.resource) qp.set("resource", filters.resource);
  if (filters.since)    qp.set("since",    _expandSince(filters.since));
  if (filters.until)    qp.set("until",    _expandUntil(filters.until));
  const qs = qp.toString();
  return qs ? `/api/iam/audit/export?${qs}` : "/api/iam/audit/export";
}

function _inputStyle() {
  return {
    background: COLORS.bgDeep,
    color: COLORS.text,
    border: `1px solid ${COLORS.border}`,
    borderRadius: RADIUS.md,
    padding: `${SPACE.sm}px ${SPACE.lg}px`,
    fontSize: TYPO.sizeSm,
    fontFamily: TYPO.family,
    minHeight: 32,
    outline: "none",
    transition: MOTION.fast,
    boxSizing: "border-box",
  };
}

export default function AuditTab({ showToast }) {
  const safeToast = showToast || (() => {});

  // Two state buckets: the filter the user is editing (controlled
  // inputs), and the filter that has been applied to the URL. Apply
  // happens on Filter button click or Enter -- typing into the
  // resource box doesn't fire a fetch on every keystroke.
  const [draft,    setDraft]    = useState(EMPTY_FILTERS);
  const [applied,  setApplied]  = useState(EMPTY_FILTERS);
  const [page,     setPage]     = useState(1);
  const [exporting, setExporting] = useState(false);

  const url = _buildAuditUrl(applied, page);
  const { data, loading, error, refetch } = useApi(url);

  const logs   = data?.logs  || [];
  const total  = data?.total ?? 0;
  const pages  = data?.pages ?? 1;

  useEffect(() => {
    if (error) safeToast(error.message || "Failed to load audit log", "error");
  }, [error, safeToast]);

  // Action dropdown options derived from the rows currently on
  // screen (PLB-17 will replace this with a backend-served full
  // vocabulary in v1.1). Sorted ASC so the dropdown is scannable
  // even when the page contains a wide mix of action codes.
  const dynamicActions = useMemo(() => {
    const set = new Set();
    for (const l of logs) {
      if (l.action) set.add(l.action);
    }
    // Always include the currently-applied action even if it isn't
    // on this page so the user can see what filter is active.
    if (applied.action) set.add(applied.action);
    return Array.from(set).sort();
  }, [logs, applied.action]);

  const applyDraft = () => {
    setApplied(draft);
    setPage(1);
  };

  const resetFilters = () => {
    setDraft(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
    setPage(1);
  };

  // CSV export. Backend caps at 10 000 rows and returns 400
  // export_too_large with body.matching_rows + body.limit when
  // exceeded. The user fixes that by narrowing filters; we
  // surface body.message verbatim.
  const handleExport = async () => {
    setExporting(true);
    let resp;
    try {
      const token = localStorage.getItem("aipet_token");
      resp = await fetch(_buildExportUrl(applied), {
        method:  "GET",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    } catch (netErr) {
      safeToast("Network error — please retry.", "error");
      setExporting(false);
      return;
    }
    if (!resp.ok) {
      // Try to read a JSON error body; if the server returned the
      // CSV stream by mistake or an HTML error page, fall back to
      // a status-tagged generic. Same string-coercion contract as
      // every other Phase F surface.
      let body = {};
      try { body = await resp.json(); } catch { /* not JSON */ }
      const raw = body.message || body.error;
      const msg = (typeof raw === "string" && raw.length > 0)
        ? raw
        : `Export failed (${resp.status}).`;
      safeToast(msg, "error");
      setExporting(false);
      return;
    }
    // 200 path: pull blob, save via temporary anchor.
    try {
      const blob = await resp.blob();
      const cd   = resp.headers.get("Content-Disposition") || "";
      // Match filename="..." OR filename=... -- backend always
      // quotes, but grandfather in the unquoted form just in case.
      const m = cd.match(/filename="?([^"]+)"?/i);
      const filename = (m && m[1]) || "audit_log.csv";
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
      safeToast("Audit log exported.", "success");
    } catch (e) {
      safeToast("Could not save the export.", "error");
    } finally {
      setExporting(false);
    }
  };

  const columns = useMemo(() => ([
    { key: "timestamp", header: "Timestamp", sortable: false,
      render: (row) => row.timestamp ? (
        <span title={row.timestamp}>
          <RelativeTime value={row.timestamp} />
        </span>
      ) : <span style={{ color: COLORS.textSubtle }}>—</span>,
    },
    { key: "user_id", header: "Actor",
      render: (row) => row.user_id != null ? (
        <span style={{ color: COLORS.textMuted, fontSize: TYPO.sizeSm }}>
          User #{row.user_id}
        </span>
      ) : <span style={{ color: COLORS.textSubtle }}>system</span>,
    },
    { key: "action", header: "Action",
      render: (row) => (
        <span style={{
          color: COLORS.text,
          fontFamily: TYPO.familyMono,
          fontSize: TYPO.sizeSm,
        }}>
          {row.action}
        </span>
      ),
    },
    { key: "resource", header: "Resource",
      render: (row) => (
        <span style={{
          color: COLORS.textMuted,
          fontFamily: TYPO.familyMono,
          fontSize: TYPO.sizeSm,
          maxWidth: 320,
          display: "inline-block",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          verticalAlign: "bottom",
        }} title={row.resource || ""}>
          {row.resource || "—"}
        </span>
      ),
    },
    { key: "status", header: "Status",
      render: (row) => row.status
        ? <Pill tone={_statusTone(row.status)}>{row.status}</Pill>
        : <span style={{ color: COLORS.textSubtle }}>—</span>,
    },
  ]), []);

  const _Label = ({ children }) => (
    <span style={{
      color: COLORS.textMuted,
      fontSize: TYPO.sizeXs,
      letterSpacing: TYPO.trackWide,
      textTransform: "uppercase",
      fontWeight: TYPO.weightSemi,
    }}>{children}</span>
  );

  return (
    <div style={{ padding: SPACE.xl }}>
      <div style={{
        display: "flex",
        flexWrap: "wrap",
        gap: SPACE.md,
        alignItems: "flex-end",
        marginBottom: SPACE.lg,
        background: COLORS.bgDeep,
        border: `1px solid ${COLORS.border}`,
        borderRadius: RADIUS.md,
        padding: SPACE.lg,
      }}>
        <label style={{ display: "grid", rowGap: SPACE.xs, minWidth: 160 }}>
          <_Label>Action</_Label>
          <select
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.target.value })}
            disabled={loading}
            style={_inputStyle()}
          >
            <option value="">Any action</option>
            {dynamicActions.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </label>

        <label style={{ display: "grid", rowGap: SPACE.xs, minWidth: 220 }}>
          <_Label>Resource contains</_Label>
          <input
            type="text"
            value={draft.resource}
            onChange={(e) => setDraft({ ...draft, resource: e.target.value })}
            onKeyDown={(e) => { if (e.key === "Enter") applyDraft(); }}
            disabled={loading}
            placeholder="e.g. invitation: or user:5"
            style={_inputStyle()}
          />
        </label>

        <label style={{ display: "grid", rowGap: SPACE.xs }}>
          <_Label>Since</_Label>
          <input
            type="date"
            value={draft.since}
            onChange={(e) => setDraft({ ...draft, since: e.target.value })}
            disabled={loading}
            style={_inputStyle()}
          />
        </label>

        <label style={{ display: "grid", rowGap: SPACE.xs }}>
          <_Label>Until</_Label>
          <input
            type="date"
            value={draft.until}
            onChange={(e) => setDraft({ ...draft, until: e.target.value })}
            disabled={loading}
            style={_inputStyle()}
          />
        </label>

        <div style={{ display: "flex", gap: SPACE.sm, alignItems: "center" }}>
          <Button
            variant="primary"
            size="sm"
            onClick={applyDraft}
            disabled={loading}
          >
            Apply
          </Button>
          <Button
            variant="ghost"
            size="sm"
            leadingIcon={<RotateCcw size={14} />}
            onClick={resetFilters}
            disabled={loading
                      || (draft === EMPTY_FILTERS && applied === EMPTY_FILTERS)}
          >
            Reset
          </Button>
        </div>
      </div>

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
                   : `${total} entr${total === 1 ? "y" : "ies"} matching`}
        </div>
        <div style={{ display: "flex", gap: SPACE.md, alignItems: "center" }}>
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
            variant="secondary"
            size="sm"
            leadingIcon={<Download size={14} />}
            onClick={handleExport}
            loading={exporting}
            disabled={loading || total === 0}
          >
            Export CSV
          </Button>
        </div>
      </div>

      <Table
        columns={columns}
        data={logs}
        rowKey="id"
        loading={loading}
        empty={
          error ? (
            <EmptyState
              icon={<FileText size={36} />}
              title="Could not load audit log"
              message={error.message || "Please retry."}
              action={
                <Button variant="secondary" size="sm" onClick={() => refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<FileText size={36} />}
              title="No audit entries match"
              message={
                applied !== EMPTY_FILTERS
                  ? "Try widening the filter or clearing it."
                  : "Once teammates start using the platform, their actions will appear here."
              }
              action={applied !== EMPTY_FILTERS ? (
                <Button variant="secondary" size="sm" onClick={resetFilters}>
                  Clear filters
                </Button>
              ) : null}
            />
          )
        }
      />

      {/* Pagination -- Prev / Page N of M / Next, no jump-to-page in v1. */}
      {total > 0 && pages > 1 && (
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: SPACE.md,
          marginTop: SPACE.lg,
          color: COLORS.textMuted,
          fontSize: TYPO.sizeSm,
        }}>
          <Button
            variant="ghost"
            size="sm"
            leadingIcon={<ChevronLeft size={14} />}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={loading || page <= 1}
          >
            Prev
          </Button>
          <span style={{ minWidth: 100, textAlign: "center" }}>
            Page {page} of {pages}
          </span>
          <Button
            variant="ghost"
            size="sm"
            trailingIcon={<ChevronRight size={14} />}
            onClick={() => setPage((p) => Math.min(pages, p + 1))}
            disabled={loading || page >= pages}
          >
            Next
          </Button>
        </div>
      )}

      <p style={{
        margin: `${SPACE.lg}px 0 0`,
        color: COLORS.textSubtle,
        fontSize: TYPO.sizeXs,
        lineHeight: TYPO.leadingNormal,
      }}>
        Action filter shows the codes present on the current page. The full
        action vocabulary will be served from a dedicated endpoint in v1.1
        (PLB-17). Times shown are relative; hover the timestamp for the exact
        ISO instant.
      </p>
    </div>
  );
}
