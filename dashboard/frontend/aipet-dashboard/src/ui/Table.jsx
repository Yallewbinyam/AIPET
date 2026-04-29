import React, { useMemo, useState } from "react";
import { ChevronUp, ChevronDown, ChevronsUpDown } from "lucide-react";
import { COLORS, TYPO, SPACE, RADIUS, MOTION } from "../design/tokens";
import EmptyState from "./EmptyState";
import Spinner from "./Spinner";

// Generic, controlled table primitive.
//   columns = [{
//     key:        unique string used for sort + react keys
//     header:     ReactNode shown in the th
//     accessor:   row => cell value (used for default rendering + sort)
//     render?:    row => ReactNode (overrides accessor for cell)
//     sortable?:  boolean
//     align?:     'left' | 'center' | 'right'
//     width?:     css width
//   }]
// Sort is internal (single-column). For server-side sort, the
// caller can read `sortKey`/`sortDir` via `onSortChange` and
// manage `data` themselves.

function _resolveCell(col, row) {
  if (typeof col.render === "function") return col.render(row);
  if (typeof col.accessor === "function") return col.accessor(row);
  return row[col.key];
}

function _resolveSortValue(col, row) {
  if (typeof col.accessor === "function") return col.accessor(row);
  return row[col.key];
}

export default function Table({
  columns,
  data,
  rowKey = "id",
  onRowClick,
  loading = false,
  empty,
  defaultSortKey,
  defaultSortDir = "asc",
  onSortChange,
  hoverable = true,
  size = "md",
}) {
  const [sortKey, setSortKey] = useState(defaultSortKey);
  const [sortDir, setSortDir] = useState(defaultSortDir);
  const [hoverIdx, setHoverIdx] = useState(-1);

  const handleSort = (col) => {
    if (!col.sortable) return;
    const nextDir = sortKey === col.key && sortDir === "asc" ? "desc" : "asc";
    setSortKey(col.key);
    setSortDir(nextDir);
    if (onSortChange) onSortChange(col.key, nextDir);
  };

  const sorted = useMemo(() => {
    if (!sortKey) return data;
    const col = columns.find((c) => c.key === sortKey);
    if (!col) return data;
    const dir = sortDir === "desc" ? -1 : 1;
    return [...data].sort((a, b) => {
      const av = _resolveSortValue(col, a);
      const bv = _resolveSortValue(col, b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [data, columns, sortKey, sortDir]);

  const cellPad = size === "sm"
    ? `${SPACE.md}px ${SPACE.lg}px`
    : `${SPACE.lg}px ${SPACE.xl}px`;

  if (loading) {
    return (
      <div style={{
        display: "flex",
        justifyContent: "center",
        padding: `${SPACE.giga}px ${SPACE.xl}px`,
      }}>
        <Spinner size="lg" />
      </div>
    );
  }

  if (!data || data.length === 0) {
    return empty || (
      <EmptyState title="No data" message="There's nothing to show yet." />
    );
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{
        width: "100%",
        borderCollapse: "separate",
        borderSpacing: 0,
        fontFamily: TYPO.family,
      }}>
        <thead>
          <tr>
            {columns.map((col) => {
              const active = sortKey === col.key;
              const Caret = !col.sortable ? null
                : active && sortDir === "asc"  ? ChevronUp
                : active && sortDir === "desc" ? ChevronDown
                : ChevronsUpDown;
              return (
                <th
                  key={col.key}
                  scope="col"
                  onClick={() => handleSort(col)}
                  style={{
                    textAlign: col.align || "left",
                    padding: cellPad,
                    width: col.width,
                    color: active ? COLORS.text : COLORS.textMuted,
                    fontSize: TYPO.sizeXs,
                    fontWeight: TYPO.weightSemi,
                    letterSpacing: TYPO.trackWide,
                    textTransform: "uppercase",
                    background: COLORS.bgRaised,
                    borderBottom: `1px solid ${COLORS.border}`,
                    cursor: col.sortable ? "pointer" : "default",
                    userSelect: "none",
                    whiteSpace: "nowrap",
                    transition: MOTION.fast,
                    position: "sticky",
                    top: 0,
                  }}
                >
                  <span style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: SPACE.xs,
                  }}>
                    {col.header}
                    {Caret && <Caret size={12} />}
                  </span>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, idx) => (
            <tr
              key={row[rowKey] ?? idx}
              onMouseEnter={() => hoverable && setHoverIdx(idx)}
              onMouseLeave={() => hoverable && setHoverIdx(-1)}
              onClick={() => onRowClick && onRowClick(row)}
              style={{
                background: hoverable && hoverIdx === idx
                  ? COLORS.bgRaised
                  : "transparent",
                cursor: onRowClick ? "pointer" : "default",
                transition: MOTION.fast,
              }}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  style={{
                    padding: cellPad,
                    color: COLORS.text,
                    fontSize: TYPO.sizeSm,
                    borderBottom: `1px solid ${COLORS.border}`,
                    textAlign: col.align || "left",
                    width: col.width,
                    verticalAlign: "middle",
                  }}
                >
                  {_resolveCell(col, row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
