import React, { useEffect, useState } from "react";
import { COLORS, TYPO } from "../design/tokens";

// Relative time string ("3 minutes ago", "yesterday", "in 2h").
// Re-renders itself periodically so a long-mounted view stays
// honest. ISO strings, Date objects, and millisecond numbers all
// supported.

const MIN  = 60;
const HOUR = 60 * MIN;
const DAY  = 24 * HOUR;
const WEEK = 7  * DAY;

function _toMs(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number") return value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function _format(diffSeconds) {
  const past = diffSeconds >= 0;
  const sec  = Math.abs(diffSeconds);
  let n, unit;
  if (sec < 45)        return past ? "just now" : "in a moment";
  if (sec < 90)        { n = 1;                 unit = "minute"; }
  else if (sec < HOUR) { n = Math.round(sec / MIN);  unit = "minute"; }
  else if (sec < DAY)  { n = Math.round(sec / HOUR); unit = "hour"; }
  else if (sec < WEEK) { n = Math.round(sec / DAY);  unit = "day"; }
  else {
    const days = Math.round(sec / DAY);
    if (days < 60)  { n = Math.round(days / 7);  unit = "week"; }
    else if (days < 365) { n = Math.round(days / 30); unit = "month"; }
    else                 { n = Math.round(days / 365); unit = "year"; }
  }
  const plural = n === 1 ? "" : "s";
  return past ? `${n} ${unit}${plural} ago` : `in ${n} ${unit}${plural}`;
}

export default function RelativeTime({
  value, fallback = "—", title, muted = true, style, ...rest
}) {
  const [, force] = useState(0);
  useEffect(() => {
    const id = setInterval(() => force((n) => n + 1), 60_000);
    return () => clearInterval(id);
  }, []);

  const ms = _toMs(value);
  if (ms == null) {
    return <span style={{ color: COLORS.textSubtle, ...style }} {...rest}>{fallback}</span>;
  }
  const diffSeconds = Math.round((Date.now() - ms) / 1000);
  const text = _format(diffSeconds);
  return (
    <time
      dateTime={new Date(ms).toISOString()}
      title={title || new Date(ms).toLocaleString()}
      style={{
        color: muted ? COLORS.textMuted : COLORS.text,
        fontSize: TYPO.sizeSm,
        ...style,
      }}
      {...rest}
    >
      {text}
    </time>
  );
}
