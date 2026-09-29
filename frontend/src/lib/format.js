/** Shared formatting helpers. Used from M3 onward by every data view. */

const RELATIVE_UNITS = [
  { limit: 60, divisor: 1, unit: "second" },
  { limit: 3600, divisor: 60, unit: "minute" },
  { limit: 86400, divisor: 3600, unit: "hour" },
  { limit: 2592000, divisor: 86400, unit: "day" },
  { limit: 31536000, divisor: 2592000, unit: "month" },
];

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** "3 minutes ago". Returns "—" for null so tables never print "Invalid Date". */
export function relativeTime(value) {
  if (!value) return "—";
  const then = new Date(value);
  if (Number.isNaN(then.getTime())) return "—";

  const seconds = (then.getTime() - Date.now()) / 1000;
  const magnitude = Math.abs(seconds);

  for (const { limit, divisor, unit } of RELATIVE_UNITS) {
    if (magnitude < limit) return rtf.format(Math.round(seconds / divisor), unit);
  }
  return rtf.format(Math.round(seconds / 31536000), "year");
}

export function absoluteTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function duration(seconds) {
  if (seconds == null) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
}
