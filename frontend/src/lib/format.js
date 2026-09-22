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

/** "4.2 MB". Used by M9 report sizes and M11 capture/flow byte counts. */
export function formatBytes(bytes) {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

/** "1m 30ms" scale but for millisecond durations (M11 flow duration_ms). */
export function durationMs(ms) {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return duration(ms / 1000);
}
