export const TTL_PRESETS = [
  { label: "15m", seconds: 15 * 60 },
  { label: "1h", seconds: 60 * 60 },
  { label: "4h", seconds: 4 * 60 * 60 },
  { label: "24h", seconds: 24 * 60 * 60 },
];

export const STATUS_TONE = {
  pending: "neutral",
  active: "success",
  expired: "neutral",
  revoked: "warning",
  failed: "danger",
};

/** A block wider than /29 (8 addresses) is a range, not a host — the UI
 * makes an operator type the target back to confirm they mean it. */
export function isWideCidr(target) {
  const [, prefixRaw] = target.split("/");
  if (prefixRaw === undefined) return false;
  const prefix = Number(prefixRaw);
  return Number.isFinite(prefix) && prefix < 29;
}

export function formatCountdown(seconds) {
  if (seconds == null || seconds <= 0) return "expired";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function directionLabel(direction) {
  return { inbound: "Inbound", outbound: "Outbound", both: "Both directions" }[direction] || direction;
}
