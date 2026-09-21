/**
 * URL <-> filter-object mapping for M6 event search, plus the time-range
 * presets. Every filter lives in the query string so a pasted link
 * reproduces the exact result set — presets resolve to concrete ISO
 * timestamps at click time rather than staying relative, so "last 24h"
 * clicked now and the same link opened later both hit the same window.
 */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const EVENT_TYPES = ["alert", "flow", "dns", "http", "tls"];

export const RANGE_PRESETS = [
  { key: "15m", label: "Last 15m", ms: 15 * 60 * 1000 },
  { key: "1h", label: "Last 1h", ms: 60 * 60 * 1000 },
  { key: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "Last 7d", ms: 7 * 24 * 60 * 60 * 1000 },
];

const MULTI_KEYS = ["severity", "event_type"];
const SCALAR_KEYS = ["from", "to", "src_ip", "dst_ip", "ip", "port", "proto", "q", "asset_id"];

export function defaultFilters() {
  const to = new Date();
  const from = new Date(to.getTime() - RANGE_PRESETS[2].ms); // 24h
  return { from: from.toISOString(), to: to.toISOString(), severity: [], event_type: [] };
}

export function filtersFromSearchParams(params) {
  const filters = {};
  for (const key of SCALAR_KEYS) {
    const v = params.get(key);
    if (v) filters[key] = v;
  }
  for (const key of MULTI_KEYS) {
    const v = params.getAll(key);
    if (v.length) filters[key] = v;
  }
  if (!filters.from || !filters.to) {
    return { ...defaultFilters(), ...filters };
  }
  return filters;
}

export function filtersToSearchParams(filters) {
  const params = new URLSearchParams();
  for (const key of SCALAR_KEYS) {
    if (filters[key]) params.set(key, filters[key]);
  }
  for (const key of MULTI_KEYS) {
    for (const v of filters[key] || []) params.append(key, v);
  }
  return params;
}

export function applyPreset(presetKey) {
  const preset = RANGE_PRESETS.find((p) => p.key === presetKey);
  if (!preset) return null;
  const to = new Date();
  const from = new Date(to.getTime() - preset.ms);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** Loose client-side CIDR/IP check so the request never fires with garbage. */
export function isValidCidrOrIp(value) {
  if (!value) return true;
  const [addr, prefix] = value.split("/");
  const octets = addr.split(".");
  if (octets.length !== 4) return false;
  if (!octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return false;
  if (prefix !== undefined && !/^\d{1,2}$/.test(prefix)) return false;
  if (prefix !== undefined && Number(prefix) > 32) return false;
  return true;
}

export function activeFilterPills(filters) {
  const pills = [];
  for (const s of filters.severity || []) pills.push({ key: `severity:${s}`, label: `severity: ${s}`, remove: () => ({ field: "severity", value: s }) });
  for (const t of filters.event_type || []) pills.push({ key: `event_type:${t}`, label: `type: ${t}`, remove: () => ({ field: "event_type", value: t }) });
  if (filters.ip) pills.push({ key: "ip", label: `ip: ${filters.ip}`, remove: () => ({ field: "ip" }) });
  if (filters.src_ip) pills.push({ key: "src_ip", label: `src: ${filters.src_ip}`, remove: () => ({ field: "src_ip" }) });
  if (filters.dst_ip) pills.push({ key: "dst_ip", label: `dst: ${filters.dst_ip}`, remove: () => ({ field: "dst_ip" }) });
  if (filters.port) pills.push({ key: "port", label: `port: ${filters.port}`, remove: () => ({ field: "port" }) });
  if (filters.proto) pills.push({ key: "proto", label: `proto: ${filters.proto}`, remove: () => ({ field: "proto" }) });
  if (filters.q) pills.push({ key: "q", label: `"${filters.q}"`, remove: () => ({ field: "q" }) });
  return pills;
}
