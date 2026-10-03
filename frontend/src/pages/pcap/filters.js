/**
 * URL <-> filter-object mapping for the M11 flows table, mirroring
 * `pages/events/filters.js`. Every filter lives in the query string so a
 * pasted link reproduces the same flow list.
 */

const SCALAR_KEYS = ["ip", "protocol", "app_protocol"];

export function flowFiltersFromSearchParams(params) {
  const filters = {};
  for (const key of SCALAR_KEYS) {
    const v = params.get(key);
    if (v) filters[key] = v;
  }
  const sortKey = params.get("sort");
  const sortDir = params.get("dir");
  filters.sort = { key: sortKey || "byte_count", dir: sortDir || "desc" };
  const page = Number(params.get("page"));
  filters.page = Number.isFinite(page) && page > 0 ? page : 0;
  return filters;
}

export function flowFiltersToSearchParams(filters) {
  const params = new URLSearchParams();
  for (const key of SCALAR_KEYS) {
    if (filters[key]) params.set(key, filters[key]);
  }
  if (filters.sort?.key) params.set("sort", filters.sort.key);
  if (filters.sort?.dir) params.set("dir", filters.sort.dir);
  if (filters.page) params.set("page", String(filters.page));
  return params;
}
