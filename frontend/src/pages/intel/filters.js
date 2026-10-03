/** URL <-> filter-object mapping for the M12 IOC table, mirroring M6's pattern. */

const SCALAR_KEYS = ["ioc_type", "severity", "source_id", "threat_type", "tag", "q"];

export function iocFiltersFromSearchParams(params) {
  const filters = {};
  for (const key of SCALAR_KEYS) {
    const v = params.get(key);
    if (v) filters[key] = v;
  }
  const isActive = params.get("is_active");
  if (isActive) filters.is_active = isActive === "true";
  return filters;
}

export function iocFiltersToSearchParams(filters) {
  const params = new URLSearchParams();
  for (const key of SCALAR_KEYS) {
    if (filters[key]) params.set(key, filters[key]);
  }
  if (filters.is_active !== undefined) params.set("is_active", String(filters.is_active));
  return params;
}
