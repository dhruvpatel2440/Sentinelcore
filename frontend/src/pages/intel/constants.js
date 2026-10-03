export const IOC_TYPES = ["ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "email"];

export const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];

export const SOURCE_FORMATS = ["csv", "json", "txt", "misp", "stix"];

export const SOURCE_STATUS_TONE = {
  ok: "success",
  error: "danger",
};

/** M6 event search pivot for an indicator value. */
export function eventSearchPivotUrl(value) {
  return `/events?q=${encodeURIComponent(value)}`;
}
