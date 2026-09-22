export const STATUS_TONE = {
  uploaded: "neutral",
  parsing: "accent",
  parsed: "success",
  failed: "danger",
};

export const STATUS_LABEL = {
  uploaded: "Queued",
  parsing: "Parsing",
  parsed: "Parsed",
  failed: "Failed",
};

export const ARTIFACT_TYPES = ["dns_query", "http_request", "tls_sni", "credential", "file_transfer", "user_agent"];

export const ARTIFACT_LABEL = {
  dns_query: "DNS queries",
  http_request: "HTTP requests",
  tls_sni: "TLS SNI",
  credential: "Credentials",
  file_transfer: "File transfers",
  user_agent: "User agents",
};

/** Client-side pre-check only — the server validates by magic bytes regardless. */
export const ACCEPTED_EXTENSIONS = [".pcap", ".pcapng", ".cap"];

export function isLikelyPcapFilename(filename) {
  const lower = filename.toLowerCase();
  return ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/** M6 event search pivot for an artifact value — best-effort free-text search. */
export function eventSearchPivotUrl(value) {
  return `/events?q=${encodeURIComponent(value)}`;
}
