/**
 * fetch wrapper for the SentinelCore API.
 *
 * Two rules drive the design:
 *  1. The access token never touches localStorage. AuthContext holds it in
 *     React state and registers a getter here, so an XSS has nothing durable
 *     to steal.
 *  2. A 401 triggers exactly one refresh no matter how many requests hit it
 *     at once — the in-flight promise is shared.
 */

const BASE = "/api";

export class ApiError extends Error {
  constructor(status, message, detail) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }

  get isAuthError() {
    return this.status === 401;
  }

  get isForbidden() {
    return this.status === 403;
  }
}

// Wired up by AuthContext at mount. Kept module-level so any caller — including
// ones outside the React tree — goes through the same token and the same
// refresh lock.
let getToken = () => null;
let onRefreshed = () => {};
let onAuthLost = () => {};

export function configureAuth({ tokenGetter, onTokenRefreshed, onSessionLost }) {
  getToken = tokenGetter ?? (() => null);
  onRefreshed = onTokenRefreshed ?? (() => {});
  onAuthLost = onSessionLost ?? (() => {});
}

/** The single shared refresh promise. Non-null only while a refresh is running. */
let refreshInFlight = null;

export function refreshAccessToken() {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new ApiError(res.status, "Session expired", null);
    }
    const data = await res.json();
    onRefreshed(data);
    return data.access_token;
  })().finally(() => {
    // Cleared in `finally` so a failed refresh does not wedge every later
    // request onto a permanently rejected promise.
    refreshInFlight = null;
  });

  return refreshInFlight;
}

async function parseError(res) {
  let detail = null;
  let message = res.statusText || `Request failed (${res.status})`;
  try {
    const body = await res.json();
    detail = body?.detail ?? body;
    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail) && detail[0]?.msg) {
      message = detail[0].msg; // FastAPI validation error shape
    }
  } catch {
    // Non-JSON error body (nginx 502, proxy timeout) — keep the status text.
  }
  return new ApiError(res.status, message, detail);
}

async function send(path, { method = "GET", body, signal, headers = {} } = {}) {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: "include",
    signal,
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return res;
}

async function request(path, options = {}) {
  // The refresh endpoint itself must not recurse through this retry logic.
  const isAuthEndpoint = path.startsWith("/auth/refresh") || path.startsWith("/auth/login");

  let res = await send(path, options);

  if (res.status === 401 && !isAuthEndpoint) {
    try {
      await refreshAccessToken();
      res = await send(path, options); // replay with the new token
    } catch {
      onAuthLost();
      throw new ApiError(401, "Your session has expired. Please sign in again.", null);
    }
  }

  if (!res.ok) throw await parseError(res);

  if (res.status === 204) return null;
  const contentType = res.headers.get("content-type") || "";
  return contentType.includes("application/json") ? res.json() : res.text();
}

/**
 * Streams an authenticated file download (reports, pcap, …) as a blob rather
 * than JSON. Shares the token/refresh logic with `request()` because a
 * download hitting a stale access token should retry exactly like any other
 * call, not surface a raw 401 to the user.
 */
export async function downloadFile(path) {
  const attempt = () => {
    const token = getToken();
    return fetch(`${BASE}${path}`, {
      credentials: "include",
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
  };

  let res = await attempt();
  if (res.status === 401) {
    try {
      await refreshAccessToken();
      res = await attempt();
    } catch {
      onAuthLost();
      throw new ApiError(401, "Your session has expired. Please sign in again.", null);
    }
  }
  if (!res.ok) throw await parseError(res);

  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return { blob: await res.blob(), filename: match?.[1] || "download" };
}

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  get: (path, options) => request(path, { ...options, method: "GET" }),
  post: (path, body, options) => request(path, { ...options, method: "POST", body }),
  patch: (path, body, options) => request(path, { ...options, method: "PATCH", body }),
  put: (path, body, options) => request(path, { ...options, method: "PUT", body }),
  del: (path, options) => request(path, { ...options, method: "DELETE" }),
};

export default api;
