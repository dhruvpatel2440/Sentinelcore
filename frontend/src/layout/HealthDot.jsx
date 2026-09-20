import { useEffect, useState } from "react";

import clsx from "clsx";

const POLL_INTERVAL_MS = 30_000;

const STATES = {
  ok: { dot: "bg-emerald-400", label: "Backend reachable" },
  degraded: { dot: "bg-amber-400", label: "Backend degraded" },
  down: { dot: "bg-rose-500", label: "Backend unreachable" },
  unknown: { dot: "bg-slate-500", label: "Checking backend…" },
};

/**
 * Backend liveness indicator. Uses plain fetch rather than the API client on
 * purpose: health must stay readable when the session is expired, and a 401
 * here should never trigger a token refresh.
 */
export default function HealthDot() {
  const [state, setState] = useState("unknown");

  useEffect(() => {
    let cancelled = false;
    let timer;

    const poll = async () => {
      try {
        const res = await fetch("/api/health", { cache: "no-store" });
        const body = res.ok ? await res.json() : null;
        if (!cancelled) setState(body?.status === "ok" ? "ok" : "degraded");
      } catch {
        if (!cancelled) setState("down");
      } finally {
        if (!cancelled) timer = setTimeout(poll, POLL_INTERVAL_MS);
      }
    };

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  const meta = STATES[state] ?? STATES.unknown;

  return (
    <span className="flex items-center gap-2" title={meta.label}>
      <span className={clsx("h-2 w-2 rounded-full", meta.dot)} aria-hidden="true" />
      <span className="sr-only">{meta.label}</span>
      <span className="hidden text-xs text-slate-400 lg:inline">
        {state === "ok" ? "Healthy" : meta.label}
      </span>
    </span>
  );
}
