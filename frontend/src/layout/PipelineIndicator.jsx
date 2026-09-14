import { AlertTriangle, Database } from "lucide-react";
import { useEffect, useState } from "react";

import clsx from "clsx";

import { api } from "../api/client";

const POLL_INTERVAL_MS = 30_000;

/**
 * Pipeline health in the top bar.
 *
 * The two signals worth surfacing are lag and time-since-last-event: a
 * pipeline can look busy while running an hour behind, or sit at zero lag
 * because the sensor has gone blind. Both mean "you are not seeing attacks".
 */
export default function PipelineIndicator() {
  const [status, setStatus] = useState(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let timer;

    const poll = async () => {
      try {
        const data = await api.get("/pipeline/status");
        if (!cancelled) {
          setStatus(data);
          setFailed(false);
        }
      } catch {
        if (!cancelled) setFailed(true);
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

  if (failed || !status) return null;
  if (!status.stalled) {
    return (
      <span
        className="hidden items-center gap-1.5 text-xs text-slate-500 xl:flex"
        title={`${status.events_per_second}/s · lag ${status.stream_length} · ${status.total_events} events`}
      >
        <Database size={13} aria-hidden="true" />
        {status.events_per_second}/s
      </span>
    );
  }

  return (
    <span
      className={clsx(
        "flex items-center gap-1.5 rounded-md px-2 py-1 text-xs",
        "bg-amber-500/10 text-amber-300 ring-1 ring-inset ring-amber-500/30",
      )}
      title={status.stall_reason ?? "Pipeline is stalled"}
    >
      <AlertTriangle size={13} aria-hidden="true" />
      <span className="hidden sm:inline">Pipeline stalled</span>
    </span>
  );
}
