import { Copy, GitBranch, Search } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Drawer from "../../components/Drawer";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-all text-sm text-slate-200">{children ?? "—"}</dd>
    </div>
  );
}

/**
 * Side drawer for a single event. `onPivot` receives a partial filter patch
 * (e.g. `{ ip: "10.0.0.5" }`) so the parent page can carry it into a new
 * search without this component knowing about URL state.
 */
export default function EventDetail({ eventId, eventTs, open, onClose, onPivot }) {
  const toast = useToast();
  const [event, setEvent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rawOpen, setRawOpen] = useState(false);

  useEffect(() => {
    if (!open || eventId == null) return undefined;
    let cancelled = false;
    setLoading(true);
    setRawOpen(false);
    // `ts` lets the backend prune to a single partition instead of scanning
    // every monthly partition for an id-only lookup.
    const query = eventTs ? `?ts=${encodeURIComponent(eventTs)}` : "";
    api
      .get(`/events/${eventId}${query}`)
      .then((data) => !cancelled && setEvent(data))
      .catch((err) => !cancelled && toast.error(err.message || "Could not load event"))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [eventId, eventTs, open, toast]);

  const copyRaw = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(event.raw, null, 2));
      toast.success("Raw event copied");
    } catch {
      toast.error("Clipboard unavailable");
    }
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={event?.signature || "Event"}
      description={event ? absoluteTime(event.ts) : undefined}
    >
      {loading && <p className="text-sm text-slate-400">Loading…</p>}

      {!loading && event && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <Badge severity={event.severity} />
            <Badge tone="neutral">{event.event_type}</Badge>
            {event.signature_id && (
              <Badge tone="accent" title="Times this signature fired in the last 24h">
                sid {event.signature_id} · {event.signature_24h_count}/24h
              </Badge>
            )}
          </div>

          <dl className="grid grid-cols-2 gap-4">
            <Field label="Source">
              <button
                className="hover:underline"
                onClick={() => onPivot?.({ src_ip: `${event.src_ip}/32` })}
              >
                {event.src_ip}
                {event.src_port ? `:${event.src_port}` : ""}
              </button>
              {event.src_asset && (
                <div className="text-xs text-slate-500">
                  {event.src_asset.hostname_override || event.src_asset.hostname || "known asset"}
                </div>
              )}
            </Field>
            <Field label="Destination">
              <button
                className="hover:underline"
                onClick={() => onPivot?.({ dst_ip: `${event.dst_ip}/32` })}
              >
                {event.dst_ip}
                {event.dst_port ? `:${event.dst_port}` : ""}
              </button>
              {event.dst_asset && (
                <div className="text-xs text-slate-500">
                  {event.dst_asset.hostname_override || event.dst_asset.hostname || "known asset"}
                </div>
              )}
            </Field>
            <Field label="Protocol">{event.proto}</Field>
            <Field label="Category">{event.category}</Field>
            <Field label="Timestamp">{absoluteTime(event.ts)}</Field>
            <Field label="Ingested">{relativeTime(event.ingested_at)}</Field>
          </dl>

          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" icon={Search} onClick={() => onPivot?.({ ip: `${event.src_ip}/32` })}>
              All events from this IP
            </Button>
            {event.signature_id && (
              <Button
                size="sm"
                variant="secondary"
                icon={Search}
                onClick={() => onPivot?.({ q: event.signature })}
              >
                All events for this signature
              </Button>
            )}
          </div>

          {event.related_flow_events.length > 0 && (
            <div>
              <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
                <GitBranch size={12} /> Related flow events ({event.related_flow_events.length})
              </h4>
              <div className="space-y-1.5 rounded-md border border-slate-700 bg-slate-900/50 p-2">
                {event.related_flow_events.map((r) => (
                  <div key={r.id} className="flex items-center justify-between gap-2 text-xs">
                    <span className="flex items-center gap-1.5">
                      <Badge severity={r.severity} className="!px-1.5 !py-0" />
                      <span className="text-slate-300">{r.event_type}</span>
                    </span>
                    <span className="truncate text-slate-500">{r.signature || "—"}</span>
                    <span className="shrink-0 text-slate-500">{relativeTime(r.ts)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <button
              type="button"
              onClick={() => setRawOpen((v) => !v)}
              className="text-xs font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200"
            >
              {rawOpen ? "▼" : "▶"} Raw event
            </button>
            {rawOpen && (
              <div className="relative mt-2">
                <button
                  onClick={copyRaw}
                  aria-label="Copy raw event JSON"
                  className="absolute right-2 top-2 rounded bg-slate-800 p-1 text-slate-400 hover:text-slate-100"
                >
                  <Copy size={12} />
                </button>
                <pre className="max-h-80 overflow-auto rounded-md border border-slate-700 bg-slate-950 p-3 text-xs text-slate-300">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </Drawer>
  );
}
