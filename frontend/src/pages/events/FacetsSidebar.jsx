import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Card from "../../components/Card";

function FacetGroup({ title, buckets, onPick }) {
  if (!buckets?.length) return null;
  const max = Math.max(...buckets.map((b) => b.count), 1);
  return (
    <div>
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h4>
      <ul className="space-y-1">
        {buckets.map((b) => (
          <li key={b.value}>
            <button
              onClick={() => onPick(b.value)}
              className="group flex w-full items-center justify-between gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-slate-700/50"
              title={`Filter to ${b.value}`}
            >
              <span className="min-w-0 flex-1">
                <span className="block truncate text-slate-300 group-hover:text-slate-100">{b.value}</span>
                <span
                  className="mt-0.5 block h-1 rounded-full bg-sky-500/40"
                  style={{ width: `${Math.max((b.count / max) * 100, 6)}%` }}
                />
              </span>
              <span className="shrink-0 text-slate-500">{b.count}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Top signatures / source IPs / destination IPs for the current filter set —
 * how an analyst finds the pattern without knowing what to search for.
 * Fetched as a separate request so a slow facet query never blocks the
 * result list itself.
 */
export default function FacetsSidebar({ filters, onPivot, refreshKey }) {
  const [facets, setFacets] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams();
    if (filters.from) params.set("from", filters.from);
    if (filters.to) params.set("to", filters.to);
    for (const s of filters.severity || []) params.append("severity", s);
    for (const t of filters.event_type || []) params.append("event_type", t);
    if (filters.ip) params.set("ip", filters.ip);
    if (filters.src_ip) params.set("src_ip", filters.src_ip);
    if (filters.dst_ip) params.set("dst_ip", filters.dst_ip);
    if (filters.q) params.set("q", filters.q);

    api
      .get(`/events/facets?${params}`)
      .then((data) => !cancelled && setFacets(data))
      .catch(() => !cancelled && setFacets(null));

    return () => {
      cancelled = true;
    };
    // refreshKey lets the parent force a re-fetch (e.g. after live-tail settles).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filters), refreshKey]);

  return (
    <Card title="Facets" className="sticky top-[calc(theme(spacing.topbar)+1rem)]" bodyClassName="space-y-4">
      {!facets && <p className="text-xs text-slate-500">Loading…</p>}
      {facets && (
        <>
          <FacetGroup
            title="Severity"
            buckets={facets.severity}
            onPick={(v) => onPivot({ severity: [v] })}
          />
          <FacetGroup
            title="Top signatures"
            buckets={facets.top_signatures}
            onPick={(v) => onPivot({ q: v })}
          />
          <FacetGroup
            title="Top source IPs"
            buckets={facets.top_src_ips}
            onPick={(v) => onPivot({ src_ip: `${v}/32` })}
          />
          <FacetGroup
            title="Top destination IPs"
            buckets={facets.top_dst_ips}
            onPick={(v) => onPivot({ dst_ip: `${v}/32` })}
          />
        </>
      )}
    </Card>
  );
}
