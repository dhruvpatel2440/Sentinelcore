import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";

/**
 * Small filter bar for the flows table — ip / protocol / app_protocol.
 * Mirrors `pages/events/FilterBar.jsx`'s debounce-and-push-to-URL pattern
 * at a scale appropriate for three fields.
 */
export default function FlowFilterBar({ filters, onChange }) {
  const [ipDraft, setIpDraft] = useState(filters.ip || "");

  useEffect(() => setIpDraft(filters.ip || ""), [filters.ip]);

  useEffect(() => {
    const t = setTimeout(() => {
      if (ipDraft !== (filters.ip || "")) onChange({ ip: ipDraft || undefined });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ipDraft]);

  const pills = [];
  if (filters.ip) pills.push({ key: "ip", label: `ip: ${filters.ip}`, clear: () => onChange({ ip: undefined }) });
  if (filters.protocol) pills.push({ key: "protocol", label: `proto: ${filters.protocol}`, clear: () => onChange({ protocol: undefined }) });
  if (filters.app_protocol)
    pills.push({ key: "app_protocol", label: `app: ${filters.app_protocol}`, clear: () => onChange({ app_protocol: undefined }) });

  return (
    <div className="mb-3 space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[12rem]">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden="true" />
          <input
            value={ipDraft}
            onChange={(e) => setIpDraft(e.target.value)}
            placeholder="Filter by IP (either side)"
            aria-label="IP filter"
            className="w-full rounded-md border border-slate-700 bg-slate-900 py-1.5 pl-8 pr-2.5 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <select
          value={filters.protocol || ""}
          onChange={(e) => onChange({ protocol: e.target.value || undefined })}
          aria-label="Protocol filter"
          className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
        >
          <option value="">Any protocol</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>

        <input
          value={filters.app_protocol || ""}
          onChange={(e) => onChange({ app_protocol: e.target.value || undefined })}
          placeholder="App protocol (http, dns, tls…)"
          aria-label="App protocol filter"
          className="min-w-[12rem] rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
      </div>

      {pills.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {pills.map((pill) => (
            <button
              key={pill.key}
              onClick={pill.clear}
              className="flex items-center gap-1 rounded-full bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300 ring-1 ring-inset ring-slate-700 hover:bg-slate-700"
            >
              {pill.label}
              <X size={10} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
