import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import Badge from "../../components/Badge";
import { EVENT_TYPES, RANGE_PRESETS, SEVERITIES, activeFilterPills, isValidCidrOrIp } from "./filters";

const SEVERITY_TONE = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

function toLocalInputValue(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Sticky filter bar: time presets, severity chips, IP/CIDR, free text,
 * and the active-filter pill row. Every change is pushed straight to the
 * parent's URL-backed filter state — this component holds no filter state
 * of its own besides local input drafts (q debounce, IP validation message).
 */
export default function FilterBar({ filters, onChange, onApplyPreset, activeRange }) {
  const [qDraft, setQDraft] = useState(filters.q || "");
  const [ipDraft, setIpDraft] = useState(filters.ip || "");
  const [ipError, setIpError] = useState(null);

  useEffect(() => setQDraft(filters.q || ""), [filters.q]);
  useEffect(() => setIpDraft(filters.ip || ""), [filters.ip]);

  useEffect(() => {
    const t = setTimeout(() => {
      if (qDraft !== (filters.q || "")) onChange({ q: qDraft || undefined });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDraft]);

  const commitIp = () => {
    if (!isValidCidrOrIp(ipDraft)) {
      setIpError("Not a valid IP or CIDR, e.g. 192.168.10.0/24");
      return;
    }
    setIpError(null);
    onChange({ ip: ipDraft || undefined });
  };

  const toggleSeverity = (s) => {
    const current = filters.severity || [];
    onChange({
      severity: current.includes(s) ? current.filter((x) => x !== s) : [...current, s],
    });
  };

  const toggleEventType = (t) => {
    const current = filters.event_type || [];
    onChange({
      event_type: current.includes(t) ? current.filter((x) => x !== t) : [...current, t],
    });
  };

  const pills = activeFilterPills(filters);
  const removePill = (pill) => {
    const { field, value } = pill.remove();
    if (value !== undefined) {
      onChange({ [field]: (filters[field] || []).filter((v) => v !== value) });
    } else {
      onChange({ [field]: undefined });
    }
  };

  return (
    <div className="sticky top-[calc(theme(spacing.topbar))] z-10 -mx-4 mb-4 space-y-3 border-b border-slate-800 bg-slate-900/95 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6">
      <div className="flex flex-wrap items-center gap-2">
        {RANGE_PRESETS.map((p) => (
          <button
            key={p.key}
            onClick={() => onApplyPreset(p.key)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              activeRange === p.key
                ? "bg-sky-600 text-white"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {p.label}
          </button>
        ))}

        <div className="flex items-center gap-1.5 text-xs text-slate-400">
          <input
            type="datetime-local"
            aria-label="Custom range start"
            value={toLocalInputValue(filters.from)}
            onChange={(e) =>
              onChange({ from: e.target.value ? new Date(e.target.value).toISOString() : undefined })
            }
            className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          />
          <span>to</span>
          <input
            type="datetime-local"
            aria-label="Custom range end"
            value={toLocalInputValue(filters.to)}
            onChange={(e) =>
              onChange({ to: e.target.value ? new Date(e.target.value).toISOString() : undefined })
            }
            className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => {
            const active = (filters.severity || []).includes(s);
            return (
              <button key={s} onClick={() => toggleSeverity(s)} className={active ? "" : "opacity-50 hover:opacity-100"}>
                <Badge severity={s} className={active ? "ring-2" : undefined}>
                  {s}
                </Badge>
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap gap-1.5">
          {EVENT_TYPES.map((t) => {
            const active = (filters.event_type || []).includes(t);
            return (
              <button
                key={t}
                onClick={() => toggleEventType(t)}
                className={
                  active
                    ? "rounded-full bg-sky-500/20 px-2 py-0.5 text-xs font-medium text-sky-200 ring-1 ring-inset ring-sky-500/40"
                    : "rounded-full bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-400 ring-1 ring-inset ring-slate-700 hover:text-slate-200"
                }
              >
                {t}
              </button>
            );
          })}
        </div>

        <div className="min-w-[12rem]">
          <div className="flex items-center gap-1">
            <input
              value={ipDraft}
              onChange={(e) => setIpDraft(e.target.value)}
              onBlur={commitIp}
              onKeyDown={(e) => e.key === "Enter" && commitIp()}
              placeholder="IP or CIDR (either side)"
              aria-label="IP or CIDR filter"
              className={`w-full rounded-md border bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 ${
                ipError ? "border-rose-500 focus:ring-rose-500" : "border-slate-700 focus:border-sky-500 focus:ring-sky-500"
              }`}
            />
          </div>
          {ipError && <p className="mt-1 text-[11px] text-rose-400">{ipError}</p>}
        </div>

        <div className="relative min-w-[14rem] flex-1">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden="true" />
          <input
            value={qDraft}
            onChange={(e) => setQDraft(e.target.value)}
            placeholder="Search signature or category…"
            aria-label="Free text search"
            className="w-full rounded-md border border-slate-700 bg-slate-900 py-1.5 pl-8 pr-2.5 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>
      </div>

      {pills.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {pills.map((pill) => (
            <button
              key={pill.key}
              onClick={() => removePill(pill)}
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
