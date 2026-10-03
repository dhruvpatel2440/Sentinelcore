import { EVENT_TYPES, SEVERITIES } from "../events/filters";

const inputClass =
  "mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500";

/**
 * The `match` block editor: dropdowns/toggles for severity, event type,
 * signature id and CIDR scoping — the structured form the M7 spec asks for,
 * rather than making every admin hand-write JSON. Used for the rule's
 * top-level `match` and reusable for a sequence step.
 */
export default function MatchBlockEditor({ value, onChange, compact = false }) {
  const v = value || {};
  const set = (patch) => onChange({ ...v, ...patch });

  const toggle = (field, item) => {
    const current = v[field] || [];
    set({ [field]: current.includes(item) ? current.filter((x) => x !== item) : [...current, item] });
  };

  return (
    <div className={compact ? "space-y-2" : "space-y-3"}>
      <div>
        <label className="text-xs font-medium text-slate-300">Severity</label>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => toggle("severity", s)}
              className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${
                (v.severity || []).includes(s)
                  ? "bg-sky-500/20 text-sky-200 ring-sky-500/40"
                  : "bg-slate-800 text-slate-400 ring-slate-700"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="text-xs font-medium text-slate-300">Event type</label>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {EVENT_TYPES.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => toggle("event_type", t)}
              className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${
                (v.event_type || []).includes(t)
                  ? "bg-sky-500/20 text-sky-200 ring-sky-500/40"
                  : "bg-slate-800 text-slate-400 ring-slate-700"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="text-xs font-medium text-slate-300">Signature IDs (comma-separated)</label>
          <input
            className={inputClass}
            value={(v.signature_id || []).join(",")}
            onChange={(e) =>
              set({
                signature_id: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean)
                  .map(Number)
                  .filter((n) => !Number.isNaN(n)),
              })
            }
            placeholder="e.g. 2001219,2001220"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Category regex</label>
          <input
            className={inputClass}
            value={v.category_regex || ""}
            onChange={(e) => set({ category_regex: e.target.value || undefined })}
            placeholder="^trojan"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Source CIDR</label>
          <input
            className={inputClass}
            value={v.src_cidr || ""}
            onChange={(e) => set({ src_cidr: e.target.value || undefined })}
            placeholder="0.0.0.0/0"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Destination CIDR</label>
          <input
            className={inputClass}
            value={v.dst_cidr || ""}
            onChange={(e) => set({ dst_cidr: e.target.value || undefined })}
            placeholder="192.168.10.0/24"
          />
        </div>
      </div>
    </div>
  );
}
