import { RANGE_PRESETS } from "../events/filters";

export const REPORT_TYPES = [
  {
    key: "incident_summary",
    label: "Incident summary",
    description: "Totals, MTTA/MTTR, top rules and assets over a window.",
    needsWindow: true,
    csv: true,
  },
  {
    key: "incident_detail",
    label: "Incident detail",
    description: "Single-incident post-mortem with full history and evidence.",
    needsWindow: false,
    needsIncident: true,
    csv: false,
  },
  {
    key: "asset_inventory",
    label: "Asset inventory",
    description: "Every asset, ports, risk flags, incident counts.",
    needsWindow: false,
    csv: true,
  },
  {
    key: "event_statistics",
    label: "Event statistics",
    description: "Volume, top signatures, sensor drop rate over a window.",
    needsWindow: true,
    csv: true,
  },
];

export const REPORT_TYPE_LABEL = Object.fromEntries(REPORT_TYPES.map((t) => [t.key, t.label]));

export const FORMATS = ["pdf", "csv", "json"];

export const STATUS_TONE = {
  queued: "neutral",
  running: "accent",
  completed: "success",
  failed: "danger",
};

export { RANGE_PRESETS };

export function formatBytes(bytes) {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

const DOW = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

const IST_OFFSET_MIN = 330;

/** Shifts a numeric minute/hour by `offsetMin`, carrying into the day fields.
 * Stored crons are UTC; the UI works in IST. */
function shiftCronParts({ min, hour, dom, dow }, offsetMin) {
  const total = Number(hour) * 60 + Number(min) + offsetMin;
  const dayShift = Math.floor(total / 1440);
  const wrapped = ((total % 1440) + 1440) % 1440;
  const shiftDom = (d) => {
    if (!/^\d+$/.test(d)) return d === "L" && dayShift > 0 ? "1" : d;
    const n = Number(d) + dayShift;
    return n < 1 ? "L" : String(n);
  };
  return {
    min: String(wrapped % 60),
    hour: String(Math.floor(wrapped / 60)),
    dom: shiftDom(dom),
    dow: /^\d+$/.test(dow) ? String((((Number(dow) + dayShift) % 7) + 7) % 7) : dow,
  };
}

/** IST wall-clock picker values -> UTC cron string. */
export function istToUtcCron({ min, hour, dom = "*", dow = "*" }) {
  const u = shiftCronParts({ min, hour, dom, dow }, -IST_OFFSET_MIN);
  return `${u.min} ${u.hour} ${u.dom} * ${u.dow}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// A cron with both the day-of-month and the month pinned to a number names one
// calendar date. The scheduler (backend/app/reports/scheduling.py) treats that
// shape as a one-shot and disables the schedule after its single run, so the
// UI's "Once" option and this constant have to agree on the shape.
// A leap year, so 29 Feb survives the IST<->UTC shift below.
const PIVOT_YEAR = 2024;

function isFixedDate(dom, month, dow) {
  return /^\d+$/.test(dom) && /^\d+$/.test(month) && dow === "*";
}

/** Does this UTC cron name a single calendar date? Mirrors `is_one_shot` in
 * backend/app/reports/scheduling.py. */
export function isOneShot(cron) {
  const parts = (cron || "").trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, month, dow] = parts;
  return /^\d+$/.test(min) && /^\d+$/.test(hour) && isFixedDate(dom, month, dow);
}

/** A pinned date+time, shifted by `offsetMin`, as a Date in the pivot year. */
function shiftFixedDate({ min, hour, dom, month }, offsetMin) {
  return new Date(
    Date.UTC(PIVOT_YEAR, Number(month) - 1, Number(dom), Number(hour), Number(min)) + offsetMin * 60_000
  );
}

/** An absolute instant -> a cron pinned to that UTC date (a one-shot). */
export function onceToUtcCron(isoInstant) {
  const d = new Date(isoInstant);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCMinutes()} ${d.getUTCHours()} ${d.getUTCDate()} ${d.getUTCMonth() + 1} *`;
}

/** A date+time typed as IST in the custom-cron box -> the UTC one-shot cron. */
export function fixedDateIstToUtc({ min, hour, dom, month }) {
  const u = shiftFixedDate({ min, hour, dom, month }, -IST_OFFSET_MIN);
  return `${u.getUTCMinutes()} ${u.getUTCHours()} ${u.getUTCDate()} ${u.getUTCMonth() + 1} *`;
}

/** Best-effort plain-language preview of a UTC cron, shown in IST. */
export function describeCron(cron) {
  const parts = (cron || "").trim().split(/\s+/);
  if (parts.length !== 5) return "Custom schedule";
  const [min, hour, dom, month, dow] = parts;
  if (!/^\d+$/.test(min) || !/^\d+$/.test(hour)) return "Custom schedule";
  if (isFixedDate(dom, month, dow)) {
    const d = shiftFixedDate({ min, hour, dom, month }, IST_OFFSET_MIN);
    const hhmm = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
    return `Once on ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} at ${hhmm} IST`;
  }
  if (month !== "*") return "Custom schedule";
  const i = shiftCronParts({ min, hour, dom, dow }, IST_OFFSET_MIN);
  const time = `${i.hour.padStart(2, "0")}:${i.min.padStart(2, "0")} IST`;
  if (i.dom === "*" && i.dow === "*") return `Every day at ${time}`;
  if (i.dom === "*" && /^\d+$/.test(i.dow)) return `Every ${DOW[Number(i.dow) % 7]} at ${time}`;
  if (/^\d+$/.test(i.dom) && i.dow === "*") return `Monthly on day ${i.dom} at ${time}`;
  return "Custom schedule";
}
