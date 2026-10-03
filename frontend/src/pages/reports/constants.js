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

export const CRON_PRESETS = [
  { cron: "0 8 * * 1", label: "Every Monday at 08:00 UTC" },
  { cron: "0 6 * * *", label: "Every day at 06:00 UTC" },
  { cron: "0 0 1 * *", label: "On the 1st of every month at 00:00 UTC" },
];

const DOW = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** Best-effort plain-language preview for the common cron shapes this UI offers. */
export function describeCron(cron) {
  const parts = (cron || "").trim().split(/\s+/);
  if (parts.length !== 5) return "Custom schedule";
  const [min, hour, dom, , dow] = parts;
  const time =
    /^\d+$/.test(min) && /^\d+$/.test(hour)
      ? `${hour.padStart(2, "0")}:${min.padStart(2, "0")} UTC`
      : null;
  if (!time) return "Custom schedule";
  if (dom === "*" && dow === "*") return `Every day at ${time}`;
  if (dom === "*" && /^\d+$/.test(dow)) return `Every ${DOW[Number(dow) % 7]} at ${time}`;
  if (/^\d+$/.test(dom) && dow === "*") return `Monthly on day ${dom} at ${time}`;
  return "Custom schedule";
}
