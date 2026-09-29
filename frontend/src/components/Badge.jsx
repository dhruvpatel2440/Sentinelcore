import clsx from "clsx";

/**
 * Severity colours are defined once here and in tailwind.config.js.
 * M5 maps Suricata priority 1-4 onto these names; M7 scoring and M9 reports
 * reuse the same scale, so the whole platform agrees on what "high" looks like.
 */
const SEVERITY = {
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  high: "bg-orange-400/15 text-orange-300 ring-orange-400/30",
  medium: "bg-yellow-400/15 text-yellow-200 ring-yellow-400/30",
  low: "bg-sky-400/15 text-sky-300 ring-sky-400/30",
  info: "bg-slate-400/15 text-slate-300 ring-slate-400/30",
};

const TONE = {
  neutral: "bg-slate-700/50 text-slate-300 ring-slate-600",
  success: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  warning: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  danger: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  accent: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
};

export default function Badge({ severity, tone = "neutral", className, children }) {
  const palette = severity ? (SEVERITY[severity] ?? SEVERITY.info) : (TONE[tone] ?? TONE.neutral);

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        "ring-1 ring-inset whitespace-nowrap",
        palette,
        className,
      )}
    >
      {children ?? severity}
    </span>
  );
}

export { SEVERITY as SEVERITY_CLASSES };
