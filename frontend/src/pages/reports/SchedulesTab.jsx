import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, fromISTInputValue, relativeTime, toISTInputValue } from "../../lib/format";
import {
  FORMATS,
  REPORT_TYPE_LABEL,
  REPORT_TYPES,
  describeCron,
  fixedDateIstToUtc,
  isOneShot,
  istToUtcCron,
  onceToUtcCron,
} from "./constants";

const RELATIVE_WINDOWS = ["last_7_days", "last_30_days", "last_90_days"];

const DOW_OPTIONS = [
  { value: "1", label: "Monday" }, { value: "2", label: "Tuesday" }, { value: "3", label: "Wednesday" },
  { value: "4", label: "Thursday" }, { value: "5", label: "Friday" }, { value: "6", label: "Saturday" },
  { value: "0", label: "Sunday" },
];

/** Builds a cron string from structured frequency/time/day inputs — the UI
 * never asks a non-cron-fluent user to hand-write one. */
function buildCron({ frequency, time, dayOfWeek, dayOfMonth }) {
  const [hour, minute] = (time || "06:00").split(":");
  if (frequency === "weekly") return istToUtcCron({ min: minute, hour, dow: dayOfWeek });
  if (frequency === "monthly") return istToUtcCron({ min: minute, hour, dom: dayOfMonth });
  return istToUtcCron({ min: minute, hour });
}

/** Custom cron is typed in IST; fixed minute/hour shapes are converted to the
 * UTC cron the backend runs. Step/range patterns pass through unchanged. */
function customIstToUtc(text) {
  const parts = (text || "").trim().split(/\s+/);
  if (parts.length !== 5) return text;
  const [min, hour, dom, month, dow] = parts;
  if (!/^\d+$/.test(min) || !/^\d+$/.test(hour)) return text;
  if (/^\d+$/.test(dom) && /^\d+$/.test(month) && dow === "*") {
    return fixedDateIstToUtc({ min, hour, dom, month });
  }
  if (month !== "*") return text;
  if (!(dom === "*" || /^\d+$/.test(dom)) || !(dow === "*" || /^\d+$/.test(dow))) return text;
  return istToUtcCron({ min, hour, dom, dow });
}

/** A schedule with no recipients generates the report but emails nobody
 * (backend/app/reports/generator.py `_notify_report_completed`), so the modal
 * pre-fills the creator's own address. */
function parseRecipients(text) {
  return (text || "")
    .split(/[,\s]+/)
    .map((e) => e.trim())
    .filter(Boolean);
}

/** Default for the "Once" picker: the next whole hour, IST. */
function defaultOnceAt() {
  const next = new Date(Date.now() + 3600_000);
  next.setUTCMinutes(0, 0, 0);
  return toISTInputValue(next.toISOString());
}

export default function SchedulesTab() {
  const toast = useToast();
  const { user } = useAuth();
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [reportType, setReportType] = useState("event_statistics");
  const [format, setFormat] = useState("pdf");
  const [window_, setWindow] = useState("last_7_days");
  const [frequency, setFrequency] = useState("daily"); // daily | weekly | monthly | once | custom
  const [time, setTime] = useState("06:00");
  const [dayOfWeek, setDayOfWeek] = useState("1");
  const [dayOfMonth, setDayOfMonth] = useState("1");
  const [onceAt, setOnceAt] = useState(defaultOnceAt);
  const [customCron, setCustomCron] = useState("0 6 * * *");
  const [recipients, setRecipients] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const onceInstant = frequency === "once" ? fromISTInputValue(onceAt) : null;
  const onceInPast = Boolean(onceInstant) && new Date(onceInstant) <= new Date();

  const cron = useMemo(() => {
    if (frequency === "custom") return customIstToUtc(customCron);
    if (frequency === "once") return onceInstant ? onceToUtcCron(onceInstant) : "";
    return buildCron({ frequency, time, dayOfWeek, dayOfMonth });
  }, [frequency, time, dayOfWeek, dayOfMonth, customCron, onceInstant]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSchedules(await api.get("/reports/schedules"));
    } catch (err) {
      toast.error(err.message || "Could not load schedules");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleEnabled = async (schedule) => {
    try {
      await api.patch(`/reports/schedules/${schedule.id}`, { enabled: !schedule.enabled });
      load();
    } catch (err) {
      toast.error(err.message || "Could not update schedule");
    }
  };

  const remove = async (schedule) => {
    try {
      await api.del(`/reports/schedules/${schedule.id}`);
      toast.success("Schedule deleted");
      load();
    } catch (err) {
      toast.error(err.message || "Could not delete schedule");
    }
  };

  const submit = async () => {
    setSubmitting(true);
    try {
      await api.post("/reports/schedules", {
        report_type: reportType,
        format,
        params: { window: window_ },
        cron,
        enabled: true,
        recipients: parseRecipients(recipients),
      });
      toast.success("Schedule created");
      setCreating(false);
      load();
    } catch (err) {
      toast.error(err.message || "Could not create schedule");
    } finally {
      setSubmitting(false);
    }
  };

  const meta = REPORT_TYPES.find((t) => t.key === reportType);

  const columns = [
    { key: "type", header: "Type", render: (s) => REPORT_TYPE_LABEL[s.report_type] || s.report_type },
    { key: "format", header: "Format", render: (s) => s.format.toUpperCase() },
    { key: "window", header: "Window", render: (s) => s.params?.window || "—" },
    { key: "cron", header: "Schedule", render: (s) => <span title={s.cron}>{describeCron(s.cron)}</span> },
    {
      key: "recipients",
      header: "Emails to",
      render: (s) =>
        s.recipients?.length ? (
          <span title={s.recipients.join(", ")}>
            {s.recipients.length === 1 ? s.recipients[0] : `${s.recipients.length} recipients`}
          </span>
        ) : (
          <span className="text-slate-500" title="This schedule generates the report but emails nobody.">
            nobody
          </span>
        ),
    },
    {
      key: "enabled",
      header: "Enabled",
      render: (s) => (
        <button
          onClick={() => toggleEnabled(s)}
          className={`rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
            s.enabled ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/50 text-slate-400 ring-slate-600"
          }`}
        >
          {s.enabled ? "Enabled" : "Disabled"}
        </button>
      ),
    },
    { key: "last_run_at", header: "Last run", render: (s) => relativeTime(s.last_run_at) },
    { key: "next_run_at", header: "Next run", render: (s) => (s.next_run_at ? absoluteTime(s.next_run_at) : "—") },
    {
      key: "actions",
      header: "",
      render: (s) => (
        <button onClick={() => remove(s)} className="rounded p-1 text-slate-500 hover:bg-slate-700 hover:text-rose-300">
          <Trash2 size={14} />
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="mb-3 flex justify-end">
        <Button
          size="sm"
          icon={Plus}
          onClick={() => {
            setOnceAt(defaultOnceAt());
            setRecipients(user?.email || "");
            setCreating(true);
          }}
        >
          New schedule
        </Button>
      </div>

      <Table
        columns={columns}
        rows={schedules}
        loading={loading}
        rowKey={(s) => s.id}
        empty={<EmptyState title="No schedules" description="Scheduled reports appear here and generate automatically." />}
      />

      <Modal
        open={creating}
        onClose={() => setCreating(false)}
        title="New schedule"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreating(false)}>
              Cancel
            </Button>
            <Button onClick={submit} loading={submitting} disabled={!cron || onceInPast}>
              Create
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="text-xs font-medium text-slate-300">Report type</label>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            >
              {REPORT_TYPES.filter((t) => t.key !== "incident_detail").map((t) => (
                <option key={t.key} value={t.key}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Window (resolved at run time)</label>
              <select
                value={window_}
                onChange={(e) => setWindow(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                {RELATIVE_WINDOWS.map((w) => (
                  <option key={w} value={w}>
                    {w.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Format</label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                {FORMATS.filter((f) => f !== "csv" || meta?.csv).map((f) => (
                  <option key={f} value={f}>
                    {f.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Repeats</label>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {[
                { key: "daily", label: "Daily" },
                { key: "weekly", label: "Weekly" },
                { key: "monthly", label: "Monthly" },
                { key: "once", label: "Once (date & time)" },
                { key: "custom", label: "Custom (cron)" },
              ].map((f) => (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => setFrequency(f.key)}
                  className={`rounded-md border px-2 py-1 text-xs ${
                    frequency === f.key ? "border-sky-500 text-sky-300" : "border-slate-700 text-slate-300 hover:border-sky-500"
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {frequency === "once" ? (
            <div>
              <label className="text-xs font-medium text-slate-300">Date &amp; time (IST)</label>
              <input
                type="datetime-local"
                value={onceAt}
                min={toISTInputValue(new Date().toISOString())}
                // A cron carries no year, so a date more than a year out would
                // resolve to the same day/month this year instead.
                max={toISTInputValue(new Date(Date.now() + 364 * 86400_000).toISOString())}
                onChange={(e) => setOnceAt(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              />
              {onceInPast && <p className="mt-1 text-xs text-amber-300">That moment has passed — pick a future date and time.</p>}
            </div>
          ) : frequency !== "custom" ? (
            <div className="grid grid-cols-2 gap-3">
              {frequency === "weekly" && (
                <div>
                  <label className="text-xs font-medium text-slate-300">Day of week</label>
                  <select
                    value={dayOfWeek}
                    onChange={(e) => setDayOfWeek(e.target.value)}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                  >
                    {DOW_OPTIONS.map((d) => (
                      <option key={d.value} value={d.value}>
                        {d.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              {frequency === "monthly" && (
                <div>
                  <label className="text-xs font-medium text-slate-300">Day of month</label>
                  <select
                    value={dayOfMonth}
                    onChange={(e) => setDayOfMonth(e.target.value)}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                  >
                    {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div>
                <label className="text-xs font-medium text-slate-300">Time (IST)</label>
                <input
                  type="time"
                  value={time}
                  onChange={(e) => setTime(e.target.value)}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                />
              </div>
            </div>
          ) : (
            <div>
              <label className="text-xs font-medium text-slate-300">Cron (IST)</label>
              <input
                value={customCron}
                onChange={(e) => setCustomCron(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100"
              />
            </div>
          )}
          <div>
            <label className="text-xs font-medium text-slate-300">Email the report to</label>
            <input
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="analyst@example.com, soc@example.com"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500"
            />
            <p className="mt-1 text-xs text-slate-500">
              {parseRecipients(recipients).length
                ? "Each run emails these addresses, with the report attached when it is small enough."
                : "Leave empty and the report is still generated — it just won't be emailed to anyone."}
            </p>
          </div>

          <p className="text-xs text-slate-500">
            {describeCron(cron)}
            {cron && isOneShot(cron) ? " — runs once, then the schedule turns itself off." : ""}
          </p>
        </div>
      </Modal>
    </>
  );
}
