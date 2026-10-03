import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { CRON_PRESETS, FORMATS, REPORT_TYPE_LABEL, REPORT_TYPES, describeCron } from "./constants";

const RELATIVE_WINDOWS = ["last_7_days", "last_30_days", "last_90_days"];

export default function SchedulesTab() {
  const toast = useToast();
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [reportType, setReportType] = useState("event_statistics");
  const [format, setFormat] = useState("pdf");
  const [window_, setWindow] = useState("last_7_days");
  const [cron, setCron] = useState(CRON_PRESETS[0].cron);
  const [submitting, setSubmitting] = useState(false);

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
        <Button size="sm" icon={Plus} onClick={() => setCreating(true)}>
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
            <Button onClick={submit} loading={submitting}>
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
            <label className="text-xs font-medium text-slate-300">Cron</label>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {CRON_PRESETS.map((p) => (
                <button
                  key={p.cron}
                  type="button"
                  onClick={() => setCron(p.cron)}
                  className={`rounded-md border px-2 py-1 text-xs ${
                    cron === p.cron ? "border-sky-500 text-sky-300" : "border-slate-700 text-slate-300 hover:border-sky-500"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <input
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              className="mt-2 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100"
            />
            <p className="mt-1 text-xs text-slate-500">{describeCron(cron)}</p>
          </div>
        </div>
      </Modal>
    </>
  );
}
