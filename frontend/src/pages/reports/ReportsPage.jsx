import { Download, FileText, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { api, downloadFile, saveBlob } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { formatBytes, REPORT_TYPE_LABEL, STATUS_TONE } from "./constants";
import NewReportModal from "./NewReportModal";
import SchedulesTab from "./SchedulesTab";

const POLL_MS = 4_000;
const ACTIVE_STATUSES = new Set(["queued", "running"]);

export default function ReportsPage() {
  const toast = useToast();
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");

  const [tab, setTab] = useState("reports");
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalPrefill, setModalPrefill] = useState(undefined); // undefined = closed
  const pollTimer = useRef(null);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const data = await api.get("/reports?limit=100");
        setReports(data);
      } catch (err) {
        if (!silent) toast.error(err.message || "Could not load reports");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    load();
  }, [load]);

  // Poll only while something is queued/running; stop the moment nothing is pending.
  useEffect(() => {
    const hasPending = reports.some((r) => ACTIVE_STATUSES.has(r.status));
    if (!hasPending) return undefined;
    pollTimer.current = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(pollTimer.current);
  }, [reports, load]);

  const download = async (report) => {
    try {
      const { blob, filename } = await downloadFile(`/reports/${report.id}/download`);
      saveBlob(blob, filename);
    } catch (err) {
      toast.error(err.message || "Download failed");
    }
  };

  const remove = async (report) => {
    try {
      await api.del(`/reports/${report.id}`);
      toast.success("Report deleted");
      load();
    } catch (err) {
      toast.error(err.message || "Could not delete report");
    }
  };

  const retry = async (report) => {
    try {
      await api.post("/reports", {
        report_type: report.report_type,
        format: report.format,
        params: report.params,
        title: report.title,
      });
      toast.success("Report re-queued");
      load();
    } catch (err) {
      toast.error(err.message || "Retry failed");
    }
  };

  const columns = [
    { key: "title", header: "Title", className: "max-w-xs truncate text-slate-100" },
    { key: "type", header: "Type", render: (r) => REPORT_TYPE_LABEL[r.report_type] || r.report_type },
    { key: "format", header: "Format", render: (r) => r.format.toUpperCase() },
    { key: "status", header: "Status", render: (r) => <Badge tone={STATUS_TONE[r.status]}>{r.status}</Badge> },
    { key: "requested_at", header: "Requested", render: (r) => relativeTime(r.requested_at) },
    { key: "size", header: "Size", render: (r) => formatBytes(r.file_size) },
    {
      key: "actions",
      header: "",
      render: (r) => (
        <div className="flex items-center gap-1">
          {r.status === "completed" && (
            <button
              onClick={() => download(r)}
              className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-sky-300"
              title="Download"
            >
              <Download size={14} />
            </button>
          )}
          <button onClick={() => remove(r)} className="rounded p-1 text-slate-500 hover:bg-slate-700 hover:text-rose-300" title="Delete">
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Reports"
        description="Generate and schedule PDF/CSV/JSON reports. Generation runs asynchronously and never blocks the API."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" icon={RefreshCw} onClick={() => load()} disabled={loading}>
              Refresh
            </Button>
            <Button icon={Plus} onClick={() => setModalPrefill(null)}>
              New report
            </Button>
          </div>
        }
      />

      {isAdmin && (
        <div className="mb-4 flex gap-1 border-b border-slate-800">
          {[
            { key: "reports", label: "Reports" },
            { key: "schedules", label: "Schedules" },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
                tab === t.key ? "border-sky-500 text-slate-100" : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      )}

      {tab === "reports" ? (
        <>
          <Table
            columns={columns}
            rows={reports}
            loading={loading}
            rowKey={(r) => r.id}
            empty={
              <EmptyState
                icon={FileText}
                title="No reports yet"
                description="Generate an incident summary, asset inventory, or event statistics report."
              />
            }
          />

          {reports
            .filter((r) => r.status === "failed")
            .map((r) => (
              <div key={r.id} className="mt-2 flex items-center justify-between rounded-md border border-rose-800/50 bg-rose-500/5 px-3 py-2 text-xs">
                <span className="text-rose-300">
                  <strong>{r.title}</strong> failed: {r.error || "unknown error"} <span title={absoluteTime(r.requested_at)}>({relativeTime(r.requested_at)})</span>
                </span>
                <Button size="sm" variant="secondary" onClick={() => retry(r)}>
                  Retry
                </Button>
              </div>
            ))}
        </>
      ) : (
        <SchedulesTab />
      )}

      <NewReportModal
        open={modalPrefill !== undefined}
        onClose={() => setModalPrefill(undefined)}
        onCreated={() => load()}
        prefill={modalPrefill}
      />
    </>
  );
}
