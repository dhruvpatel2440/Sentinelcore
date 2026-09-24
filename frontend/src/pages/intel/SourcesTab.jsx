import { AlertTriangle, Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { relativeTime } from "../../lib/format";
import { SOURCE_STATUS_TONE } from "./constants";
import SourceModal from "./SourceModal";

const STALE_AFTER_MS = 24 * 3600 * 1000;

export default function SourcesTab() {
  const toast = useToast();
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSources(await api.get("/intel/sources"));
    } catch (err) {
      toast.error(err.message || "Could not load sources");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleEnabled = async (source) => {
    try {
      await api.patch(`/intel/sources/${source.id}`, { enabled: !source.enabled });
      load();
    } catch (err) {
      toast.error(err.message || "Could not update source");
    }
  };

  const refreshNow = async (source) => {
    setRefreshing(source.id);
    try {
      await api.post(`/intel/sources/${source.id}/refresh`);
      toast.success(`Refreshing ${source.name}…`);
      setTimeout(load, 2000);
    } catch (err) {
      toast.error(err.message || "Could not trigger refresh");
    } finally {
      setRefreshing(null);
    }
  };

  const remove = async (source) => {
    if (!window.confirm(`Delete source "${source.name}"? Its IOCs stay until they expire.`)) return;
    try {
      await api.del(`/intel/sources/${source.id}`);
      load();
    } catch (err) {
      toast.error(err.message || "Could not delete source");
    }
  };

  const failing = sources.filter(
    (s) => s.last_status === "error" && s.last_fetch_at && Date.now() - new Date(s.last_fetch_at).getTime() > STALE_AFTER_MS,
  );

  return (
    <>
      {failing.length > 0 && (
        <div className="mb-3 flex items-start gap-2 rounded-md bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-inset ring-rose-500/30">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          <span>
            {failing.map((s) => s.name).join(", ")} {failing.length === 1 ? "has" : "have"} been failing for over a day —
            the platform is quietly less protected until this is fixed.
          </span>
        </div>
      )}

      <div className="mb-3 flex justify-end">
        <Button size="sm" icon={Plus} onClick={() => setModalOpen(true)}>
          Add source
        </Button>
      </div>

      <Table
        columns={[
          { key: "name", header: "Name", className: "text-slate-100" },
          { key: "format", header: "Format", render: (s) => s.format.toUpperCase() },
          { key: "enabled", header: "Enabled", render: (s) => (
            <button
              onClick={() => toggleEnabled(s)}
              className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${
                s.enabled ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/50 text-slate-400 ring-slate-600"
              }`}
            >
              {s.enabled ? "On" : "Off"}
            </button>
          ) },
          { key: "indicator_count", header: "Indicators", render: (s) => s.indicator_count.toLocaleString() },
          { key: "last_fetch_at", header: "Last fetch", render: (s) => (s.last_fetch_at ? relativeTime(s.last_fetch_at) : "never") },
          {
            key: "last_status", header: "Status",
            render: (s) => s.last_status ? <Badge tone={SOURCE_STATUS_TONE[s.last_status] || "neutral"}>{s.last_status}</Badge> : "—",
          },
          {
            key: "actions", header: "",
            render: (s) => (
              <div className="flex gap-1">
                <Button size="sm" variant="secondary" icon={RefreshCw} loading={refreshing === s.id} onClick={() => refreshNow(s)}>
                  Refresh
                </Button>
                <Button size="sm" variant="ghost" onClick={() => remove(s)}>
                  Delete
                </Button>
              </div>
            ),
          },
        ]}
        rows={sources}
        loading={loading}
        rowKey={(s) => s.id}
        empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No feed sources configured yet.</p>}
      />

      <SourceModal open={modalOpen} onClose={() => setModalOpen(false)} onSaved={load} />
    </>
  );
}
