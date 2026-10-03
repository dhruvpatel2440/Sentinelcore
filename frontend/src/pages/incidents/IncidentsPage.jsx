import { RefreshCw, ShieldAlert, UserCheck } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { relativeTime } from "../../lib/format";
import { QUEUE_TABS, STATUS_LABEL, STATUS_TONE, ageTone, paramsForTab } from "./constants";

const AUTO_REFRESH_MS = 30_000;

export default function IncidentsPage() {
  const { user } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();

  const [tab, setTab] = useState("my_open");
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const [selected, setSelected] = useState(new Set());
  const [cursorRow, setCursorRow] = useState(0);
  const [bulkAction, setBulkAction] = useState(null); // "status" | "assign" | "close"
  const [bulkNote, setBulkNote] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const knownIds = useRef(new Set());

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const params = paramsForTab(tab, user?.id);
        params.set("limit", "100");
        const data = await api.get(`/incidents?${params}`);
        if (silent) {
          const fresh = data.items.filter((i) => !knownIds.current.has(i.id));
          if (fresh.length) setNewCount((n) => n + fresh.length);
        } else {
          setNewCount(0);
        }
        knownIds.current = new Set(data.items.map((i) => i.id));
        if (!silent) setIncidents(data.items);
      } catch (err) {
        if (!silent) toast.error(err.message || "Could not load incidents");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [tab, user?.id, toast],
  );

  useEffect(() => {
    setSelected(new Set());
    load();
  }, [load]);

  useEffect(() => {
    const timer = setInterval(() => load(true), AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const applyNew = () => {
    setNewCount(0);
    load();
  };

  // j/k/Enter/a — a queue analysts live in all day.
  useEffect(() => {
    const onKeyDown = (e) => {
      if (["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName)) return;
      if (e.key === "j") setCursorRow((r) => Math.min(r + 1, incidents.length - 1));
      else if (e.key === "k") setCursorRow((r) => Math.max(r - 1, 0));
      else if (e.key === "Enter" && incidents[cursorRow]) navigate(`/incidents/${incidents[cursorRow].number}`);
      else if (e.key === "a" && incidents[cursorRow]) assignToMe(incidents[cursorRow]);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidents, cursorRow]);

  const assignToMe = async (incident) => {
    try {
      await api.post(`/incidents/${incident.id}/assign`, { version: incident.version, user_id: user.id });
      toast.success(`Assigned INC-${incident.number} to you`);
      load();
    } catch (err) {
      toast.error(err.message || "Could not assign");
    }
  };

  const toggleSelect = (id) => {
    setSelected((s) => {
      const next = new Set(s);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const runBulk = async (payload, path) => {
    setSubmitting(true);
    try {
      await Promise.all(
        [...selected].map((id) => {
          const incident = incidents.find((i) => i.id === id);
          return api.post(`/incidents/${id}/${path}`, { version: incident.version, ...payload });
        }),
      );
      toast.success(`Updated ${selected.size} incident(s)`);
      setBulkAction(null);
      setBulkNote("");
      setSelected(new Set());
      load();
    } catch (err) {
      toast.error(err.message || "Bulk action failed");
    } finally {
      setSubmitting(false);
    }
  };

  const columns = [
    {
      key: "select",
      header: (
        <input
          type="checkbox"
          onChange={(e) =>
            setSelected(e.target.checked ? new Set(incidents.map((i) => i.id)) : new Set())
          }
          checked={selected.size > 0 && selected.size === incidents.length}
          className="rounded border-slate-600 bg-slate-900 text-sky-500"
        />
      ),
      render: (i) => (
        <input
          type="checkbox"
          checked={selected.has(i.id)}
          onClick={(e) => e.stopPropagation()}
          onChange={() => toggleSelect(i.id)}
          className="rounded border-slate-600 bg-slate-900 text-sky-500"
        />
      ),
    },
    { key: "number", header: "#", render: (i) => <span className="font-mono text-slate-400">INC-{i.number}</span> },
    { key: "severity", header: "Severity", render: (i) => <Badge severity={i.severity} /> },
    { key: "title", header: "Title", className: "max-w-sm truncate text-slate-100" },
    { key: "status", header: "Status", render: (i) => <Badge tone={STATUS_TONE[i.status]}>{STATUS_LABEL[i.status]}</Badge> },
    {
      key: "assigned_to",
      header: "Assignee",
      render: (i) =>
        i.assigned_to ? (
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-slate-700 text-[10px] font-semibold text-slate-200">
            {i.assigned_to.slice(0, 2).toUpperCase()}
          </span>
        ) : (
          <span className="text-xs text-slate-600">unassigned</span>
        ),
    },
    { key: "age", header: "Age", render: (i) => <span className={ageTone(i.opened_at)}>{relativeTime(i.opened_at)}</span> },
    { key: "event_count", header: "Events" },
    { key: "updated_at", header: "Last activity", render: (i) => relativeTime(i.updated_at) },
  ];

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Triage queue for correlated activity."
        actions={
          <Button variant="secondary" icon={RefreshCw} onClick={() => load()} disabled={loading}>
            Refresh
          </Button>
        }
      />

      <div className="mb-4 flex gap-1 border-b border-slate-800">
        {QUEUE_TABS.map((t) => (
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

      {newCount > 0 && (
        <button
          onClick={applyNew}
          className="mb-3 flex items-center gap-1.5 rounded-md bg-sky-500/15 px-3 py-1.5 text-xs font-medium text-sky-200 ring-1 ring-inset ring-sky-500/30"
        >
          {newCount} new incident{newCount === 1 ? "" : "s"} — click to refresh
        </button>
      )}

      {selected.size > 0 && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-slate-700 bg-slate-800/60 px-3 py-2">
          <span className="text-xs text-slate-300">{selected.size} selected</span>
          <Button size="sm" variant="secondary" icon={UserCheck} onClick={() => setBulkAction("assign")}>
            Assign to me
          </Button>
          <Button size="sm" variant="secondary" onClick={() => setBulkAction("close")}>
            Close…
          </Button>
        </div>
      )}

      <Table
        columns={columns}
        rows={incidents}
        loading={loading}
        rowKey={(i) => i.id}
        onRowClick={(i) => navigate(`/incidents/${i.number}`)}
        empty={<EmptyState icon={ShieldAlert} title="Queue is empty" description="Nothing matches this view." />}
      />

      <Modal
        open={bulkAction === "assign"}
        onClose={() => setBulkAction(null)}
        title={`Assign ${selected.size} incident(s) to yourself?`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setBulkAction(null)}>
              Cancel
            </Button>
            <Button loading={submitting} onClick={() => runBulk({ user_id: user.id }, "assign")}>
              Assign
            </Button>
          </>
        }
      >
        <p>This assigns every selected incident to you.</p>
      </Modal>

      <Modal
        open={bulkAction === "close"}
        onClose={() => setBulkAction(null)}
        title={`Close ${selected.size} incident(s)`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setBulkAction(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={submitting}
              disabled={!bulkNote.trim()}
              onClick={() => runBulk({ status: "resolved", note: bulkNote.trim() }, "status")}
            >
              Close as resolved
            </Button>
          </>
        }
      >
        <label className="text-xs font-medium text-slate-300">Resolution note (shared across all selected, required)</label>
        <textarea
          rows={3}
          value={bulkNote}
          onChange={(e) => setBulkNote(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
      </Modal>
    </>
  );
}
