import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import RuleEditor from "./RuleEditor";

export default function RulesTab() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const isAdmin = hasRole("admin");

  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState(undefined); // undefined = closed, null = new
  const [deleteTarget, setDeleteTarget] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRules(await api.get("/correlation/rules"));
    } catch (err) {
      toast.error(err.message || "Could not load rules");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleEnabled = async (rule) => {
    try {
      await api.patch(`/correlation/rules/${rule.id}`, { enabled: !rule.enabled });
      load();
    } catch (err) {
      toast.error(err.message || "Could not update rule");
    }
  };

  const remove = async () => {
    try {
      await api.del(`/correlation/rules/${deleteTarget.id}`);
      toast.success("Rule deleted");
      setDeleteTarget(null);
      load();
    } catch (err) {
      toast.error(err.message || "Could not delete rule");
    }
  };

  const columns = [
    { key: "name", header: "Name", render: (r) => <span className="font-medium text-slate-100">{r.name}</span> },
    { key: "rule_type", header: "Type", render: (r) => <Badge tone="neutral">{r.rule_type}</Badge> },
    {
      key: "enabled",
      header: "Enabled",
      render: (r) =>
        isAdmin ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              toggleEnabled(r);
            }}
            className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${
              r.enabled ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/50 text-slate-400 ring-slate-600"
            }`}
          >
            {r.enabled ? "enabled" : "disabled"}
          </button>
        ) : (
          <Badge tone={r.enabled ? "success" : "neutral"}>{r.enabled ? "enabled" : "disabled"}</Badge>
        ),
    },
    { key: "window_seconds", header: "Window", render: (r) => `${r.window_seconds}s` },
    { key: "threshold", header: "Threshold" },
    { key: "severity", header: "Severity", render: (r) => <Badge severity={r.severity} /> },
    {
      key: "candidates_24h",
      header: "Candidates (24h)",
      render: (r) => (
        <span className={r.candidates_24h === 0 && r.enabled ? "text-amber-300" : "text-slate-200"}>
          {r.candidates_24h}
        </span>
      ),
    },
    {
      key: "last_run_status",
      header: "Last run",
      render: (r) =>
        r.last_run_status ? (
          <Badge tone={r.last_run_status === "ok" ? "success" : "danger"}>{r.last_run_status}</Badge>
        ) : (
          <span className="text-slate-600">never</span>
        ),
    },
    ...(isAdmin
      ? [
          {
            key: "actions",
            header: "",
            render: (r) => (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setDeleteTarget(r);
                }}
                aria-label={`Delete ${r.name}`}
                className="rounded p-1 text-slate-500 hover:bg-slate-700 hover:text-rose-300"
              >
                <Trash2 size={14} />
              </button>
            ),
          },
        ]
      : []),
  ];

  return (
    <div>
      {isAdmin && (
        <div className="mb-3 flex justify-end">
          <Button icon={Plus} onClick={() => setEditingId(null)}>
            New rule
          </Button>
        </div>
      )}

      <Table
        columns={columns}
        rows={rules}
        loading={loading}
        rowKey={(r) => r.id}
        onRowClick={isAdmin ? (r) => setEditingId(r.id) : undefined}
        empty={
          <EmptyState
            title="No correlation rules yet"
            description={isAdmin ? "Create one to start turning alert noise into findings." : "An admin needs to add correlation rules."}
          />
        }
      />

      {editingId !== undefined && (
        <RuleEditor
          ruleId={editingId}
          open={editingId !== undefined}
          onClose={() => setEditingId(undefined)}
          onSaved={load}
        />
      )}

      <Modal
        open={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        title="Delete correlation rule?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={remove}>
              Delete
            </Button>
          </>
        }
      >
        <p>
          This deletes <strong>{deleteTarget?.name}</strong> and its candidate history. This cannot be undone.
        </p>
      </Modal>
    </div>
  );
}
