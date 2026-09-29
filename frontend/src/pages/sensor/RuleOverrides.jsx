import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime } from "../../lib/format";

const ACTION_TONE = { disabled: "danger", enabled: "success", threshold: "warning" };

const EMPTY = { sid: "", action: "disabled", reason: "", count: 5, seconds: 300, track: "by_src" };

export default function RuleOverrides({ onChanged }) {
  const toast = useToast();
  const [overrides, setOverrides] = useState([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setOverrides(await api.get("/sensor/rules/overrides"));
    } catch (err) {
      toast.error(err.message || "Could not load overrides");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const add = async (e) => {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      const body = {
        sid: Number(form.sid),
        action: form.action,
        reason: form.reason,
        params:
          form.action === "threshold"
            ? {
                type: "limit",
                track: form.track,
                count: Number(form.count),
                seconds: Number(form.seconds),
              }
            : null,
      };
      await api.post("/sensor/rules/overrides", body);
      toast.success(`Override for SID ${form.sid} saved`);
      setAdding(false);
      setForm(EMPTY);
      load();
      onChanged?.();
    } catch (err) {
      setError(err.message || "Could not save the override");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (sid) => {
    try {
      await api.del(`/sensor/rules/overrides/${sid}`);
      toast.success(`Override for SID ${sid} removed`);
      load();
      onChanged?.();
    } catch (err) {
      toast.error(err.message || "Could not remove the override");
    }
  };

  return (
    <Card
      title="Rule overrides"
      description="Tune noisy signatures. A reason is required — six months later nobody remembers why a rule was silenced."
      actions={
        <Button size="sm" variant="secondary" icon={Plus} onClick={() => setAdding(true)}>
          Add override
        </Button>
      }
    >
      <Table
        loading={loading}
        rows={overrides}
        rowKey={(o) => o.id}
        columns={[
          { key: "sid", header: "SID", className: "font-mono text-slate-100" },
          {
            key: "action",
            header: "Action",
            render: (o) => <Badge tone={ACTION_TONE[o.action] ?? "neutral"}>{o.action}</Badge>,
          },
          {
            key: "reason",
            header: "Reason",
            render: (o) => (
              <span className="block max-w-md truncate" title={o.reason}>
                {o.reason}
              </span>
            ),
          },
          { key: "created_at", header: "Added", render: (o) => absoluteTime(o.created_at) },
          {
            key: "actions",
            header: "",
            render: (o) => (
              <Button size="sm" variant="ghost" icon={Trash2} onClick={() => remove(o.sid)}>
                Remove
              </Button>
            ),
          },
        ]}
        empty={
          <p className="px-4 py-6 text-center text-xs text-slate-500">
            No signature overrides. Every rule in the feed is active.
          </p>
        }
      />

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="Add rule override"
        footer={
          <>
            <Button variant="ghost" onClick={() => setAdding(false)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={add} loading={saving}>
              Save override
            </Button>
          </>
        }
      >
        <form onSubmit={add} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="ov-sid" className="block text-xs font-medium text-slate-300">
                Signature ID (SID)
              </label>
              <input
                id="ov-sid"
                type="number"
                min="1"
                value={form.sid}
                onChange={(e) => setForm({ ...form, sid: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              />
            </div>
            <div>
              <label htmlFor="ov-action" className="block text-xs font-medium text-slate-300">
                Action
              </label>
              <select
                id="ov-action"
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              >
                <option value="disabled">Disable</option>
                <option value="enabled">Enable</option>
                <option value="threshold">Threshold</option>
              </select>
            </div>
          </div>

          {form.action === "threshold" && (
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label htmlFor="ov-track" className="block text-xs font-medium text-slate-300">
                  Track
                </label>
                <select
                  id="ov-track"
                  value={form.track}
                  onChange={(e) => setForm({ ...form, track: e.target.value })}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                >
                  <option value="by_src">by_src</option>
                  <option value="by_dst">by_dst</option>
                  <option value="by_rule">by_rule</option>
                </select>
              </div>
              <div>
                <label htmlFor="ov-count" className="block text-xs font-medium text-slate-300">
                  Count
                </label>
                <input
                  id="ov-count"
                  type="number"
                  min="1"
                  value={form.count}
                  onChange={(e) => setForm({ ...form, count: e.target.value })}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="ov-seconds" className="block text-xs font-medium text-slate-300">
                  Seconds
                </label>
                <input
                  id="ov-seconds"
                  type="number"
                  min="1"
                  value={form.seconds}
                  onChange={(e) => setForm({ ...form, seconds: e.target.value })}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                />
              </div>
            </div>
          )}

          <div>
            <label htmlFor="ov-reason" className="block text-xs font-medium text-slate-300">
              Reason <span className="text-rose-400">*</span>
            </label>
            <textarea
              id="ov-reason"
              rows={3}
              required
              value={form.reason}
              placeholder="Why is this signature being changed? Include the ticket or context."
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          {error && (
            <p role="alert" className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
              {error}
            </p>
          )}
        </form>
      </Modal>
    </Card>
  );
}
