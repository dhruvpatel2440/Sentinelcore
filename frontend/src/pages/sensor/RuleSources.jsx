import { Download, Plus } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { relativeTime } from "../../lib/format";

export default function RuleSources({ onUpdateRules, updating, onChanged }) {
  const toast = useToast();
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ name: "", url: "" });
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSources(await api.get("/sensor/rules/sources"));
    } catch (err) {
      toast.error(err.message || "Could not load rule sources");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (source) => {
    try {
      await api.patch(`/sensor/rules/sources/${source.id}`, { enabled: !source.enabled });
      load();
      onChanged?.();
    } catch (err) {
      toast.error(err.message || "Could not update the source");
    }
  };

  const add = async (e) => {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      await api.post("/sensor/rules/sources", form);
      toast.success("Rule source added");
      setAdding(false);
      setForm({ name: "", url: "" });
      load();
    } catch (err) {
      setError(err.message || "Could not add the source");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card
      title="Rule sources"
      description="Feeds are fetched over HTTPS, validated, then reloaded without a restart."
      actions={
        <>
          <Button size="sm" variant="secondary" icon={Plus} onClick={() => setAdding(true)}>
            Add source
          </Button>
          <Button size="sm" icon={Download} loading={updating} onClick={onUpdateRules}>
            Update now
          </Button>
        </>
      }
    >
      <Table
        loading={loading}
        rows={sources}
        rowKey={(s) => s.id}
        columns={[
          { key: "name", header: "Name", className: "text-slate-100" },
          {
            key: "url",
            header: "URL",
            render: (s) => (
              <span className="block max-w-xs truncate text-xs text-slate-400" title={s.url}>
                {s.url}
              </span>
            ),
          },
          {
            key: "enabled",
            header: "Enabled",
            render: (s) => (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={s.enabled}
                  onChange={() => toggle(s)}
                  aria-label={`Toggle ${s.name}`}
                  className="rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
                />
              </label>
            ),
          },
          { key: "rule_count", header: "Rules" },
          {
            key: "last_status",
            header: "Last result",
            render: (s) =>
              s.last_status ? (
                <Badge tone={s.last_status === "ok" ? "success" : "danger"} className="cursor-help">
                  <span title={s.last_error ?? ""}>{s.last_status}</span>
                </Badge>
              ) : (
                <span className="text-xs text-slate-500">never run</span>
              ),
          },
          {
            key: "last_updated_at",
            header: "Updated",
            render: (s) => relativeTime(s.last_updated_at),
          },
        ]}
        empty={
          <p className="px-4 py-6 text-center text-xs text-slate-500">
            No rule sources configured.
          </p>
        }
      />

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="Add rule source"
        description="Must be an HTTPS URL to a .tar.gz or .zip rule archive."
        footer={
          <>
            <Button variant="ghost" onClick={() => setAdding(false)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={add} loading={saving}>
              Add source
            </Button>
          </>
        }
      >
        <form onSubmit={add} className="space-y-4">
          <div>
            <label htmlFor="source-name" className="block text-xs font-medium text-slate-300">
              Name
            </label>
            <input
              id="source-name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <div>
            <label htmlFor="source-url" className="block text-xs font-medium text-slate-300">
              URL
            </label>
            <input
              id="source-url"
              value={form.url}
              placeholder="https://rules.example.net/suricata.rules.tar.gz"
              onChange={(e) => setForm({ ...form, url: e.target.value })}
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
