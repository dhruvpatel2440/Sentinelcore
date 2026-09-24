import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { SEVERITY_OPTIONS, SOURCE_FORMATS } from "./constants";

const DEFAULTS = {
  name: "", url: "", format: "csv", enabled: true, default_confidence: 50,
  default_severity: "medium", refresh_interval_hours: 24, ttl_days: 30,
};

export default function SourceModal({ open, onClose, onSaved }) {
  const toast = useToast();
  const [form, setForm] = useState(DEFAULTS);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) setForm(DEFAULTS);
  }, [open]);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  const submit = async () => {
    if (!form.name.trim() || !form.url.trim()) return;
    setSubmitting(true);
    try {
      await api.post("/intel/sources", { ...form, parser_config: {} });
      toast.success("Source added");
      onSaved?.();
      onClose();
    } catch (err) {
      toast.error(err.message || "Could not add source");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add feed source"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={submitting} disabled={!form.name.trim() || !form.url.trim()}>
            Add source
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-slate-300">Name</label>
          <input
            value={form.name}
            onChange={(e) => set({ name: e.target.value })}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">URL (HTTPS)</label>
          <input
            value={form.url}
            onChange={(e) => set({ url: e.target.value })}
            placeholder="https://…"
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Format</label>
            <select
              value={form.format}
              onChange={(e) => set({ format: e.target.value })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
            >
              {SOURCE_FORMATS.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-slate-300">Default severity</label>
            <select
              value={form.default_severity}
              onChange={(e) => set({ default_severity: e.target.value })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Refresh (hours)</label>
            <input
              type="number"
              min={1}
              value={form.refresh_interval_hours}
              onChange={(e) => set({ refresh_interval_hours: Number(e.target.value) })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-300">TTL (days)</label>
            <input
              type="number"
              min={1}
              value={form.ttl_days}
              onChange={(e) => set({ ttl_days: Number(e.target.value) })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-300">Default confidence</label>
            <input
              type="number"
              min={0}
              max={100}
              value={form.default_confidence}
              onChange={(e) => set({ default_confidence: Number(e.target.value) })}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
            />
          </div>
        </div>
      </div>
    </Modal>
  );
}
