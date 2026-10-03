import { FlaskConical } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { SEVERITIES } from "../events/filters";
import MatchBlockEditor from "./MatchBlockEditor";
import { GROUP_BY_FIELDS, RULE_TYPES, defaultParamsFor } from "./ruleTypes";

const inputClass =
  "mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500";

function emptyForm() {
  return {
    name: "",
    description: "",
    enabled: false,
    rule_type: "threshold",
    match: {},
    group_by: ["src_ip"],
    window_seconds: 300,
    threshold: 10,
    severity: "high",
    dedup_window_seconds: 3600,
    params: defaultParamsFor("threshold"),
  };
}

function ParamsEditor({ ruleType, params, onChange }) {
  const set = (patch) => onChange({ ...params, ...patch });

  if (ruleType === "threshold") {
    return (
      <div>
        <label className="text-xs font-medium text-slate-300">Count distinct field (optional)</label>
        <select
          className={inputClass}
          value={params.count_distinct_field || ""}
          onChange={(e) => set({ count_distinct_field: e.target.value || null })}
        >
          <option value="">Count every matching event</option>
          {GROUP_BY_FIELDS.map((f) => (
            <option key={f} value={f}>
              distinct {f}
            </option>
          ))}
        </select>
      </div>
    );
  }

  if (ruleType === "rare") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="text-xs font-medium text-slate-300">Baseline window (days)</label>
          <input
            type="number"
            min={1}
            className={inputClass}
            value={params.baseline_days ?? 14}
            onChange={(e) => set({ baseline_days: Number(e.target.value) })}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Frequency floor</label>
          <input
            type="number"
            min={1}
            className={inputClass}
            value={params.frequency_floor ?? 3}
            onChange={(e) => set({ frequency_floor: Number(e.target.value) })}
          />
        </div>
      </div>
    );
  }

  if (ruleType === "beacon") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="text-xs font-medium text-slate-300">Max coefficient of variation</label>
          <input
            type="number"
            step="0.01"
            min={0.01}
            max={1}
            className={inputClass}
            value={params.max_cv ?? 0.15}
            onChange={(e) => set({ max_cv: Number(e.target.value) })}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Min samples</label>
          <input
            type="number"
            min={3}
            className={inputClass}
            value={params.min_samples ?? 5}
            onChange={(e) => set({ min_samples: Number(e.target.value) })}
          />
        </div>
      </div>
    );
  }

  // sequence — a JSON escape hatch for the step list, as the spec allows for
  // power users rather than a full nested match-block-list builder.
  return (
    <div>
      <label className="text-xs font-medium text-slate-300">
        Steps (JSON array of match blocks, in order)
      </label>
      <textarea
        rows={6}
        className={`${inputClass} font-mono`}
        value={JSON.stringify(params.steps ?? [], null, 2)}
        onChange={(e) => {
          try {
            set({ steps: JSON.parse(e.target.value) });
          } catch {
            // Leave params.steps as the last valid parse; the raw text stays
            // visible for the admin to keep fixing without losing input.
          }
        }}
      />
    </div>
  );
}

export default function RuleEditor({ ruleId, open, onClose, onSaved }) {
  const toast = useToast();
  const [form, setForm] = useState(emptyForm());
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const [testFrom, setTestFrom] = useState("");
  const [testTo, setTestTo] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const isEdit = Boolean(ruleId);

  useEffect(() => {
    if (!open) return;
    setTestResult(null);
    const now = new Date();
    setTestTo(now.toISOString().slice(0, 16));
    setTestFrom(new Date(now.getTime() - 24 * 3600 * 1000).toISOString().slice(0, 16));

    if (!ruleId) {
      setForm(emptyForm());
      return;
    }
    setLoading(true);
    api
      .get("/correlation/rules")
      .then((rules) => {
        const rule = rules.find((r) => r.id === ruleId);
        if (rule) setForm(rule);
      })
      .catch((err) => toast.error(err.message || "Could not load rule"))
      .finally(() => setLoading(false));
  }, [ruleId, open, toast]);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  const changeRuleType = (rule_type) => set({ rule_type, params: defaultParamsFor(rule_type) });

  const toggleGroupBy = (field) => {
    const current = form.group_by || [];
    set({ group_by: current.includes(field) ? current.filter((x) => x !== field) : [...current, field] });
  };

  const save = async () => {
    setSaving(true);
    try {
      const body = {
        name: form.name,
        description: form.description,
        enabled: form.enabled,
        rule_type: form.rule_type,
        match: form.match,
        group_by: form.group_by,
        window_seconds: Number(form.window_seconds),
        threshold: Number(form.threshold),
        severity: form.severity,
        dedup_window_seconds: Number(form.dedup_window_seconds),
        params: form.params,
      };
      if (isEdit) {
        await api.patch(`/correlation/rules/${ruleId}`, body);
        toast.success("Rule updated");
      } else {
        await api.post("/correlation/rules", body);
        toast.success("Rule created (disabled) — test it before enabling");
      }
      onSaved();
      onClose();
    } catch (err) {
      toast.error(err.message || "Could not save rule");
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.post(`/correlation/rules/${ruleId}/test`, {
        from: new Date(testFrom).toISOString(),
        to: new Date(testTo).toISOString(),
      });
      setTestResult(result);
    } catch (err) {
      toast.error(err.message || "Test run failed");
    } finally {
      setTesting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? "Edit correlation rule" : "New correlation rule"}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={save} loading={saving} disabled={!form.name || !form.description}>
            {isEdit ? "Save changes" : "Create rule (disabled)"}
          </Button>
        </>
      }
    >
      {loading ? (
        <p className="text-sm text-slate-400">Loading…</p>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Name</label>
              <input className={inputClass} value={form.name} onChange={(e) => set({ name: e.target.value })} />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Rule type</label>
              <select
                className={inputClass}
                value={form.rule_type}
                onChange={(e) => changeRuleType(e.target.value)}
                disabled={isEdit}
              >
                {RULE_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p className="-mt-3 text-xs text-slate-500">
            {RULE_TYPES.find((t) => t.value === form.rule_type)?.hint}
          </p>

          <div>
            <label className="text-xs font-medium text-slate-300">Description (becomes the incident narrative)</label>
            <textarea
              rows={2}
              className={inputClass}
              value={form.description}
              onChange={(e) => set({ description: e.target.value })}
            />
          </div>

          <div className="grid grid-cols-4 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Severity</label>
              <select className={inputClass} value={form.severity} onChange={(e) => set({ severity: e.target.value })}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Window (s)</label>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={form.window_seconds}
                onChange={(e) => set({ window_seconds: e.target.value })}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Threshold</label>
              <input
                type="number"
                min={1}
                className={inputClass}
                value={form.threshold}
                onChange={(e) => set({ threshold: e.target.value })}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Dedup window (s)</label>
              <input
                type="number"
                min={0}
                className={inputClass}
                value={form.dedup_window_seconds}
                onChange={(e) => set({ dedup_window_seconds: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Group by</label>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {GROUP_BY_FIELDS.map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => toggleGroupBy(f)}
                  className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset ${
                    (form.group_by || []).includes(f)
                      ? "bg-sky-500/20 text-sky-200 ring-sky-500/40"
                      : "bg-slate-800 text-slate-400 ring-slate-700"
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => set({ enabled: e.target.checked })}
              className="rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
            />
            Enabled — will run on the live engine every tick
          </label>

          <div className="rounded-md border border-slate-700 p-3">
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Match</h4>
            <MatchBlockEditor value={form.match} onChange={(match) => set({ match })} />
          </div>

          <div className="rounded-md border border-slate-700 p-3">
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Type parameters ({form.rule_type})
            </h4>
            <ParamsEditor ruleType={form.rule_type} params={form.params || {}} onChange={(params) => set({ params })} />
          </div>

          {isEdit && (
            <div className="rounded-md border border-sky-700/40 bg-sky-500/5 p-3">
              <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-sky-300">
                <FlaskConical size={13} /> Dry-run test — required before enabling
              </h4>
              <div className="flex flex-wrap items-end gap-2">
                <div>
                  <label className="text-xs text-slate-400">From</label>
                  <input
                    type="datetime-local"
                    className={inputClass}
                    value={testFrom}
                    onChange={(e) => setTestFrom(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">To</label>
                  <input
                    type="datetime-local"
                    className={inputClass}
                    value={testTo}
                    onChange={(e) => setTestTo(e.target.value)}
                  />
                </div>
                <Button size="sm" variant="secondary" onClick={runTest} loading={testing}>
                  Run test
                </Button>
              </div>

              {testResult && (
                <div className="mt-3 text-xs">
                  <p className="text-slate-300">
                    Scanned {testResult.events_scanned} event(s) in {testResult.duration_ms}ms —{" "}
                    <strong>{testResult.candidates.length}</strong> candidate(s) would be created. Nothing was
                    persisted.
                  </p>
                  <div className="mt-2 max-h-48 space-y-1.5 overflow-y-auto">
                    {testResult.candidates.map((c, i) => (
                      <div key={i} className="rounded border border-slate-700 bg-slate-900/60 p-2">
                        <div className="flex items-center justify-between">
                          <Badge severity={c.severity} />
                          <span className="text-slate-500">score {c.score}</span>
                        </div>
                        <p className="mt-1 text-slate-300">{c.summary}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
