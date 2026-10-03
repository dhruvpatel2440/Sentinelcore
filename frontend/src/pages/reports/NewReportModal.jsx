import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { EVENT_TYPES, SEVERITIES } from "../events/filters";
import { STATUS_LABEL } from "../incidents/constants";
import { FORMATS, RANGE_PRESETS, REPORT_TYPES } from "./constants";

const INCIDENT_STATUSES = Object.keys(STATUS_LABEL);

function defaultWindow() {
  const to = new Date();
  const from = new Date(to.getTime() - RANGE_PRESETS[2].ms); // 24h
  return { from: from.toISOString(), to: to.toISOString() };
}

function MultiCheck({ options, selected, onToggle, labelFor = (v) => v }) {
  return (
    <div className="flex flex-wrap gap-2">
      {options.map((opt) => (
        <label
          key={opt}
          className="flex cursor-pointer items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300"
        >
          <input
            type="checkbox"
            checked={selected.includes(opt)}
            onChange={() => onToggle(opt)}
            className="rounded border-slate-600 bg-slate-900 text-sky-500"
          />
          {labelFor(opt)}
        </label>
      ))}
    </div>
  );
}

/**
 * Type picker + per-type param form. When `prefill` is set (from the M8
 * incident detail "Generate report" shortcut), the type is locked to
 * incident_detail and the incident is already chosen — that is where the
 * need for this report actually arises.
 */
export default function NewReportModal({ open, onClose, onCreated, prefill }) {
  const toast = useToast();
  const [type, setType] = useState(prefill?.reportType || "incident_summary");
  const [format, setFormat] = useState("pdf");
  const [title, setTitle] = useState("");
  const [window_, setWindow] = useState(defaultWindow());
  const [severity, setSeverity] = useState([]);
  const [status, setStatus] = useState([]);
  const [eventType, setEventType] = useState([]);
  const [incidentId, setIncidentId] = useState(prefill?.incidentId || "");
  const [isActive, setIsActive] = useState("");
  const [cidr, setCidr] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState(null);

  useEffect(() => {
    if (!open) return;
    setType(prefill?.reportType || "incident_summary");
    setIncidentId(prefill?.incidentId || "");
    setTitle(prefill?.title || "");
    setFormat("pdf");
    setWindow(defaultWindow());
    setSeverity([]);
    setStatus([]);
    setEventType([]);
    setIsActive("");
    setCidr("");
    setFieldErrors(null);
  }, [open, prefill]);

  const meta = REPORT_TYPES.find((t) => t.key === type);
  const locked = Boolean(prefill?.reportType);

  const toggle = (list, setList, value) =>
    setList(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);

  const buildParams = () => {
    if (type === "incident_detail") return { incident_id: incidentId.trim() };
    if (type === "asset_inventory") {
      const params = {};
      if (isActive !== "") params.is_active = isActive === "true";
      if (cidr.trim()) params.cidr = cidr.trim();
      return params;
    }
    const params = { from: window_.from, to: window_.to };
    if (severity.length) params.severity = severity;
    if (type === "incident_summary" && status.length) params.status = status;
    if (type === "event_statistics" && eventType.length) params.event_type = eventType;
    return params;
  };

  const submit = async () => {
    setSubmitting(true);
    setFieldErrors(null);
    try {
      await api.post("/reports", {
        report_type: type,
        format,
        params: buildParams(),
        title: title.trim() || undefined,
      });
      toast.success("Report queued");
      onCreated?.();
      onClose();
    } catch (err) {
      if (Array.isArray(err.detail)) {
        setFieldErrors(err.detail.map((e) => e.msg).join("; "));
      } else {
        toast.error(err.message || "Could not create report");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmit = type === "incident_detail" ? Boolean(incidentId.trim()) : true;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New report"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={submitting} disabled={!canSubmit}>
            Generate
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <label className="text-xs font-medium text-slate-300">Report type</label>
          <select
            value={type}
            disabled={locked}
            onChange={(e) => setType(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
          >
            {REPORT_TYPES.map((t) => (
              <option key={t.key} value={t.key}>
                {t.label}
              </option>
            ))}
          </select>
          {meta && <p className="mt-1 text-xs text-slate-500">{meta.description}</p>}
        </div>

        {type === "incident_detail" && (
          <div>
            <label className="text-xs font-medium text-slate-300">Incident ID</label>
            <input
              value={incidentId}
              disabled={locked}
              onChange={(e) => setIncidentId(e.target.value)}
              placeholder="UUID"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
            />
          </div>
        )}

        {meta?.needsWindow && (
          <div>
            <label className="text-xs font-medium text-slate-300">Window</label>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {RANGE_PRESETS.map((p) => (
                <button
                  key={p.key}
                  type="button"
                  onClick={() => {
                    const to = new Date();
                    const from = new Date(to.getTime() - p.ms);
                    setWindow({ from: from.toISOString(), to: to.toISOString() });
                  }}
                  className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300 hover:border-sky-500"
                >
                  {p.label}
                </button>
              ))}
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2">
              <input
                type="datetime-local"
                value={window_.from.slice(0, 16)}
                onChange={(e) => setWindow((w) => ({ ...w, from: new Date(e.target.value).toISOString() }))}
                className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
              />
              <input
                type="datetime-local"
                value={window_.to.slice(0, 16)}
                onChange={(e) => setWindow((w) => ({ ...w, to: new Date(e.target.value).toISOString() }))}
                className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
              />
            </div>
          </div>
        )}

        {(type === "incident_summary" || type === "event_statistics") && (
          <div>
            <label className="text-xs font-medium text-slate-300">Severity filter (optional)</label>
            <div className="mt-1">
              <MultiCheck options={SEVERITIES} selected={severity} onToggle={(v) => toggle(severity, setSeverity, v)} />
            </div>
          </div>
        )}

        {type === "incident_summary" && (
          <div>
            <label className="text-xs font-medium text-slate-300">Status filter (optional)</label>
            <div className="mt-1">
              <MultiCheck
                options={INCIDENT_STATUSES}
                selected={status}
                onToggle={(v) => toggle(status, setStatus, v)}
                labelFor={(v) => STATUS_LABEL[v]}
              />
            </div>
          </div>
        )}

        {type === "event_statistics" && (
          <div>
            <label className="text-xs font-medium text-slate-300">Event type filter (optional)</label>
            <div className="mt-1">
              <MultiCheck options={EVENT_TYPES} selected={eventType} onToggle={(v) => toggle(eventType, setEventType, v)} />
            </div>
          </div>
        )}

        {type === "asset_inventory" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Active only</label>
              <select
                value={isActive}
                onChange={(e) => setIsActive(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                <option value="">Any</option>
                <option value="true">Active</option>
                <option value="false">Inactive</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">CIDR filter (optional)</label>
              <input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="10.0.0.0/24"
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              />
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
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
          <div>
            <label className="text-xs font-medium text-slate-300">Title (optional)</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={meta?.label}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            />
          </div>
        </div>

        {fieldErrors && <p className="text-xs text-rose-400">{fieldErrors}</p>}
      </div>
    </Modal>
  );
}
