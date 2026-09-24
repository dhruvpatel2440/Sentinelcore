import { useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { SEVERITY_OPTIONS } from "./constants";

/** Client-side preview only — a rough mirror of the server's defanging so an
 * analyst sees what will happen before submitting. The server is the real
 * normalizer and validator regardless. */
function previewNormalize(raw) {
  return raw
    .trim()
    .replace(/hxxps?:\/\//gi, (m) => m.replace(/hxx/i, "htt"))
    .replace(/\[\.\]|\(\.\)|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":")
    .toLowerCase();
}

export default function AddIocModal({ open, onClose, onAdded }) {
  const toast = useToast();
  const [tab, setTab] = useState("single"); // single | bulk
  const [indicator, setIndicator] = useState("");
  const [bulkText, setBulkText] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [threatType, setThreatType] = useState("");
  const [confidence, setConfidence] = useState(50);
  const [submitting, setSubmitting] = useState(false);
  const [bulkResult, setBulkResult] = useState(null);

  const reset = () => {
    setTab("single");
    setIndicator("");
    setBulkText("");
    setDescription("");
    setSeverity("medium");
    setThreatType("");
    setConfidence(50);
    setBulkResult(null);
  };

  const close = () => {
    reset();
    onClose();
  };

  const submitSingle = async () => {
    if (!indicator.trim() || !description.trim()) return;
    setSubmitting(true);
    try {
      await api.post("/intel/iocs", {
        indicator: indicator.trim(),
        description: description.trim(),
        severity,
        threat_type: threatType.trim() || null,
        confidence,
      });
      toast.success("IOC added");
      onAdded?.();
      close();
    } catch (err) {
      toast.error(err.message || "Could not add IOC");
    } finally {
      setSubmitting(false);
    }
  };

  const submitBulk = async () => {
    const lines = bulkText.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length || !description.trim()) return;
    setSubmitting(true);
    try {
      const result = await api.post("/intel/iocs/bulk", {
        indicators: lines,
        description: description.trim(),
        severity,
        threat_type: threatType.trim() || null,
        confidence,
      });
      setBulkResult(result);
      if (result.accepted_count > 0) onAdded?.();
      toast.success(`${result.accepted_count} accepted, ${result.rejected_count} rejected`);
    } catch (err) {
      toast.error(err.message || "Could not add IOCs");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add IOC"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {bulkResult ? "Close" : "Cancel"}
          </Button>
          {!bulkResult && (
            <Button
              onClick={tab === "single" ? submitSingle : submitBulk}
              loading={submitting}
              disabled={tab === "single" ? !indicator.trim() || !description.trim() : !bulkText.trim() || !description.trim()}
            >
              {tab === "single" ? "Add IOC" : "Add all"}
            </Button>
          )}
        </>
      }
    >
      <div className="mb-3 flex gap-1 border-b border-slate-700">
        {[
          { key: "single", label: "Single" },
          { key: "bulk", label: "Bulk paste" },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => {
              setTab(t.key);
              setBulkResult(null);
            }}
            className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.key ? "border-sky-500 text-slate-100" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "single" && !bulkResult && (
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Indicator</label>
            <input
              autoFocus
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              placeholder="hxxp://evil[.]com, 1.2.3.4, evil.com, a1b2c3…"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
            {indicator.trim() && (
              <p className="mt-1 text-xs text-slate-500">
                normalizes to <span className="font-mono text-sky-300">{previewNormalize(indicator)}</span>
              </p>
            )}
          </div>
          <SharedFields
            description={description} setDescription={setDescription}
            severity={severity} setSeverity={setSeverity}
            threatType={threatType} setThreatType={setThreatType}
            confidence={confidence} setConfidence={setConfidence}
          />
        </div>
      )}

      {tab === "bulk" && !bulkResult && (
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Indicators (one per line)</label>
            <textarea
              rows={6}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              placeholder={"1.2.3.4\nevil[.]com\nhxxp://bad[.]example/path"}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <SharedFields
            description={description} setDescription={setDescription}
            severity={severity} setSeverity={setSeverity}
            threatType={threatType} setThreatType={setThreatType}
            confidence={confidence} setConfidence={setConfidence}
          />
        </div>
      )}

      {bulkResult && (
        <div className="max-h-80 space-y-1 overflow-y-auto">
          {bulkResult.results.map((r, i) => (
            <div key={i} className="flex items-center justify-between gap-2 rounded border border-slate-700 px-2 py-1.5 text-xs">
              <span className="truncate font-mono text-slate-300">{r.input}</span>
              {r.accepted ? <Badge tone="success">Added</Badge> : <Badge tone="danger">{r.reason}</Badge>}
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

function SharedFields({ description, setDescription, severity, setSeverity, threatType, setThreatType, confidence, setConfidence }) {
  return (
    <>
      <div>
        <label className="text-xs font-medium text-slate-300">Description (required)</label>
        <textarea
          rows={2}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Why is this indicator known-bad?"
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
        />
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs font-medium text-slate-300">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Threat type</label>
          <input
            value={threatType}
            onChange={(e) => setThreatType(e.target.value)}
            placeholder="c2, phishing…"
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-300">Confidence</label>
          <input
            type="number"
            min={0}
            max={100}
            value={confidence}
            onChange={(e) => setConfidence(Number(e.target.value))}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
          />
        </div>
      </div>
    </>
  );
}
