import { useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { TTL_PRESETS, isWideCidr } from "./constants";

const PRECHECK_DEBOUNCE_MS = 400;

/**
 * Two-step flow: fill in the block, then a plain-language confirmation
 * screen restating target/scope/duration. A CIDR wider than /29 additionally
 * requires typing the target back — blocking a range is not the same
 * gesture as blocking a single host.
 */
export default function NewBlockModal({ open, onClose, onCreated, prefill }) {
  const toast = useToast();
  const [step, setStep] = useState("form"); // "form" | "confirm"
  const [target, setTarget] = useState("");
  const [direction, setDirection] = useState("inbound");
  const [protocol, setProtocol] = useState("");
  const [port, setPort] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(3600);
  const [customTtl, setCustomTtl] = useState("");
  const [reason, setReason] = useState("");
  const [incidentId, setIncidentId] = useState(prefill?.incidentId || "");
  const [precheck, setPrecheck] = useState(null); // { allowed, reason } | null | "checking"
  const [confirmTyped, setConfirmTyped] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const debounceRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setStep("form");
    setTarget(prefill?.target || "");
    setDirection("inbound");
    setProtocol("");
    setPort("");
    setTtlSeconds(3600);
    setCustomTtl("");
    setReason(prefill?.reason || "");
    setIncidentId(prefill?.incidentId || "");
    setPrecheck(null);
    setConfirmTyped("");
  }, [open, prefill]);

  useEffect(() => {
    clearTimeout(debounceRef.current);
    if (!target.trim()) {
      setPrecheck(null);
      return;
    }
    setPrecheck("checking");
    debounceRef.current = setTimeout(async () => {
      try {
        const result = await api.post("/firewall/precheck", { target: target.trim() });
        setPrecheck(result);
      } catch {
        setPrecheck(null);
      }
    }, PRECHECK_DEBOUNCE_MS);
    return () => clearTimeout(debounceRef.current);
  }, [target]);

  const effectiveTtl = customTtl ? Number(customTtl) : ttlSeconds;
  const wide = isWideCidr(target.trim());
  const canProceedToConfirm =
    target.trim() &&
    reason.trim() &&
    effectiveTtl > 0 &&
    (precheck === null || precheck === "checking" || precheck.allowed !== false);

  const submit = async () => {
    setSubmitting(true);
    try {
      const created = await api.post("/firewall/actions", {
        target: target.trim(),
        direction,
        protocol: protocol || undefined,
        port: port ? Number(port) : undefined,
        ttl_seconds: effectiveTtl,
        reason: reason.trim(),
        incident_id: incidentId || undefined,
      });
      toast.success(`Blocking ${created.target}`);
      onCreated?.();
      onClose();
    } catch (err) {
      if (Array.isArray(err.detail)) {
        toast.error(err.detail.map((e) => e.msg).join("; "));
      } else {
        toast.error(err.message || "Could not create block");
      }
      setStep("form");
    } finally {
      setSubmitting(false);
    }
  };

  const directionText = { inbound: "inbound traffic from", outbound: "outbound traffic to", both: "traffic to/from" }[direction];
  const durationText = effectiveTtl >= 3600 ? `${(effectiveTtl / 3600).toFixed(effectiveTtl % 3600 ? 1 : 0)} hour(s)` : `${Math.round(effectiveTtl / 60)} minute(s)`;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={step === "form" ? "New containment block" : "Confirm block"}
      size="md"
      footer={
        step === "form" ? (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={!canProceedToConfirm} onClick={() => setStep("confirm")}>
              Continue
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={() => setStep("form")}>
              Back
            </Button>
            <Button
              variant="danger"
              loading={submitting}
              disabled={wide && confirmTyped.trim() !== target.trim()}
              onClick={submit}
            >
              Block now
            </Button>
          </>
        )
      }
    >
      {step === "form" ? (
        <div className="space-y-4">
          <div>
            <label className="text-xs font-medium text-slate-300">Target (IP or CIDR)</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.10.57 or 192.168.10.0/28"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
            {precheck === "checking" && <p className="mt-1 text-xs text-slate-500">Checking…</p>}
            {precheck && precheck !== "checking" && precheck.allowed === false && (
              <p className="mt-1 text-xs text-rose-400">Refused: {precheck.reason}</p>
            )}
            {precheck && precheck !== "checking" && precheck.allowed === true && (
              <p className="mt-1 text-xs text-emerald-400">Target is blockable.</p>
            )}
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Direction</label>
              <select
                value={direction}
                onChange={(e) => setDirection(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                <option value="inbound">Inbound</option>
                <option value="outbound">Outbound</option>
                <option value="both">Both</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Protocol (optional)</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                <option value="">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Port (optional)</label>
              <input
                value={port}
                onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
                placeholder="22"
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Duration</label>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {TTL_PRESETS.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => {
                    setTtlSeconds(p.seconds);
                    setCustomTtl("");
                  }}
                  className={`rounded-md border px-2.5 py-1 text-xs ${
                    !customTtl && ttlSeconds === p.seconds
                      ? "border-sky-500 text-sky-300"
                      : "border-slate-700 text-slate-300 hover:border-sky-500"
                  }`}
                >
                  {p.label}
                </button>
              ))}
              <input
                value={customTtl}
                onChange={(e) => setCustomTtl(e.target.value.replace(/\D/g, ""))}
                placeholder="custom seconds"
                className="w-32 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Reason (required)</label>
            <textarea
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Linked incident (optional)</label>
            <input
              value={incidentId}
              disabled={Boolean(prefill?.incidentId)}
              onChange={(e) => setIncidentId(e.target.value)}
              placeholder="Incident UUID"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
            />
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="rounded-md border border-amber-700/50 bg-amber-500/5 px-3 py-3 text-sm text-amber-200">
            Block {directionText} <strong className="font-mono">{target.trim()}</strong>
            {protocol && <> on <strong>{protocol.toUpperCase()}</strong></>}
            {port && <> port <strong>{port}</strong></>} for <strong>{durationText}</strong>.
          </p>
          <p className="text-xs text-slate-400">Reason: {reason.trim()}</p>

          {wide && (
            <div>
              <label className="text-xs font-medium text-rose-300">
                This is a range wider than /29 — type the target to confirm you mean it.
              </label>
              <input
                value={confirmTyped}
                onChange={(e) => setConfirmTyped(e.target.value)}
                placeholder={target.trim()}
                className="mt-1 w-full rounded-md border border-rose-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100 focus:border-rose-500 focus:outline-none focus:ring-1 focus:ring-rose-500"
              />
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
