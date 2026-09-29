import { useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";

const MODES = [
  { value: "tcp_syn", label: "TCP SYN (fast, default)" },
  { value: "tcp_connect", label: "TCP connect" },
  { value: "service_version", label: "Service + version detection" },
  { value: "udp", label: "UDP" },
  { value: "ping", label: "Host discovery only" },
];

export default function ScanModal({ open, onClose, defaultTarget, onStarted }) {
  const toast = useToast();
  const [targets, setTargets] = useState(defaultTarget ?? "");
  const [ports, setPorts] = useState("1-1024");
  const [mode, setMode] = useState("tcp_syn");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);

  const portsDisabled = mode === "ping";

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      const body = {
        targets: targets
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        ports,
        mode,
      };
      const scan = await api.post("/assets/scan", body);
      toast.info("Discovery scan started");
      onStarted?.(scan);
      onClose();
    } catch (err) {
      // 409 = another scan running; 422 = target outside MONITORED_NETWORK.
      setError(err.message || "Could not start the scan");
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Run discovery scan"
      description="Targets must fall inside the monitored network."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={submit} loading={pending}>
            Start scan
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="targets" className="block text-xs font-medium text-slate-300">
            Targets
          </label>
          <input
            id="targets"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder={defaultTarget}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
          <p className="mt-1 text-xs text-slate-500">
            Comma-separated IPs or CIDRs. Defaults to {defaultTarget}.
          </p>
        </div>

        <div>
          <label htmlFor="mode" className="block text-xs font-medium text-slate-300">
            Scan mode
          </label>
          <select
            id="mode"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          >
            {MODES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="ports" className="block text-xs font-medium text-slate-300">
            Ports
          </label>
          <input
            id="ports"
            value={ports}
            disabled={portsDisabled}
            onChange={(e) => setPorts(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
          />
          <p className="mt-1 text-xs text-slate-500">
            {portsDisabled
              ? "Host discovery does not scan ports."
              : "Digits, ranges and commas only — e.g. 22,80,1-1024."}
          </p>
        </div>

        {error && (
          <p
            role="alert"
            className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
          >
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}
