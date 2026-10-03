import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";

/** Attach a capture to an incident — analyst/admin only, audited server-side. */
export default function AttachModal({ open, onClose, pcap, onAttached }) {
  const toast = useToast();
  const [incidents, setIncidents] = useState([]);
  const [incidentId, setIncidentId] = useState("");
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setIncidentId(pcap?.incident_id || "");
    setLoading(true);
    api
      .get("/incidents?status=new&status=triage&status=investigating&status=contained&limit=100")
      .then((data) => setIncidents(data.items))
      .catch(() => setIncidents([]))
      .finally(() => setLoading(false));
  }, [open, pcap]);

  const submit = async () => {
    if (!incidentId) return;
    setSubmitting(true);
    try {
      await api.post(`/pcap/${pcap.id}/attach`, { incident_id: incidentId });
      toast.success("Capture attached to incident");
      onAttached?.();
      onClose();
    } catch (err) {
      toast.error(err.message || "Could not attach capture");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Attach to incident"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} loading={submitting} disabled={!incidentId}>
            Attach
          </Button>
        </>
      }
    >
      <label className="text-xs font-medium text-slate-300">Open incident</label>
      <select
        value={incidentId}
        onChange={(e) => setIncidentId(e.target.value)}
        disabled={loading}
        className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
      >
        <option value="">Select an incident…</option>
        {incidents.map((i) => (
          <option key={i.id} value={i.id}>
            INC-{i.number} — {i.title}
          </option>
        ))}
      </select>
    </Modal>
  );
}
