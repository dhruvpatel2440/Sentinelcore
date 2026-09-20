import { useEffect, useState } from "react";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";

const PORT_STATE_TONE = {
  open: "success",
  filtered: "warning",
  closed: "neutral",
};

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-all text-sm text-slate-200">{children ?? "—"}</dd>
    </div>
  );
}

export default function AssetDetail({ assetId, open, onClose, onSaved }) {
  const { hasRole } = useAuth();
  const toast = useToast();

  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState("");
  const [hostnameOverride, setHostnameOverride] = useState("");
  const [saving, setSaving] = useState(false);

  const canEdit = hasRole("analyst", "admin");

  useEffect(() => {
    if (!open || !assetId) return undefined;
    let cancelled = false;

    setLoading(true);
    api
      .get(`/assets/${assetId}`)
      .then((data) => {
        if (cancelled) return;
        setAsset(data);
        setNotes(data.notes ?? "");
        setHostnameOverride(data.hostname_override ?? "");
      })
      .catch((err) => !cancelled && toast.error(err.message || "Could not load asset"))
      .finally(() => !cancelled && setLoading(false));

    return () => {
      cancelled = true;
    };
  }, [assetId, open, toast]);

  const save = async () => {
    setSaving(true);
    try {
      const updated = await api.patch(`/assets/${assetId}`, {
        notes,
        hostname_override: hostnameOverride || null,
      });
      setAsset(updated);
      toast.success("Asset updated");
      onSaved?.(updated);
    } catch (err) {
      toast.error(err.message || "Could not save changes");
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    { key: "port", header: "Port", className: "font-mono text-slate-100" },
    { key: "protocol", header: "Proto", render: (r) => r.protocol.toUpperCase() },
    {
      key: "state",
      header: "State",
      render: (r) => <Badge tone={PORT_STATE_TONE[r.state] ?? "neutral"}>{r.state}</Badge>,
    },
    { key: "service", header: "Service", render: (r) => r.service ?? "—" },
    { key: "product", header: "Product", render: (r) => r.product ?? "—" },
    { key: "version", header: "Version", render: (r) => r.version ?? "—" },
    { key: "last_seen", header: "Last seen", render: (r) => relativeTime(r.last_seen) },
  ];

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={asset ? (asset.hostname_override || asset.hostname || asset.ip_address) : "Asset"}
      description={asset?.ip_address}
      footer={
        canEdit ? (
          <>
            <Button variant="ghost" onClick={onClose} disabled={saving}>
              Close
            </Button>
            <Button onClick={save} loading={saving}>
              Save changes
            </Button>
          </>
        ) : (
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        )
      }
    >
      {loading && <p className="text-sm text-slate-400">Loading…</p>}

      {!loading && asset && (
        <div className="space-y-6">
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Field label="IP address">{asset.ip_address}</Field>
            <Field label="MAC address">{asset.mac_address}</Field>
            <Field label="Vendor">{asset.vendor}</Field>
            <Field label="Hostname">{asset.hostname}</Field>
            <Field label="OS guess">{asset.os_guess}</Field>
            <Field label="Status">
              <Badge tone={asset.is_active ? "success" : "neutral"}>
                {asset.is_active ? "active" : "inactive"}
              </Badge>
            </Field>
            <Field label="First seen">{absoluteTime(asset.first_seen)}</Field>
            <Field label="Last seen">{relativeTime(asset.last_seen)}</Field>
            <Field label="Open ports">{asset.open_port_count}</Field>
          </dl>

          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Ports
            </h4>
            <Table
              columns={columns}
              rows={asset.ports}
              rowKey={(r) => r.id}
              empty={
                <p className="px-4 py-6 text-center text-xs text-slate-500">
                  No ports recorded for this host.
                </p>
              }
            />
          </div>

          <div className="space-y-3">
            <div>
              <label
                htmlFor="hostname-override"
                className="block text-xs font-medium text-slate-300"
              >
                Hostname override
              </label>
              <input
                id="hostname-override"
                value={hostnameOverride}
                disabled={!canEdit}
                onChange={(e) => setHostnameOverride(e.target.value)}
                placeholder={asset.hostname ?? "Not detected"}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-60"
              />
            </div>

            <div>
              <label htmlFor="asset-notes" className="block text-xs font-medium text-slate-300">
                Analyst notes
              </label>
              <textarea
                id="asset-notes"
                rows={4}
                value={notes}
                disabled={!canEdit}
                onChange={(e) => setNotes(e.target.value)}
                placeholder={canEdit ? "Context for the next responder…" : "Read only"}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-60"
              />
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}
