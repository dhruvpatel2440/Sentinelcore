import { AlertTriangle, Plus, RefreshCw, ShieldBan, ShieldOff } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { STATUS_TONE, directionLabel, formatCountdown } from "./constants";
import NewBlockModal from "./NewBlockModal";

const POLL_MS = 5_000;
const TICK_MS = 1_000;

function Countdown({ expiresAt, active }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return undefined;
    const timer = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(timer);
  }, [active]);
  if (!active) return <span className="text-slate-500">—</span>;
  const seconds = Math.round((new Date(expiresAt).getTime() - now) / 1000);
  return <span className={seconds < 60 ? "text-rose-300" : "text-slate-200"}>{formatCountdown(seconds)}</span>;
}

export default function FirewallPage() {
  const toast = useToast();
  const [tab, setTab] = useState("active");
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [extendTarget, setExtendTarget] = useState(null);
  const [extendSeconds, setExtendSeconds] = useState(3600);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revokeReason, setRevokeReason] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = tab === "active" ? "?status=active" : "";
      const [rows, statusData] = await Promise.all([
        api.get(`/firewall/actions${params}`),
        api.get("/firewall/status").catch(() => null),
      ]);
      setActions(tab === "active" ? rows : rows.filter((r) => r.status !== "active" && r.status !== "pending"));
      setStatus(statusData);
    } catch (err) {
      toast.error(err.message || "Could not load firewall data");
    } finally {
      setLoading(false);
    }
  }, [tab, toast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  const revoke = async () => {
    try {
      await api.del(`/firewall/actions/${revokeTarget.id}${revokeReason ? `?reason=${encodeURIComponent(revokeReason)}` : ""}`);
      toast.success("Block revoked");
      setRevokeTarget(null);
      setRevokeReason("");
      load();
    } catch (err) {
      toast.error(err.message || "Could not revoke");
    }
  };

  const extend = async () => {
    try {
      await api.post(`/firewall/actions/${extendTarget.id}/extend`, { additional_seconds: Number(extendSeconds) });
      toast.success("Extended");
      setExtendTarget(null);
      load();
    } catch (err) {
      toast.error(err.message || "Could not extend");
    }
  };

  const columns = [
    { key: "target", header: "Target", className: "font-mono", render: (a) => a.target },
    { key: "direction", header: "Direction", render: (a) => directionLabel(a.direction) },
    {
      key: "proto",
      header: "Proto/Port",
      render: (a) => (a.protocol ? `${a.protocol.toUpperCase()}${a.port ? `/${a.port}` : ""}` : "—"),
    },
    { key: "reason", header: "Reason", className: "max-w-xs truncate" },
    { key: "incident_id", header: "Incident", render: (a) => (a.incident_id ? a.incident_id.slice(0, 8) : "—") },
    { key: "status", header: "Status", render: (a) => <Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge> },
    ...(tab === "active"
      ? [
          {
            key: "countdown",
            header: "Expires in",
            render: (a) => <Countdown expiresAt={a.expires_at} active={a.status === "active"} />,
          },
          {
            key: "actions",
            header: "",
            render: (a) => (
              <div className="flex gap-1">
                <Button size="sm" variant="secondary" onClick={() => { setExtendTarget(a); setExtendSeconds(3600); }}>
                  Extend
                </Button>
                <Button size="sm" variant="danger" onClick={() => setRevokeTarget(a)}>
                  Revoke
                </Button>
              </div>
            ),
          },
        ]
      : [{ key: "created_at", header: "Created", render: (a) => relativeTime(a.created_at) }]),
  ];

  const driftOrDown = status && (!status.helper_reachable || status.drift_count > 0);

  return (
    <>
      <PageHeader
        title="Firewall"
        description="TTL-bounded containment via the privileged helper. Every block auto-expires; nothing here is permanent."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" icon={RefreshCw} onClick={load} disabled={loading}>
              Refresh
            </Button>
            <Button icon={Plus} onClick={() => setModalOpen(true)}>
              New block
            </Button>
          </div>
        }
      />

      {driftOrDown && (
        <div className="mb-4 flex items-center gap-2 rounded-md border border-amber-700/50 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
          <AlertTriangle size={16} />
          {!status.helper_reachable
            ? "Privileged helper is unreachable — this view shows intent, not confirmed reality."
            : `Drift detected: ${status.drift_count} rule(s) out of sync between the database and the kernel.`}
        </div>
      )}

      {status && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-slate-800 px-3 py-2">
            <p className="text-xs text-slate-500">Active blocks</p>
            <p className="text-lg font-semibold text-slate-100">{status.db_active_count}</p>
          </div>
          <div className="rounded-lg border border-slate-800 px-3 py-2">
            <p className="text-xs text-slate-500">Kernel rules</p>
            <p className="text-lg font-semibold text-slate-100">{status.active_rule_count}</p>
          </div>
          <div className="rounded-lg border border-slate-800 px-3 py-2">
            <p className="text-xs text-slate-500">Drift</p>
            <p className={`text-lg font-semibold ${status.drift_count ? "text-amber-300" : "text-slate-100"}`}>{status.drift_count}</p>
          </div>
          <div className="rounded-lg border border-slate-800 px-3 py-2">
            <p className="text-xs text-slate-500">Last reconciliation</p>
            <p className="text-sm text-slate-300">{status.last_reconciliation_at ? relativeTime(status.last_reconciliation_at) : "never"}</p>
          </div>
        </div>
      )}

      <div className="mb-4 flex gap-1 border-b border-slate-800">
        {[
          { key: "active", label: "Active blocks" },
          { key: "history", label: "History" },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.key ? "border-sky-500 text-slate-100" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <Table
        columns={columns}
        rows={actions}
        loading={loading}
        rowKey={(a) => a.id}
        empty={
          <EmptyState
            icon={tab === "active" ? ShieldBan : ShieldOff}
            title={tab === "active" ? "No active blocks" : "No history yet"}
            description={tab === "active" ? "Containment actions you create appear here with a live countdown." : "Expired, revoked and failed actions appear here."}
          />
        }
      />

      <NewBlockModal open={modalOpen} onClose={() => setModalOpen(false)} onCreated={load} />

      <Modal
        open={Boolean(extendTarget)}
        onClose={() => setExtendTarget(null)}
        title="Extend block"
        footer={
          <>
            <Button variant="ghost" onClick={() => setExtendTarget(null)}>
              Cancel
            </Button>
            <Button onClick={extend}>Extend</Button>
          </>
        }
      >
        <label className="text-xs font-medium text-slate-300">Additional seconds</label>
        <input
          value={extendSeconds}
          onChange={(e) => setExtendSeconds(e.target.value.replace(/\D/g, ""))}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
        />
      </Modal>

      <Modal
        open={Boolean(revokeTarget)}
        onClose={() => setRevokeTarget(null)}
        title={`Revoke block on ${revokeTarget?.target ?? ""}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevokeTarget(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={revoke}>
              Revoke now
            </Button>
          </>
        }
      >
        <label className="text-xs font-medium text-slate-300">Reason (optional)</label>
        <textarea
          rows={2}
          value={revokeReason}
          onChange={(e) => setRevokeReason(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
        />
      </Modal>
    </>
  );
}
