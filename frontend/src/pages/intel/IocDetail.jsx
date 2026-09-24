import { ArrowLeft, ShieldAlert, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { eventSearchPivotUrl } from "./constants";

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-200">{children ?? "—"}</dd>
    </div>
  );
}

export default function IocDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { hasRole } = useAuth();
  const canWrite = hasRole("analyst", "admin");
  const isAdmin = hasRole("admin");

  const [ioc, setIoc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [retrohuntDays, setRetrohuntDays] = useState(7);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setIoc(await api.get(`/intel/iocs/${id}`));
    } catch (err) {
      toast.error(err.message || "Could not load IOC");
      navigate("/intel");
    } finally {
      setLoading(false);
    }
  }, [id, navigate, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleActive = async () => {
    try {
      const updated = await api.patch(`/intel/iocs/${id}`, { is_active: !ioc.is_active });
      setIoc((i) => ({ ...i, ...updated }));
    } catch (err) {
      toast.error(err.message || "Could not update IOC");
    }
  };

  const remove = async () => {
    if (!window.confirm("Delete this manually-added IOC?")) return;
    try {
      await api.del(`/intel/iocs/${id}`);
      toast.success("IOC deleted");
      navigate("/intel");
    } catch (err) {
      toast.error(err.message || "Could not delete IOC");
    }
  };

  const runRetrohunt = async () => {
    try {
      await api.post("/intel/retrohunt", { ioc_id: id, days: retrohuntDays });
      toast.success(`Retro-hunt started over the last ${retrohuntDays} day(s) — check Matches shortly`);
    } catch (err) {
      toast.error(err.message || "Could not start retro-hunt");
    }
  };

  if (loading || !ioc) {
    return <p className="text-sm text-slate-400">Loading…</p>;
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <button onClick={() => navigate("/intel")} className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100">
            <ArrowLeft size={16} />
          </button>
          <div>
            <h1 className="font-mono text-xl font-semibold tracking-tight text-slate-100">{ioc.indicator}</h1>
            <p className="mt-1 text-sm text-slate-400">
              {ioc.ioc_type} · added {relativeTime(ioc.created_at)} · {ioc.source_name || "manual"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge severity={ioc.severity} />
          {canWrite && (
            <Button size="sm" variant="secondary" onClick={toggleActive}>
              {ioc.is_active ? "Deactivate" : "Reactivate"}
            </Button>
          )}
          {canWrite && !ioc.source_id && (
            <Button size="sm" variant="danger" icon={Trash2} onClick={remove}>
              Delete
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[18rem_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title="Details">
            <dl className="space-y-3">
              <Field label="Description">{ioc.description}</Field>
              <Field label="Threat type">{ioc.threat_type}</Field>
              <Field label="Confidence">{ioc.confidence}%</Field>
              <Field label="Tags">{ioc.tags?.length ? ioc.tags.join(", ") : "—"}</Field>
              <Field label="First seen">{absoluteTime(ioc.first_seen)}</Field>
              <Field label="Last seen">{absoluteTime(ioc.last_seen)}</Field>
              <Field label="Expires">{ioc.expires_at ? absoluteTime(ioc.expires_at) : "never"}</Field>
              <Field label="Status">
                <Badge tone={ioc.is_active ? "success" : "neutral"}>{ioc.is_active ? "Active" : "Inactive"}</Badge>
              </Field>
            </dl>
          </Card>

          {isAdmin && (
            <Card title="Retro-hunt" description="Scan historical events for this indicator.">
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={retrohuntDays}
                  onChange={(e) => setRetrohuntDays(Number(e.target.value))}
                  className="w-20 rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
                />
                <span className="text-xs text-slate-400">days back</span>
                <Button size="sm" onClick={runRetrohunt}>
                  Run
                </Button>
              </div>
            </Card>
          )}

          {ioc.affected_assets?.length > 0 && (
            <Card title="Affected assets">
              <ul className="space-y-1 text-sm text-slate-300">
                {ioc.affected_assets.map((a) => (
                  <li key={a} className="font-mono text-xs">
                    {a}
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <Card title={`Match history (${ioc.match_count})`}>
          <Table
            columns={[
              { key: "matched_field", header: "Field", render: (m) => <Badge tone="neutral">{m.matched_field}</Badge> },
              { key: "matched_value", header: "Value", className: "max-w-xs truncate font-mono text-xs", render: (m) => m.matched_value },
              {
                key: "ts", header: "Time",
                render: (m) => <span title={absoluteTime(m.ts)}>{relativeTime(m.ts)}</span>,
              },
              {
                key: "pivot", header: "",
                render: (m) => (
                  <Link className="text-xs text-sky-300 hover:underline" to={eventSearchPivotUrl(m.matched_value)}>
                    Search events
                  </Link>
                ),
              },
            ]}
            rows={ioc.recent_matches}
            rowKey={(m) => m.id}
            empty={
              <div className="px-4 py-8 text-center">
                <ShieldAlert size={24} className="mx-auto mb-2 text-slate-600" />
                <p className="text-xs text-slate-500">No matches yet — this indicator has not been seen in traffic.</p>
              </div>
            }
          />
        </Card>
      </div>
    </>
  );
}
