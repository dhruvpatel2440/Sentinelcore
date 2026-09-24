import { Activity, AlertTriangle, RefreshCw, Radar, ServerCog, ShieldAlert, ShieldBan, Target } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { duration, relativeTime } from "../../lib/format";

const REFRESH_MS = 15_000;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/** A tile that survives its own endpoint failing — one dead module must not
 *  blank the whole dashboard. */
function Stat({ label, value, sub, tone, to, icon: Icon }) {
  const inner = (
    <Card bodyClassName="p-3" className={to ? "transition-colors hover:border-slate-600" : undefined}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-xs text-slate-500">{label}</p>
          <p className="mt-0.5 truncate text-2xl font-semibold text-slate-100">{value}</p>
          {sub && <p className="mt-0.5 truncate text-xs text-slate-500">{sub}</p>}
        </div>
        {Icon && <Icon size={18} className={tone === "danger" ? "text-rose-400" : "text-slate-600"} aria-hidden="true" />}
      </div>
    </Card>
  );
  return to ? <Link to={to}>{inner}</Link> : inner;
}

export default function OverviewPage() {
  const toast = useToast();
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");

  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState(null);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      // Every tile is fetched independently and failures are tolerated: an
      // unreachable sensor or a 403 on an admin-only endpoint must degrade
      // that one tile, not the page.
      const get = (p) => api.get(p).catch(() => null);
      const [facets, incidents, pipeline, sensor, intel, recent, firewall] = await Promise.all([
        get("/events/facets"),
        get("/incidents/stats/summary"),
        get("/pipeline/status"),
        get("/sensor/status"),
        get("/intel/stats"),
        get("/events?severity=critical&severity=high&limit=8"),
        isAdmin ? get("/firewall/status") : Promise.resolve(null),
      ]);
      setData({ facets, incidents, pipeline, sensor, intel, recent, firewall });
      setLoadedAt(new Date());
      if (!silent) setLoading(false);
    },
    [isAdmin],
  );

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => load(true), REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  const { facets, incidents, pipeline, sensor, intel, recent, firewall } = data;

  const openIncidents = incidents ? Object.values(incidents.open_by_severity || {}).reduce((a, b) => a + b, 0) : null;
  const sevBuckets = facets?.severity || [];
  const maxSev = Math.max(1, ...sevBuckets.map((b) => b.count));

  const sensorDown = sensor && !sensor.running;
  const sensorStale = sensor?.eve_log_stale;
  const feedsFailing = (intel?.source_health || []).filter((s) => s.last_status === "error");

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          loadedAt ? `Platform posture · updated ${relativeTime(loadedAt.toISOString())}` : "Platform-wide detection and response posture."
        }
        actions={
          <Button variant="secondary" icon={RefreshCw} onClick={() => load()} disabled={loading}>
            Refresh
          </Button>
        }
      />

      {/* Things that are actively wrong get surfaced above everything else. */}
      <div className="mb-4 space-y-2">
        {sensorDown && (
          <div className="flex items-center gap-2 rounded-md bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-inset ring-rose-500/30">
            <AlertTriangle size={14} /> The Suricata sensor is not running — no new detections are being produced.
            {isAdmin && (
              <Link to="/sensor" className="ml-1 underline">
                Open sensor control
              </Link>
            )}
          </div>
        )}
        {!sensorDown && sensorStale && (
          <div className="flex items-center gap-2 rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-300 ring-1 ring-inset ring-amber-500/30">
            <AlertTriangle size={14} /> The sensor is up but its event log has gone stale
            {sensor?.eve_log_age_seconds != null ? ` (${duration(sensor.eve_log_age_seconds)} old)` : ""}.
          </div>
        )}
        {feedsFailing.length > 0 && (
          <div className="flex items-center gap-2 rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-300 ring-1 ring-inset ring-amber-500/30">
            <AlertTriangle size={14} /> {feedsFailing.length} threat-intel feed
            {feedsFailing.length === 1 ? "" : "s"} failing to refresh — the platform is quietly less protected.
            <Link to="/intel" className="ml-1 underline">
              Review sources
            </Link>
          </div>
        )}
        {firewall?.drift_count > 0 && (
          <div className="flex items-center gap-2 rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-300 ring-1 ring-inset ring-amber-500/30">
            <AlertTriangle size={14} /> {firewall.drift_count} firewall rule(s) drifted from the intended state.
          </div>
        )}
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat
          label="Open incidents"
          value={openIncidents ?? "—"}
          sub={incidents ? `${incidents.unassigned_count} unassigned` : "unavailable"}
          tone={openIncidents ? "danger" : undefined}
          to="/incidents"
          icon={ShieldAlert}
        />
        <Stat
          label="Events / sec"
          value={pipeline ? pipeline.events_per_second.toFixed(2) : "—"}
          sub={pipeline ? `${pipeline.events_last_minute} in the last minute` : "pipeline unavailable"}
          to="/events"
          icon={Activity}
        />
        <Stat
          label="Sensor"
          value={sensor ? (sensor.running ? "Running" : "Stopped") : "—"}
          sub={sensor ? `${sensor.rule_count.toLocaleString()} rules loaded` : "unavailable"}
          tone={sensorDown ? "danger" : undefined}
          to={isAdmin ? "/sensor" : undefined}
          icon={ServerCog}
        />
        <Stat
          label="Active IOCs"
          value={intel ? Object.values(intel.active_by_type || {}).reduce((a, b) => a + b, 0) : "—"}
          sub={intel ? `${intel.matches_last_24h} match(es) in 24h` : "unavailable"}
          to="/intel"
          icon={Target}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Card
          title="Recent high-severity events"
          description="Critical and high detections, newest first."
          actions={
            <Link to="/events?severity=critical&severity=high" className="text-xs text-sky-300 hover:underline">
              View all
            </Link>
          }
        >
          <Table
            columns={[
              { key: "ts", header: "Time", render: (e) => relativeTime(e.ts) },
              { key: "severity", header: "Sev", render: (e) => <Badge severity={e.severity} /> },
              {
                key: "signature",
                header: "Signature",
                className: "max-w-sm truncate",
                render: (e) => (
                  <span className="flex items-center gap-1.5">
                    {e.signature || <span className="text-slate-600">—</span>}
                    {e.ioc_match && <Badge tone="danger">IOC</Badge>}
                  </span>
                ),
              },
              {
                key: "flow",
                header: "Src → Dst",
                render: (e) => (
                  <span className="font-mono text-xs">
                    {e.src_ip ?? "—"} <span className="text-slate-600">→</span> {e.dst_ip ?? "—"}
                  </span>
                ),
              },
            ]}
            rows={recent?.items || []}
            loading={loading}
            rowKey={(e) => e.id}
            empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No high-severity events in this window.</p>}
          />
        </Card>

        <div className="space-y-4">
          <Card title="Severity breakdown" description="Last 24 hours.">
            {sevBuckets.length === 0 ? (
              <p className="text-xs text-slate-500">No events in this window.</p>
            ) : (
              <div className="space-y-1.5">
                {SEVERITY_ORDER.filter((s) => sevBuckets.some((b) => b.value === s)).map((sev) => {
                  const count = sevBuckets.find((b) => b.value === sev)?.count ?? 0;
                  return (
                    <Link key={sev} to={`/events?severity=${sev}`} className="flex items-center gap-2 text-xs hover:opacity-80">
                      <span className="w-16 shrink-0">
                        <Badge severity={sev} />
                      </span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-700">
                        <div className="h-full bg-sky-500" style={{ width: `${(count / maxSev) * 100}%` }} />
                      </div>
                      <span className="w-12 shrink-0 text-right text-slate-400">{count}</span>
                    </Link>
                  );
                })}
              </div>
            )}
          </Card>

          <Card title="Response posture">
            <dl className="space-y-2 text-xs">
              <div className="flex justify-between">
                <dt className="text-slate-500">Mean time to acknowledge</dt>
                <dd className="text-slate-200">{incidents?.mtta_seconds != null ? duration(incidents.mtta_seconds) : "—"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Mean time to resolve</dt>
                <dd className="text-slate-200">{incidents?.mttr_seconds != null ? duration(incidents.mttr_seconds) : "—"}</dd>
              </div>
              {isAdmin && (
                <div className="flex justify-between">
                  <dt className="flex items-center gap-1 text-slate-500">
                    <ShieldBan size={11} /> Active containment
                  </dt>
                  <dd className="text-slate-200">{firewall ? `${firewall.db_active_count} block(s)` : "—"}</dd>
                </div>
              )}
              <div className="flex justify-between">
                <dt className="flex items-center gap-1 text-slate-500">
                  <Radar size={11} /> Ingest backlog
                </dt>
                <dd className="text-slate-200">{pipeline ? `${pipeline.stream_length} queued` : "—"}</dd>
              </div>
            </dl>
          </Card>
        </div>
      </div>
    </>
  );
}
