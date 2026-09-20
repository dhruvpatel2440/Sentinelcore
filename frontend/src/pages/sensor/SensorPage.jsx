import {
  Activity,
  AlertTriangle,
  Download,
  Play,
  RefreshCw,
  Square,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import Modal from "../../components/Modal";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, duration, relativeTime } from "../../lib/format";
import RuleOverrides from "./RuleOverrides";
import RuleSources from "./RuleSources";

const STATUS_POLL_MS = 10_000;

function Stat({ label, value, tone }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className={`mt-0.5 text-sm ${tone ?? "text-slate-200"}`}>{value ?? "—"}</dd>
    </div>
  );
}

/** Minimal inline sparkline — a dependency-free SVG polyline is enough here. */
function Sparkline({ points, width = 220, height = 40 }) {
  if (!points || points.length < 2) {
    return <p className="text-xs text-slate-500">Not enough samples yet.</p>;
  }
  const max = Math.max(...points, 1);
  const step = width / (points.length - 1);
  const path = points
    .map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`)
    .join(" ");

  return (
    <svg width={width} height={height} className="overflow-visible" role="img" aria-label="Throughput trend">
      <polyline points={path} fill="none" stroke="currentColor" strokeWidth="1.5" className="text-sky-400" />
    </svg>
  );
}

export default function SensorPage() {
  const toast = useToast();

  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [s, st, ev] = await Promise.all([
        api.get("/sensor/status"),
        api.get("/sensor/stats").catch(() => null),
        api.get("/sensor/events?limit=15").catch(() => []),
      ]);
      setStatus(s);
      setStats(st);
      setEvents(ev);
    } catch (err) {
      toast.error(err.message || "Could not load sensor status");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, STATUS_POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const runAction = async (action, path) => {
    setBusy(action);
    setConfirm(null);
    try {
      const updated = await api.post(path);
      setStatus(updated);
      toast.success(`Sensor ${action} succeeded`);
      refresh();
    } catch (err) {
      toast.error(err.message || `Sensor ${action} failed`, { duration: 10000 });
    } finally {
      setBusy(null);
    }
  };

  const updateRules = async () => {
    setBusy("rules");
    try {
      await api.post("/sensor/rules/update");
      toast.info("Rule update started — this can take a minute.");
      setTimeout(refresh, 5000);
    } catch (err) {
      toast.error(err.message || "Could not start the rule update");
    } finally {
      setBusy(null);
    }
  };

  const running = status?.running;
  const helperDown = status && !status.helper_available;

  return (
    <>
      <PageHeader
        title="Sensor"
        description="Suricata lifecycle, ruleset and capture health."
        actions={
          <>
            <Button variant="secondary" icon={RefreshCw} onClick={refresh} disabled={loading}>
              Refresh
            </Button>
            {running ? (
              <Button
                variant="danger"
                icon={Square}
                loading={busy === "stop"}
                onClick={() => setConfirm("stop")}
              >
                Stop
              </Button>
            ) : (
              <Button
                icon={Play}
                loading={busy === "start"}
                disabled={helperDown}
                onClick={() => setConfirm("start")}
              >
                Start
              </Button>
            )}
            <Button
              variant="secondary"
              icon={RefreshCw}
              loading={busy === "reload"}
              disabled={!running}
              onClick={() => setConfirm("reload")}
            >
              Reload rules
            </Button>
          </>
        }
      />

      {helperDown && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3">
          <AlertTriangle size={16} className="text-rose-400" aria-hidden="true" />
          <p className="text-sm text-rose-200">
            The privileged helper is unreachable. Sensor control is offline.
          </p>
        </div>
      )}

      {status?.eve_log_stale && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <AlertTriangle size={16} className="text-amber-400" aria-hidden="true" />
          <p className="text-sm text-amber-200">
            Suricata is running but <code>eve.json</code> has not been written in{" "}
            {status.eve_log_age_seconds == null
              ? "an unknown time"
              : duration(status.eve_log_age_seconds)}
            . The sensor is up but may not be seeing traffic.
          </p>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Status">
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Stat
              label="State"
              value={
                <Badge tone={running ? "success" : "danger"}>
                  {running ? "running" : "stopped"}
                </Badge>
              }
            />
            <Stat label="PID" value={status?.pid} />
            <Stat label="Uptime" value={duration(status?.uptime_seconds)} />
            <Stat label="Version" value={status?.version} />
            <Stat
              label="Rules loaded"
              value={status?.rule_count ?? 0}
              tone={status?.rule_count ? "text-slate-200" : "text-amber-300"}
            />
            <Stat label="Last reload" value={relativeTime(status?.last_reload_at)} />
            <Stat
              label="eve.json age"
              value={duration(status?.eve_log_age_seconds)}
              tone={status?.eve_log_stale ? "text-amber-300" : "text-slate-200"}
            />
            <Stat
              label="Ruleset checksum"
              value={
                status?.ruleset_sha256 ? (
                  <code className="text-xs">{status.ruleset_sha256.slice(0, 12)}…</code>
                ) : null
              }
            />
          </dl>
        </Card>

        <Card title="Throughput" description="A sensor dropping packets is silently missing attacks.">
          <dl className="grid grid-cols-3 gap-4">
            <Stat label="Packets" value={stats?.kernel_packets?.toLocaleString() ?? "0"} />
            <Stat label="Drops" value={stats?.kernel_drops?.toLocaleString() ?? "0"} />
            <Stat
              label="Drop rate"
              value={`${(stats?.drop_rate ?? 0).toFixed(2)}%`}
              tone={
                (stats?.drop_rate ?? 0) > 1 ? "text-rose-300 font-semibold" : "text-emerald-300"
              }
            />
          </dl>
          <div className="mt-4">
            <Sparkline points={(stats?.history ?? []).map((h) => h.kernel_packets || h.packets || 0)} />
            <p className="mt-1 text-xs text-slate-500">
              {stats?.captured_at
                ? `Last stats record ${relativeTime(stats.captured_at)}`
                : "No stats records in eve.json yet."}
            </p>
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4">
        <RuleSources onUpdateRules={updateRules} updating={busy === "rules"} onChanged={refresh} />
        <RuleOverrides onChanged={refresh} />

        <Card title="Sensor history">
          <Table
            columns={[
              { key: "action", header: "Action" },
              {
                key: "status",
                header: "Result",
                render: (e) => (
                  <Badge tone={e.status === "ok" || e.status === "started" || e.status === "stopped" ? "success" : "danger"}>
                    {e.status}
                  </Badge>
                ),
              },
              {
                key: "detail",
                header: "Detail",
                render: (e) => (
                  <span className="text-xs text-slate-400">
                    {e.detail ? JSON.stringify(e.detail).slice(0, 90) : "—"}
                  </span>
                ),
              },
              { key: "created_at", header: "When", render: (e) => absoluteTime(e.created_at) },
            ]}
            rows={events}
            rowKey={(e) => e.id}
            empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No sensor actions recorded yet.</p>}
          />
        </Card>
      </div>

      <Modal
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        title={
          confirm === "stop"
            ? "Stop the sensor?"
            : confirm === "start"
              ? "Start the sensor?"
              : "Reload rules?"
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant={confirm === "stop" ? "danger" : "primary"}
              onClick={() =>
                runAction(
                  confirm,
                  confirm === "stop"
                    ? "/sensor/stop"
                    : confirm === "start"
                      ? "/sensor/start"
                      : "/sensor/reload",
                )
              }
            >
              {confirm === "stop" ? "Stop sensor" : confirm === "start" ? "Start sensor" : "Reload"}
            </Button>
          </>
        }
      >
        {confirm === "stop" && (
          <p className="text-rose-300">
            Stopping Suricata blinds the platform. No traffic will be inspected and no new
            detections will be generated until it is started again.
          </p>
        )}
        {confirm === "start" && <p>Suricata will begin inspecting traffic on the capture interface.</p>}
        {confirm === "reload" && (
          <p>The ruleset is reloaded live, without dropping packets or restarting the sensor.</p>
        )}
      </Modal>
    </>
  );
}
