import { ArrowLeft, Download, FileSearch, Link2, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { api, downloadFile, saveBlob } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, duration, formatBytes, relativeTime } from "../../lib/format";
import AttachModal from "./AttachModal";
import { ARTIFACT_LABEL, ARTIFACT_TYPES, STATUS_LABEL, STATUS_TONE, eventSearchPivotUrl } from "./constants";
import FlowDetailDrawer from "./FlowDetailDrawer";
import FlowFilterBar from "./FlowFilterBar";
import { flowFiltersFromSearchParams, flowFiltersToSearchParams } from "./filters";

const FLOW_PAGE_SIZE = 100;
const POLL_MS = 3000;

export default function PcapDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const flowFilters = flowFiltersFromSearchParams(searchParams);

  const [pcap, setPcap] = useState(null);
  const [loading, setLoading] = useState(true);
  const [flows, setFlows] = useState([]);
  const [flowsLoading, setFlowsLoading] = useState(true);
  const [tab, setTab] = useState("flows"); // flows | artifacts
  const [artifactType, setArtifactType] = useState(null);
  const [artifactQuery, setArtifactQuery] = useState("");
  const [artifacts, setArtifacts] = useState([]);
  const [artifactsLoading, setArtifactsLoading] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [attachOpen, setAttachOpen] = useState(false);

  const canWrite = hasRole("analyst", "admin");
  const isAdmin = hasRole("admin");

  const loadPcap = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const data = await api.get(`/pcap/${id}`);
        setPcap(data);
      } catch (err) {
        if (!silent) {
          toast.error(err.message || "Could not load capture");
          navigate("/pcap");
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [id, navigate, toast],
  );

  useEffect(() => {
    loadPcap();
  }, [loadPcap]);

  useEffect(() => {
    if (!pcap || (pcap.status !== "parsing" && pcap.status !== "uploaded")) return undefined;
    const timer = setInterval(() => loadPcap(true), POLL_MS);
    return () => clearInterval(timer);
  }, [pcap, loadPcap]);

  const loadFlows = useCallback(async () => {
    if (!pcap || pcap.status !== "parsed") return;
    setFlowsLoading(true);
    try {
      const params = new URLSearchParams();
      if (flowFilters.ip) params.set("ip", flowFilters.ip);
      if (flowFilters.protocol) params.set("protocol", flowFilters.protocol);
      if (flowFilters.app_protocol) params.set("app_protocol", flowFilters.app_protocol);
      params.set("sort", flowFilters.sort.key);
      params.set("limit", String(FLOW_PAGE_SIZE));
      params.set("offset", String(flowFilters.page * FLOW_PAGE_SIZE));
      const data = await api.get(`/pcap/${id}/flows?${params.toString()}`);
      setFlows(flowFilters.sort.dir === "asc" ? [...data].reverse() : data);
    } catch (err) {
      toast.error(err.message || "Could not load flows");
    } finally {
      setFlowsLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, pcap?.status, JSON.stringify(flowFilters)]);

  useEffect(() => {
    loadFlows();
  }, [loadFlows]);

  useEffect(() => {
    if (tab !== "artifacts" || !pcap || pcap.status !== "parsed") return;
    setArtifactsLoading(true);
    const params = new URLSearchParams();
    if (artifactType) params.set("artifact_type", artifactType);
    if (artifactQuery) params.set("q", artifactQuery);
    params.set("limit", "200");
    api
      .get(`/pcap/${id}/artifacts?${params.toString()}`)
      .then(setArtifacts)
      .catch((err) => toast.error(err.message || "Could not load artifacts"))
      .finally(() => setArtifactsLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, id, artifactType, artifactQuery, pcap?.status]);

  const topTalkers = useMemo(() => {
    const byIp = new Map();
    for (const flow of flows) {
      for (const [ip, bytes, asset, dir] of [
        [flow.src_ip, flow.byte_count, flow.src_asset_hostname, "out"],
        [flow.dst_ip, flow.byte_count, flow.dst_asset_hostname, "in"],
      ]) {
        const entry = byIp.get(ip) || { ip, asset, packets: 0, bytesIn: 0, bytesOut: 0 };
        entry.packets += flow.packet_count;
        if (dir === "in") entry.bytesIn += bytes;
        else entry.bytesOut += bytes;
        entry.asset = entry.asset || asset;
        byIp.set(ip, entry);
      }
    }
    return [...byIp.values()].sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut)).slice(0, 10);
  }, [flows]);

  const updateFlowFilters = (patch) => {
    setSearchParams(flowFiltersToSearchParams({ ...flowFilters, ...patch, page: "page" in patch ? patch.page : 0 }));
  };

  const download = async () => {
    try {
      const { blob, filename } = await downloadFile(`/pcap/${id}/download`);
      saveBlob(blob, filename);
    } catch (err) {
      toast.error(err.message || "Could not download capture");
    }
  };

  const remove = async () => {
    if (!window.confirm("Delete this capture and its stored file? This cannot be undone.")) return;
    try {
      await api.del(`/pcap/${id}`);
      toast.success("Capture deleted");
      navigate("/pcap");
    } catch (err) {
      toast.error(err.message || "Could not delete capture");
    }
  };

  if (loading || !pcap) {
    return <p className="text-sm text-slate-400">Loading…</p>;
  }

  return (
    <>
      <PageHeader
        title={
          <div className="flex items-center gap-2">
            <button onClick={() => navigate("/pcap")} className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100">
              <ArrowLeft size={16} />
            </button>
            <span className="truncate">{pcap.filename}</span>
          </div>
        }
        description={`Uploaded ${relativeTime(pcap.uploaded_at)} · ${formatBytes(pcap.size_bytes)} · sha256 ${pcap.sha256.slice(0, 16)}…`}
        actions={
          <div className="flex items-center gap-2">
            <Badge tone={STATUS_TONE[pcap.status]}>{STATUS_LABEL[pcap.status] || pcap.status}</Badge>
            {canWrite && (
              <Button size="sm" variant="secondary" icon={Link2} onClick={() => setAttachOpen(true)}>
                Attach to incident
              </Button>
            )}
            {isAdmin && (
              <Button size="sm" variant="secondary" icon={Download} onClick={download}>
                Download
              </Button>
            )}
            {canWrite && (
              <Button size="sm" variant="danger" icon={Trash2} onClick={remove}>
                Delete
              </Button>
            )}
          </div>
        }
      />

      {pcap.incident_id && (
        <p className="mb-4 text-xs text-slate-400">
          Attached to{" "}
          <Link className="text-sky-300 hover:underline" to={`/incidents`}>
            an incident
          </Link>
        </p>
      )}

      {pcap.status === "failed" && (
        <Card className="mb-4 border-rose-800/60 bg-rose-950/20">
          <p className="text-sm text-rose-300">Parsing failed: {pcap.error || "unknown error"}</p>
        </Card>
      )}

      {(pcap.status === "uploaded" || pcap.status === "parsing") && (
        <Card className="mb-4">
          <p className="mb-2 text-sm text-slate-300">Parsing in progress…</p>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
            <div className="h-full bg-sky-500 transition-all" style={{ width: `${pcap.progress ?? 0}%` }} />
          </div>
        </Card>
      )}

      {pcap.status === "parsed" && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Card bodyClassName="p-3">
              <p className="text-xs text-slate-500">Packets</p>
              <p className="text-lg font-semibold text-slate-100">{pcap.packet_count?.toLocaleString() ?? "—"}</p>
            </Card>
            <Card bodyClassName="p-3">
              <p className="text-xs text-slate-500">Duration</p>
              <p className="text-lg font-semibold text-slate-100">{duration(pcap.duration_seconds)}</p>
            </Card>
            <Card bodyClassName="p-3">
              <p className="text-xs text-slate-500">Flows</p>
              <p className="text-lg font-semibold text-slate-100">
                {pcap.flow_count ?? "—"}
                {pcap.flow_truncated && <span className="ml-1 text-xs text-amber-400">(truncated)</span>}
              </p>
            </Card>
            <Card bodyClassName="p-3">
              <p className="text-xs text-slate-500">Unique hosts</p>
              <p className="text-lg font-semibold text-slate-100">{pcap.unique_hosts ?? "—"}</p>
            </Card>
          </div>

          {pcap.protocol_distribution && Object.keys(pcap.protocol_distribution).length > 0 && (
            <Card title="Protocol distribution" className="mb-4">
              <div className="space-y-1.5">
                {Object.entries(pcap.protocol_distribution)
                  .sort((a, b) => b[1] - a[1])
                  .map(([proto, count]) => {
                    const max = Math.max(...Object.values(pcap.protocol_distribution));
                    return (
                      <div key={proto} className="flex items-center gap-2 text-xs">
                        <span className="w-20 shrink-0 text-slate-400">{proto}</span>
                        <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-700">
                          <div className="h-full bg-sky-500" style={{ width: `${(count / max) * 100}%` }} />
                        </div>
                        <span className="w-10 shrink-0 text-right text-slate-500">{count}</span>
                      </div>
                    );
                  })}
              </div>
            </Card>
          )}

          <Card title="Top talkers" className="mb-4">
            <Table
              columns={[
                { key: "ip", header: "IP", className: "font-mono text-xs", render: (r) => r.ip },
                { key: "asset", header: "Asset", render: (r) => r.asset || <span className="text-slate-600">—</span> },
                { key: "packets", header: "Packets", render: (r) => r.packets.toLocaleString() },
                { key: "bytes_in", header: "Bytes in", render: (r) => formatBytes(r.bytesIn) },
                { key: "bytes_out", header: "Bytes out", render: (r) => formatBytes(r.bytesOut) },
              ]}
              rows={topTalkers}
              rowKey={(r) => r.ip}
              empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No flows yet.</p>}
            />
          </Card>

          <div className="mb-3 flex gap-1 border-b border-slate-700">
            {[
              { key: "flows", label: "Flows" },
              { key: "artifacts", label: "Artifacts" },
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

          {tab === "flows" && (
            <>
              <FlowFilterBar filters={flowFilters} onChange={updateFlowFilters} />
              <Table
                columns={[
                  {
                    key: "flow",
                    header: "Src → Dst",
                    render: (f) => (
                      <span className="font-mono text-xs">
                        {f.src_asset_hostname || f.src_ip}
                        {f.src_port ? `:${f.src_port}` : ""} <span className="text-slate-600">→</span>{" "}
                        {f.dst_asset_hostname || f.dst_ip}
                        {f.dst_port ? `:${f.dst_port}` : ""}
                      </span>
                    ),
                  },
                  { key: "protocol", header: "Proto", render: (f) => f.protocol.toUpperCase() },
                  { key: "app_protocol", header: "App", render: (f) => f.app_protocol || "—" },
                  {
                    key: "byte_count",
                    header: "Bytes",
                    sortable: true,
                    render: (f) => formatBytes(f.byte_count),
                  },
                  { key: "packet_count", header: "Packets", sortable: true, render: (f) => f.packet_count.toLocaleString() },
                  { key: "duration_ms", header: "Duration", render: (f) => (f.duration_ms != null ? `${f.duration_ms}ms` : "—") },
                  {
                    key: "start_ts",
                    header: "Start",
                    sortable: true,
                    render: (f) => <span title={absoluteTime(f.start_ts)}>{relativeTime(f.start_ts)}</span>,
                  },
                ]}
                rows={flows}
                loading={flowsLoading}
                rowKey={(f) => f.id}
                onRowClick={setSelectedFlow}
                sort={flowFilters.sort}
                onSortChange={(sort) => updateFlowFilters({ sort })}
                empty={<EmptyState icon={FileSearch} title="No flows match these filters" />}
              />
              <div className="mt-3 flex justify-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={flowFilters.page === 0}
                  onClick={() => updateFlowFilters({ page: Math.max(0, flowFilters.page - 1) })}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={flows.length < FLOW_PAGE_SIZE}
                  onClick={() => updateFlowFilters({ page: flowFilters.page + 1 })}
                >
                  Next
                </Button>
              </div>
            </>
          )}

          {tab === "artifacts" && (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <select
                  value={artifactType || ""}
                  onChange={(e) => setArtifactType(e.target.value || null)}
                  className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100"
                >
                  <option value="">All types</option>
                  {ARTIFACT_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {ARTIFACT_LABEL[t]}
                    </option>
                  ))}
                </select>
                <input
                  value={artifactQuery}
                  onChange={(e) => setArtifactQuery(e.target.value)}
                  placeholder="Search artifact values…"
                  className="min-w-[16rem] rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
                />
              </div>
              <Table
                columns={[
                  { key: "artifact_type", header: "Type", render: (a) => <Badge tone="neutral">{ARTIFACT_LABEL[a.artifact_type]}</Badge> },
                  { key: "value", header: "Value", className: "max-w-md truncate font-mono text-xs", render: (a) => a.value },
                  { key: "ts", header: "Time", render: (a) => (a.ts ? relativeTime(a.ts) : "—") },
                  {
                    key: "pivot",
                    header: "",
                    render: (a) => (
                      <Link className="text-xs text-sky-300 hover:underline" to={eventSearchPivotUrl(a.value)}>
                        Search events
                      </Link>
                    ),
                  },
                ]}
                rows={artifacts}
                loading={artifactsLoading}
                rowKey={(a) => a.id}
                empty={<EmptyState icon={FileSearch} title="No artifacts match these filters" />}
              />
            </>
          )}
        </>
      )}

      <FlowDetailDrawer pcapId={id} flow={selectedFlow} open={Boolean(selectedFlow)} onClose={() => setSelectedFlow(null)} />
      <AttachModal open={attachOpen} onClose={() => setAttachOpen(false)} pcap={pcap} onAttached={() => loadPcap()} />
    </>
  );
}
