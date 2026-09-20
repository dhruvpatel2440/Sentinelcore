import { Radar, RefreshCw, Search } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { duration, relativeTime } from "../../lib/format";
import AssetDetail from "./AssetDetail";
import ScanModal from "./ScanModal";

const SCAN_POLL_MS = 2000;

const SCAN_STATUS_TONE = {
  queued: "neutral",
  running: "accent",
  completed: "success",
  failed: "danger",
};

export default function AssetsPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const isAdmin = hasRole("admin");

  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  const [query, setQuery] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [openPortsOnly, setOpenPortsOnly] = useState(false);
  const [sort, setSort] = useState({ key: "last_seen", dir: "desc" });

  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState(null);

  const pollRef = useRef(null);

  const loadAssets = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        sort: sort.key,
        order: sort.dir,
        limit: "200",
      });
      if (query.trim()) params.set("q", query.trim());
      if (activeOnly) params.set("is_active", "true");
      if (openPortsOnly) params.set("has_open_port", "true");

      const data = await api.get(`/assets?${params}`);
      setAssets(data.items);
      setTotal(data.total);
    } catch (err) {
      toast.error(err.message || "Could not load assets");
    } finally {
      setLoading(false);
    }
  }, [query, activeOnly, openPortsOnly, sort, toast]);

  const loadScans = useCallback(async () => {
    try {
      const data = await api.get("/assets/scans?limit=10");
      setScans(data);
      return data;
    } catch {
      return [];
    }
  }, []);

  // Debounce the search box so typing does not fire a request per keystroke.
  useEffect(() => {
    const timer = setTimeout(loadAssets, 250);
    return () => clearTimeout(timer);
  }, [loadAssets]);

  useEffect(() => {
    loadScans().then((list) => {
      const running = list.find((s) => s.status === "running" || s.status === "queued");
      if (running) setActiveScan(running);
    });
  }, [loadScans]);

  // Poll only while a scan is in flight, then stop.
  useEffect(() => {
    if (!activeScan) return undefined;

    pollRef.current = setInterval(async () => {
      try {
        const scan = await api.get(`/assets/scans/${activeScan.id}`);
        setActiveScan(scan);

        if (scan.status === "completed") {
          toast.success(`Scan finished — ${scan.hosts_found} host(s) found`);
          setActiveScan(null);
          loadAssets();
          loadScans();
        } else if (scan.status === "failed") {
          toast.error(`Scan failed: ${scan.error ?? "unknown error"}`, { duration: 12000 });
          setActiveScan(null);
          loadScans();
        }
      } catch {
        // Transient poll failure is not fatal; the next tick retries.
      }
    }, SCAN_POLL_MS);

    return () => clearInterval(pollRef.current);
  }, [activeScan, loadAssets, loadScans, toast]);

  const columns = [
    {
      key: "ip_address",
      header: "IP address",
      sortable: true,
      className: "font-mono text-slate-100",
    },
    {
      key: "hostname",
      header: "Hostname",
      render: (r) => r.hostname_override || r.hostname || "—",
    },
    {
      key: "mac",
      header: "MAC / vendor",
      render: (r) => (
        <div className="leading-tight">
          <div className="font-mono text-xs text-slate-300">{r.mac_address ?? "—"}</div>
          {r.vendor && <div className="text-xs text-slate-500">{r.vendor}</div>}
        </div>
      ),
    },
    {
      key: "open_port_count",
      header: "Open ports",
      render: (r) =>
        r.open_port_count > 0 ? (
          <Badge tone="accent">{r.open_port_count}</Badge>
        ) : (
          <span className="text-slate-500">0</span>
        ),
    },
    { key: "last_seen", header: "Last seen", sortable: true, render: (r) => relativeTime(r.last_seen) },
    {
      key: "is_active",
      header: "Status",
      render: (r) => (
        <Badge tone={r.is_active ? "success" : "neutral"}>
          {r.is_active ? "active" : "inactive"}
        </Badge>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Assets"
        description={`${total} host${total === 1 ? "" : "s"} discovered on the monitored network.`}
        actions={
          <>
            <Button variant="secondary" icon={RefreshCw} onClick={loadAssets} disabled={loading}>
              Refresh
            </Button>
            {isAdmin && (
              <Button
                icon={Radar}
                onClick={() => setScanModalOpen(true)}
                disabled={Boolean(activeScan)}
              >
                {activeScan ? "Scan running…" : "Run scan"}
              </Button>
            )}
          </>
        }
      />

      {activeScan && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-3">
          <RefreshCw size={16} className="animate-spin text-sky-400" aria-hidden="true" />
          <p className="text-sm text-sky-200">
            Discovery scan {activeScan.status} — targets {activeScan.targets.join(", ")}
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[16rem] flex-1">
          <Search
            size={14}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            aria-hidden="true"
          />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IP, hostname or vendor…"
            aria-label="Search assets"
            className="w-full rounded-md border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setActiveOnly(e.target.checked)}
            className="rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
          />
          Active only
        </label>

        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input
            type="checkbox"
            checked={openPortsOnly}
            onChange={(e) => setOpenPortsOnly(e.target.checked)}
            className="rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
          />
          Has open ports
        </label>
      </div>

      <Table
        columns={columns}
        rows={assets}
        loading={loading}
        rowKey={(r) => r.id}
        sort={sort}
        onSortChange={setSort}
        onRowClick={(row) => setSelectedAssetId(row.id)}
        empty={
          <EmptyState
            icon={Radar}
            title="No assets discovered yet"
            description={
              isAdmin
                ? "Run a discovery scan to populate the inventory."
                : "An administrator needs to run a discovery scan."
            }
            action={isAdmin && <Button icon={Radar} onClick={() => setScanModalOpen(true)}>Run scan</Button>}
          />
        }
      />

      {scans.length > 0 && (
        <Card title="Scan history" className="mt-6">
          <Table
            columns={[
              {
                key: "status",
                header: "Status",
                render: (s) => (
                  <Badge tone={SCAN_STATUS_TONE[s.status] ?? "neutral"}>{s.status}</Badge>
                ),
              },
              { key: "targets", header: "Targets", render: (s) => s.targets.join(", ") },
              { key: "mode", header: "Mode", render: (s) => s.mode ?? "—" },
              { key: "hosts_found", header: "Hosts" },
              {
                key: "duration",
                header: "Duration",
                render: (s) => duration(s.duration_seconds),
              },
              { key: "created_at", header: "Started", render: (s) => relativeTime(s.created_at) },
              {
                key: "error",
                header: "Error",
                render: (s) =>
                  s.error ? (
                    <span className="text-xs text-rose-300" title={s.error}>
                      {s.error.slice(0, 60)}
                      {s.error.length > 60 ? "…" : ""}
                    </span>
                  ) : (
                    "—"
                  ),
              },
            ]}
            rows={scans}
            rowKey={(s) => s.id}
          />
        </Card>
      )}

      <ScanModal
        open={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
        defaultTarget={import.meta.env.VITE_MONITORED_NETWORK || "192.168.10.0/24"}
        onStarted={(scan) => {
          setActiveScan(scan);
          loadScans();
        }}
      />

      <AssetDetail
        assetId={selectedAssetId}
        open={Boolean(selectedAssetId)}
        onClose={() => setSelectedAssetId(null)}
        onSaved={loadAssets}
      />
    </>
  );
}
