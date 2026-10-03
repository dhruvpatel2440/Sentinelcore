import { Plus, Search, Target } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { relativeTime } from "../../lib/format";
import AddIocModal from "./AddIocModal";
import { IOC_TYPES, SEVERITY_OPTIONS } from "./constants";
import { iocFiltersFromSearchParams, iocFiltersToSearchParams } from "./filters";
import MatchesTab from "./MatchesTab";
import SourcesTab from "./SourcesTab";

export default function IntelPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = iocFiltersFromSearchParams(searchParams);
  const canWrite = hasRole("analyst", "admin");
  const isAdmin = hasRole("admin");

  const [tab, setTab] = useState("iocs"); // iocs | sources | matches
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addModalOpen, setAddModalOpen] = useState(false);

  const [lookupValue, setLookupValue] = useState(searchParams.get("q") || "");
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.ioc_type) params.set("ioc_type", filters.ioc_type);
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.threat_type) params.set("threat_type", filters.threat_type);
      if (filters.tag) params.set("tag", filters.tag);
      if (filters.q) params.set("q", filters.q);
      if (filters.is_active !== undefined) params.set("is_active", String(filters.is_active));
      params.set("limit", "100");
      setIocs(await api.get(`/intel/iocs?${params.toString()}`));
    } catch (err) {
      toast.error(err.message || "Could not load IOCs");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filters), toast]);

  useEffect(() => {
    if (tab === "iocs") load();
  }, [tab, load]);

  const updateFilters = (patch) => {
    const next = { ...filters, ...patch };
    Object.keys(next).forEach((k) => (next[k] === undefined || next[k] === "") && delete next[k]);
    setSearchParams(iocFiltersToSearchParams(next));
  };

  const runLookup = async () => {
    if (!lookupValue.trim()) return;
    setLookupLoading(true);
    try {
      const result = await api.get(`/intel/lookup?value=${encodeURIComponent(lookupValue.trim())}`);
      setLookupResult(result);
    } catch (err) {
      toast.error(err.message || "Lookup failed");
    } finally {
      setLookupLoading(false);
    }
  };

  const toggleActive = async (ioc) => {
    try {
      await api.patch(`/intel/iocs/${ioc.id}`, { is_active: !ioc.is_active });
      load();
    } catch (err) {
      toast.error(err.message || "Could not update IOC");
    }
  };

  return (
    <>
      <PageHeader
        title="Threat Intel"
        description="Known-bad indicators, matched against live traffic and captures."
        actions={
          canWrite && (
            <Button icon={Plus} onClick={() => setAddModalOpen(true)}>
              Add IOC
            </Button>
          )
        }
      />

      <Card className="mb-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={lookupValue}
              onChange={(e) => setLookupValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runLookup()}
              placeholder="Paste any indicator — defanged or not — for an instant verdict"
              className="w-full rounded-md border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <Button onClick={runLookup} loading={lookupLoading} disabled={!lookupValue.trim()}>
            Look up
          </Button>
        </div>

        {lookupResult && (
          <div className="mt-3 rounded-md border border-slate-700 bg-slate-900/60 p-3">
            {!lookupResult.found ? (
              <p className="text-sm text-slate-400">
                No match for <span className="font-mono text-slate-200">{lookupResult.normalized || lookupResult.query}</span> — clean, or not yet
                known.
              </p>
            ) : (
              <div className="space-y-2">
                <p className="text-sm text-rose-300">
                  <span className="font-mono">{lookupResult.normalized}</span> is known-bad ({lookupResult.matches.length} source
                  {lookupResult.matches.length === 1 ? "" : "s"}).
                </p>
                {lookupResult.matches.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => navigate(`/intel/${m.id}`)}
                    className="flex w-full items-center justify-between gap-2 rounded border border-slate-700 px-2 py-1.5 text-left text-xs hover:bg-slate-800"
                  >
                    <span className="flex items-center gap-2">
                      <Badge severity={m.severity} />
                      {m.threat_type && <Badge tone="neutral">{m.threat_type}</Badge>}
                      <span className="text-slate-400">{m.source_name || "manual"}</span>
                    </span>
                    <span className="text-slate-500">confidence {m.confidence}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="mb-3 flex gap-1 border-b border-slate-700">
        {[
          { key: "iocs", label: "IOCs" },
          { key: "matches", label: "Matches" },
          ...(isAdmin ? [{ key: "sources", label: "Sources" }] : []),
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

      {tab === "iocs" && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <select
              value={filters.ioc_type || ""}
              onChange={(e) => updateFilters({ ioc_type: e.target.value || undefined })}
              className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100"
            >
              <option value="">Any type</option>
              {IOC_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <select
              value={filters.severity || ""}
              onChange={(e) => updateFilters({ severity: e.target.value || undefined })}
              className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100"
            >
              <option value="">Any severity</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input
              value={filters.q || ""}
              onChange={(e) => updateFilters({ q: e.target.value || undefined })}
              placeholder="Search indicator…"
              className="min-w-[14rem] rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500"
            />
            <select
              value={filters.is_active === undefined ? "" : String(filters.is_active)}
              onChange={(e) => updateFilters({ is_active: e.target.value === "" ? undefined : e.target.value === "true" })}
              className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100"
            >
              <option value="">Active + inactive</option>
              <option value="true">Active only</option>
              <option value="false">Inactive only</option>
            </select>
          </div>

          <Table
            columns={[
              { key: "indicator", header: "Indicator", className: "font-mono text-xs", render: (i) => i.indicator },
              { key: "ioc_type", header: "Type", render: (i) => <Badge tone="neutral">{i.ioc_type}</Badge> },
              { key: "severity", header: "Severity", render: (i) => <Badge severity={i.severity} /> },
              { key: "confidence", header: "Confidence", render: (i) => `${i.confidence}%` },
              { key: "source_name", header: "Source", render: (i) => i.source_name || "manual" },
              { key: "threat_type", header: "Threat type", render: (i) => i.threat_type || "—" },
              { key: "match_count", header: "Matches", render: (i) => i.match_count },
              { key: "last_seen", header: "Last seen", render: (i) => relativeTime(i.last_seen) },
              {
                key: "is_active", header: "Active",
                render: (i) => (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleActive(i);
                    }}
                    disabled={!canWrite}
                    className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset disabled:cursor-not-allowed ${
                      i.is_active ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/50 text-slate-400 ring-slate-600"
                    }`}
                  >
                    {i.is_active ? "Active" : "Inactive"}
                  </button>
                ),
              },
            ]}
            rows={iocs}
            loading={loading}
            rowKey={(i) => i.id}
            onRowClick={(row) => navigate(`/intel/${row.id}`)}
            empty={
              <EmptyState icon={Target} title="No IOCs match these filters" description="Add one manually or configure a feed source." />
            }
          />
        </>
      )}

      {tab === "matches" && <MatchesTab />}
      {tab === "sources" && isAdmin && <SourcesTab />}

      <AddIocModal open={addModalOpen} onClose={() => setAddModalOpen(false)} onAdded={load} />
    </>
  );
}
