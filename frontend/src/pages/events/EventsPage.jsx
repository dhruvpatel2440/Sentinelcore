import { Activity, PauseCircle, PlayCircle, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import EventDetail from "./EventDetail";
import FacetsSidebar from "./FacetsSidebar";
import FilterBar from "./FilterBar";
import SavedSearches from "./SavedSearches";
import { applyPreset, filtersFromSearchParams, filtersToSearchParams } from "./filters";

const PAGE_LIMIT = 50;
const LIVE_TAIL_INTERVAL_MS = 5000;

function eventsQueryString(filters, { cursor, limit = PAGE_LIMIT, sort = "ts_desc" } = {}) {
  const params = filtersToSearchParams(filters);
  params.set("limit", String(limit));
  params.set("sort", sort);
  if (cursor) params.set("cursor", cursor);
  return params.toString();
}

export default function EventsPage() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = filtersFromSearchParams(searchParams);

  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [nextCursor, setNextCursor] = useState(null);
  const [tookMs, setTookMs] = useState(null);
  const [activeRange, setActiveRange] = useState("24h");

  const [selectedEventId, setSelectedEventId] = useState(null);
  const [liveTail, setLiveTail] = useState(false);
  const [newCount, setNewCount] = useState(0);
  const [scrolledDown, setScrolledDown] = useState(false);
  const [facetsRefreshKey, setFacetsRefreshKey] = useState(0);

  const topTsRef = useRef(null);
  const liveTailTimer = useRef(null);

  const updateFilters = useCallback(
    (patch) => {
      const next = { ...filters };
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined || v === null || (Array.isArray(v) && v.length === 0) || v === "") {
          delete next[k];
        } else {
          next[k] = v;
        }
      }
      setActiveRange("custom");
      setSearchParams(filtersToSearchParams(next), { replace: false });
    },
    [filters, setSearchParams],
  );

  const pivotTo = useCallback(
    (patch) => {
      setSelectedEventId(null);
      setActiveRange("custom");
      setSearchParams(
        filtersToSearchParams({ from: filters.from, to: filters.to, severity: [], event_type: [], ...patch }),
      );
    },
    [filters.from, filters.to, setSearchParams],
  );

  const applyRangePreset = (key) => {
    const range = applyPreset(key);
    if (!range) return;
    setActiveRange(key);
    setSearchParams(filtersToSearchParams({ ...filters, ...range }));
  };

  const loadFirstPage = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get(`/events?${eventsQueryString(filters)}`);
      setEvents(data.items);
      setNextCursor(data.next_cursor);
      setTookMs(data.took_ms);
      topTsRef.current = data.items[0]?.ts ?? null;
      setNewCount(0);
      setFacetsRefreshKey((k) => k + 1);
    } catch (err) {
      toast.error(err.message || "Could not load events");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filters), toast]);

  useEffect(() => {
    loadFirstPage();
  }, [loadFirstPage]);

  const loadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    try {
      const data = await api.get(`/events?${eventsQueryString(filters, { cursor: nextCursor })}`);
      setEvents((list) => [...list, ...data.items]);
      setNextCursor(data.next_cursor);
    } catch (err) {
      toast.error(err.message || "Could not load more events");
    } finally {
      setLoadingMore(false);
    }
  };

  // Pause live tail once the analyst has scrolled away from the top row.
  useEffect(() => {
    const onScroll = () => setScrolledDown(window.scrollY > 80);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!liveTail) return undefined;

    const tick = async () => {
      if (document.visibilityState !== "visible" || scrolledDown || !topTsRef.current) return;
      try {
        const since = new Date(new Date(topTsRef.current).getTime() + 1).toISOString();
        const data = await api.get(
          `/events?${eventsQueryString({ ...filters, from: since, to: new Date().toISOString() }, { sort: "ts_desc", limit: 200 })}`,
        );
        if (data.items.length === 0) return;
        setEvents((list) => {
          const known = new Set(list.map((e) => e.id));
          const fresh = data.items.filter((e) => !known.has(e.id));
          if (fresh.length === 0) return list;
          setNewCount((n) => n + fresh.length);
          topTsRef.current = fresh[0].ts;
          return [...fresh, ...list];
        });
      } catch {
        // A missed live-tail tick is not worth surfacing; the next one retries.
      }
    };

    liveTailTimer.current = setInterval(tick, LIVE_TAIL_INTERVAL_MS);
    return () => clearInterval(liveTailTimer.current);
  }, [liveTail, scrolledDown, filters]);

  const columns = [
    {
      key: "ts",
      header: "Time",
      render: (r) => (
        <span title={absoluteTime(r.ts)} className="whitespace-nowrap">
          {relativeTime(r.ts)}
        </span>
      ),
    },
    { key: "severity", header: "Severity", render: (r) => <Badge severity={r.severity} /> },
    {
      key: "signature",
      header: "Signature",
      className: "max-w-xs truncate",
      render: (r) => r.signature || <span className="text-slate-600">—</span>,
    },
    {
      key: "flow",
      header: "Source → Destination",
      render: (r) => (
        <span className="font-mono text-xs">
          {r.src_ip}
          {r.src_port ? `:${r.src_port}` : ""} <span className="text-slate-600">→</span> {r.dst_ip}
          {r.dst_port ? `:${r.dst_port}` : ""}
        </span>
      ),
    },
    { key: "proto", header: "Proto", render: (r) => r.proto?.toUpperCase() ?? "—" },
    { key: "event_type", header: "Type", render: (r) => <Badge tone="neutral">{r.event_type}</Badge> },
  ];

  return (
    <>
      <PageHeader
        title="Events"
        description={
          tookMs != null ? `${events.length} event(s) loaded · query took ${tookMs}ms` : "Normalized detections from the sensor."
        }
        actions={
          <>
            <Button
              variant={liveTail ? "primary" : "secondary"}
              icon={liveTail ? PauseCircle : PlayCircle}
              onClick={() => setLiveTail((v) => !v)}
            >
              {liveTail ? "Live tail on" : "Live tail"}
            </Button>
            <Button variant="secondary" icon={RefreshCw} onClick={loadFirstPage} disabled={loading}>
              Refresh
            </Button>
            <SavedSearches
              currentFilters={filters}
              onLoad={(f) => {
                setActiveRange("custom");
                setSearchParams(filtersToSearchParams(f));
              }}
            />
          </>
        }
      />

      <FilterBar filters={filters} onChange={updateFilters} onApplyPreset={applyRangePreset} activeRange={activeRange} />

      {newCount > 0 && (
        <button
          onClick={() => setNewCount(0)}
          className="mb-3 flex items-center gap-1.5 rounded-md bg-sky-500/15 px-3 py-1.5 text-xs font-medium text-sky-200 ring-1 ring-inset ring-sky-500/30"
        >
          <Activity size={12} /> {newCount} new event{newCount === 1 ? "" : "s"}
        </button>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_16rem]">
        <div>
          <Table
            columns={columns}
            rows={events}
            loading={loading}
            rowKey={(r) => r.id}
            onRowClick={(row) => setSelectedEventId(row.id)}
            empty={
              <EmptyState
                icon={Activity}
                title="No events in this window"
                description="Widen the time range or clear filters."
              />
            }
          />

          {nextCursor && (
            <div className="mt-3 flex justify-center">
              <Button variant="secondary" onClick={loadMore} loading={loadingMore}>
                Load more
              </Button>
            </div>
          )}
        </div>

        <FacetsSidebar filters={filters} onPivot={updateFilters} refreshKey={facetsRefreshKey} />
      </div>

      <EventDetail
        eventId={selectedEventId}
        open={selectedEventId != null}
        onClose={() => setSelectedEventId(null)}
        onPivot={pivotTo}
      />
    </>
  );
}
