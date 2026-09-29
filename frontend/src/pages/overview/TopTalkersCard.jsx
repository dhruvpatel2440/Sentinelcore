import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Card from "../../components/Card";

const REFRESH_MS = 30_000;

const WINDOWS = [
  { key: "1h", label: "1h" },
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
];

const TABS = [
  { key: "src", label: "Top talkers", linkParam: "src_ip" },
  { key: "dest", label: "Top targets", linkParam: "dst_ip" },
  { key: "signature", label: "Top signatures", linkParam: null },
];

/** Top talkers / targets / signatures for the Overview dashboard, windowed
 *  independently of the rest of the page — this card fetches and fails on
 *  its own, so a broken /stats/top-talkers endpoint never blanks the tiles
 *  around it. */
export default function TopTalkersCard() {
  const [tab, setTab] = useState("src");
  const [window_, setWindow] = useState("24h");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  // Guards a fetch whose response arrives after the tab/window that started
  // it has already changed — without this, a slow "7d" response can
  // overwrite a faster "1h" one that the user switched to afterward.
  const requestId = useRef(0);

  useEffect(() => {
    let cancelled = false;
    const id = ++requestId.current;

    async function load() {
      setLoading(true);
      try {
        const result = await api.get(
          `/stats/top-talkers?window=${window_}&by=${tab}&limit=10`,
        );
        if (!cancelled && id === requestId.current) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled && id === requestId.current) {
          setError(err.message || "Failed to load top talkers");
        }
      } finally {
        if (!cancelled && id === requestId.current) setLoading(false);
      }
    }

    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [tab, window_]);

  const items = data?.items || [];
  const maxCount = Math.max(1, ...items.map((i) => i.count));
  const activeTab = TABS.find((t) => t.key === tab);

  return (
    <Card
      title="Network activity"
      description="Live top talkers, targets, and signatures."
      actions={
        <div className="flex items-center gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w.key}
              type="button"
              onClick={() => setWindow(w.key)}
              className={`rounded px-2 py-0.5 text-xs ${
                window_ === w.key
                  ? "bg-sky-500/20 text-sky-300"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      }
    >
      <div className="mb-3 flex gap-1 border-b border-slate-800 pb-2">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`rounded px-2 py-1 text-xs font-medium ${
              tab === t.key
                ? "bg-slate-700/60 text-slate-100"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <p className="px-1 py-4 text-center text-xs text-rose-400">
          {error}
        </p>
      )}

      {!error && !loading && items.length === 0 && (
        <p className="px-1 py-4 text-center text-xs text-slate-500">
          No activity in this window.
        </p>
      )}

      {!error && items.length > 0 && (
        <div className="space-y-1.5">
          {items.map((item) => {
            const row = (
              <div className="flex items-center gap-2 text-xs hover:opacity-80">
                <span className="w-40 shrink-0 truncate font-mono" title={item.value}>
                  {item.hostname ? `${item.hostname} (${item.value})` : item.value}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-700">
                  <div
                    className="h-full bg-sky-500"
                    style={{ width: `${(item.count / maxCount) * 100}%` }}
                  />
                </div>
                <span className="w-10 shrink-0 text-right text-slate-400">{item.count}</span>
                {item.ioc_match && <Badge tone="danger">IOC</Badge>}
                {item.max_severity && <Badge severity={item.max_severity} />}
              </div>
            );
            return (
              <Link
                key={item.value}
                to={activeTab.linkParam ? `/events?${activeTab.linkParam}=${encodeURIComponent(item.value)}` : "/events"}
              >
                {row}
              </Link>
            );
          })}
        </div>
      )}
    </Card>
  );
}
