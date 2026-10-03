import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { eventSearchPivotUrl } from "./constants";

export default function MatchesTab() {
  const toast = useToast();
  const [matches, setMatches] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setMatches(await api.get("/intel/matches?limit=200"));
    } catch (err) {
      toast.error(err.message || "Could not load matches");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <Table
      columns={[
        { key: "indicator", header: "Indicator", className: "font-mono text-xs", render: (m) => m.indicator || "—" },
        { key: "severity", header: "Severity", render: (m) => <Badge severity={m.severity} /> },
        { key: "matched_field", header: "Field", render: (m) => <Badge tone="neutral">{m.matched_field}</Badge> },
        { key: "matched_value", header: "Matched value", className: "font-mono text-xs max-w-xs truncate", render: (m) => m.matched_value },
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
      rows={matches}
      loading={loading}
      rowKey={(m) => m.id}
      empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No matches yet.</p>}
    />
  );
}
