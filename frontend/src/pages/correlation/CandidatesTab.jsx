import { ExternalLink, ShieldOff } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import { CandidateStatus } from "./status";

const STATUS_TONE = { new: "accent", promoted: "success", suppressed: "neutral" };

/** Parses a `field=value|field=value` group key into M6 event-search filters,
 * padded around the candidate's time span, so "view matched events" lands on
 * exactly the story this candidate is about. */
function eventsLinkFor(candidate) {
  const params = new URLSearchParams();
  const from = new Date(new Date(candidate.first_event_ts).getTime() - 60_000).toISOString();
  const to = new Date(new Date(candidate.last_event_ts).getTime() + 60_000).toISOString();
  params.set("from", from);
  params.set("to", to);

  for (const part of candidate.group_key.split("|")) {
    const [field, value] = part.split("=");
    if (!field || value === undefined || value === "None") continue;
    if (field === "src_ip") params.set("src_ip", `${value}/32`);
    else if (field === "dst_ip") params.set("dst_ip", `${value}/32`);
    else if (field === "signature_id") params.append("signature_id", value);
    else if (field === "dst_port" || field === "src_port") params.set("port", value);
    else if (field === "proto") params.set("proto", value);
  }
  return `/events?${params.toString()}`;
}

export default function CandidatesTab() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const canSuppress = hasRole("analyst", "admin");

  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [suppressTarget, setSuppressTarget] = useState(null);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.set("status", statusFilter);
      setCandidates(await api.get(`/correlation/candidates?${params}`));
    } catch (err) {
      toast.error(err.message || "Could not load candidates");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const submitSuppress = async () => {
    if (!reason.trim()) return;
    setSubmitting(true);
    try {
      await api.post(`/correlation/candidates/${suppressTarget.id}/suppress`, { reason: reason.trim() });
      toast.success("Candidate suppressed");
      setSuppressTarget(null);
      setReason("");
      load();
    } catch (err) {
      toast.error(err.message || "Could not suppress candidate");
    } finally {
      setSubmitting(false);
    }
  };

  const columns = [
    { key: "severity", header: "Severity", render: (c) => <Badge severity={c.severity} /> },
    { key: "rule_name", header: "Rule", render: (c) => c.rule_name ?? "—" },
    { key: "group_key", header: "Group", className: "font-mono text-xs" },
    { key: "event_count", header: "Events" },
    { key: "score", header: "Score" },
    {
      key: "span",
      header: "Time span",
      render: (c) => (
        <span title={`${absoluteTime(c.first_event_ts)} → ${absoluteTime(c.last_event_ts)}`}>
          {relativeTime(c.last_event_ts)}
        </span>
      ),
    },
    { key: "status", header: "Status", render: (c) => <Badge tone={STATUS_TONE[c.status]}>{c.status}</Badge> },
    {
      key: "actions",
      header: "",
      render: (c) => (
        <div className="flex items-center gap-1">
          <Link
            to={eventsLinkFor(c)}
            onClick={(e) => e.stopPropagation()}
            className="flex items-center gap-1 rounded p-1 text-xs text-sky-300 hover:bg-slate-700"
            title="View matched events in M6 search"
          >
            <ExternalLink size={13} /> events
          </Link>
          {canSuppress && c.status === CandidateStatus.NEW && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                setSuppressTarget(c);
              }}
              className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-amber-300"
              title="Suppress"
            >
              <ShieldOff size={14} />
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value={CandidateStatus.NEW}>New</option>
          <option value={CandidateStatus.PROMOTED}>Promoted</option>
          <option value={CandidateStatus.SUPPRESSED}>Suppressed</option>
        </select>
      </div>

      <Table
        columns={columns}
        rows={candidates}
        loading={loading}
        rowKey={(c) => c.id}
        empty={<EmptyState title="No candidates" description="Nothing has matched an enabled rule yet." />}
      />

      <Modal
        open={Boolean(suppressTarget)}
        onClose={() => setSuppressTarget(null)}
        title="Suppress candidate"
        footer={
          <>
            <Button variant="ghost" onClick={() => setSuppressTarget(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={submitSuppress} loading={submitting} disabled={!reason.trim()}>
              Suppress
            </Button>
          </>
        }
      >
        <p className="mb-2 text-slate-300">{suppressTarget?.summary}</p>
        <label className="text-xs font-medium text-slate-300">Reason (required)</label>
        <textarea
          rows={3}
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          placeholder="e.g. known-good scanner, false positive because…"
        />
      </Modal>
    </div>
  );
}
