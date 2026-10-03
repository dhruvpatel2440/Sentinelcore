import { Mail, Pause, Play, RotateCcw, Send, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { FullPageSpinner } from "../../components/Spinner";
import { absoluteTime, relativeTime } from "../../lib/format";

const STATUS_TONE = {
  queued: "accent",
  sending: "accent",
  sent: "success",
  failed: "danger",
  suppressed: "warning",
  dry_run: "neutral",
};

const ALL_TYPES = Array.from({ length: 21 }, (_, i) => `E${String(i + 1).padStart(2, "0")}`);

export default function EmailPage() {
  const toast = useToast();
  const [status, setStatus] = useState(null);
  const [outbox, setOutbox] = useState({ items: [], total: 0 });
  const [suppressions, setSuppressions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [testBusy, setTestBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.set("status", statusFilter);
      if (typeFilter) params.set("email_type", typeFilter);
      params.set("limit", "50");
      const [s, o, sup] = await Promise.all([
        api.get("/email/status"),
        api.get(`/email/outbox?${params.toString()}`),
        api.get("/email/suppressions"),
      ]);
      setStatus(s);
      setOutbox(o);
      setSuppressions(sup);
    } catch (err) {
      toast.error(err.message || "Could not load email status");
    } finally {
      setLoading(false);
    }
  }, [toast, statusFilter, typeFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const togglePause = async () => {
    try {
      const updated = await api.put("/email/settings", { global_pause: !status.global_pause });
      setStatus((s) => ({ ...s, global_pause: updated.global_pause }));
      toast.success(updated.global_pause ? "All outbound email paused" : "Email sending resumed");
    } catch (err) {
      toast.error(err.message || "Could not change the global pause");
    }
  };

  const retry = async (id) => {
    try {
      await api.post(`/email/outbox/${id}/retry`);
      toast.success("Row queued for retry");
      load();
    } catch (err) {
      toast.error(err.message || "Could not retry this row");
    }
  };

  const removeSuppression = async (id) => {
    try {
      await api.del(`/email/suppressions/${id}`);
      toast.success("Suppression removed");
      load();
    } catch (err) {
      toast.error(err.message || "Could not remove suppression");
    }
  };

  const sendTest = async () => {
    setTestBusy(true);
    try {
      await api.post("/email/test", {});
      toast.success("Test email queued to your own address");
    } catch (err) {
      toast.error(err.message || "Could not send a test email");
    } finally {
      setTestBusy(false);
    }
  };

  if (loading && !status) return <FullPageSpinner />;

  return (
    <div>
      <PageHeader
        title="Email"
        description="Brevo-backed transactional email: outbox, delivery status, and suppressions."
        actions={
          <>
            <Button icon={Send} variant="secondary" size="sm" loading={testBusy} onClick={sendTest}>
              Send test email
            </Button>
            <Button
              icon={status?.global_pause ? Play : Pause}
              variant={status?.global_pause ? "primary" : "danger"}
              size="sm"
              onClick={togglePause}
            >
              {status?.global_pause ? "Resume sending" : "Pause all sending"}
            </Button>
          </>
        }
      />

      <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <p className="text-xs text-slate-500">Mode</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">{status?.mode}</p>
          {status?.mode !== "brevo" && (
            <Badge tone="warning" className="mt-1">
              Not sending to Brevo
            </Badge>
          )}
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Queue depth</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">{status?.queue_depth}</p>
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Failed</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">{status?.failed_count}</p>
        </Card>
        <Card>
          <p className="text-xs text-slate-500">Sends today / cap</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">
            {status?.sends_today} / {status?.global_daily_cap}
          </p>
        </Card>
      </div>

      <div className="mb-4 grid gap-4 sm:grid-cols-2">
        <Card title="Sender &amp; webhook">
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between">
              <dt className="text-slate-500">Sender</dt>
              <dd className="text-slate-200">{status?.sender || "(not set)"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">API key configured</dt>
              <dd className="text-slate-200">{status?.api_key_present ? "yes" : "no"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Webhook</dt>
              <dd className="text-slate-200">{status?.webhook_active ? "active" : "polling fallback (see docs/email.md)"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Last successful send</dt>
              <dd className="text-slate-200">
                {status?.last_successful_send_at ? relativeTime(status.last_successful_send_at) : "never"}
              </dd>
            </div>
          </dl>
        </Card>

        <Card title="Suppressions" description="Addresses that will never be sent to again.">
          {suppressions.length === 0 ? (
            <p className="text-sm text-slate-500">No suppressed addresses.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {suppressions.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-2">
                  <span className="truncate text-slate-300">{s.email}</span>
                  <span className="flex items-center gap-2">
                    <Badge tone="warning">{s.reason}</Badge>
                    <button
                      type="button"
                      onClick={() => removeSuppression(s.id)}
                      className="text-slate-500 hover:text-rose-400"
                      title="Remove suppression"
                    >
                      <Trash2 size={14} />
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card
        title="Outbox"
        actions={
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
            >
              <option value="">Any status</option>
              {Object.keys(STATUS_TONE).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
            >
              <option value="">Any type</option>
              {ALL_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        }
      >
        <Table
          loading={loading}
          rows={outbox.items}
          columns={[
            { key: "created_at", header: "Created", render: (r) => <span title={absoluteTime(r.created_at)}>{relativeTime(r.created_at)}</span> },
            { key: "email_type", header: "Type" },
            { key: "recipient_email", header: "Recipient" },
            { key: "subject", header: "Subject" },
            { key: "status", header: "Status", render: (r) => <Badge tone={STATUS_TONE[r.status] ?? "neutral"}>{r.status}</Badge> },
            { key: "attempts", header: "Attempts" },
            {
              key: "actions",
              header: "",
              render: (r) =>
                r.status === "failed" ? (
                  <Button icon={RotateCcw} variant="ghost" size="sm" onClick={() => retry(r.id)}>
                    Retry
                  </Button>
                ) : null,
            },
          ]}
          empty={
            <div className="py-8 text-center text-sm text-slate-500">
              <Mail size={22} className="mx-auto mb-2 text-slate-600" />
              No outbox rows match this filter.
            </div>
          }
        />
      </Card>
    </div>
  );
}
