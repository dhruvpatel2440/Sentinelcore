import { Check, ExternalLink, FileText, Plus, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Card from "../../components/Card";
import Modal from "../../components/Modal";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";
import NewReportModal from "../reports/NewReportModal";
import { FORWARD_TRANSITIONS, STATUS_LABEL, STATUS_TONE, TERMINAL_STATUSES } from "./constants";

const RESOLUTION_TEMPLATE = "Root cause: \nActions taken: \nVerified: ";
const FALSE_POSITIVE_TEMPLATE = "Reason this is not a true positive: ";

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-200">{children ?? "—"}</dd>
    </div>
  );
}

export default function IncidentDetail() {
  const { number } = useParams();
  const navigate = useNavigate();
  const { hasRole, user } = useAuth();
  const toast = useToast();
  const canEdit = hasRole("analyst", "admin");
  const isAdmin = hasRole("admin");

  const [incident, setIncident] = useState(null);
  const [events, setEvents] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  const [titleDraft, setTitleDraft] = useState("");
  const [editingTitle, setEditingTitle] = useState(false);
  const [comment, setComment] = useState("");
  const [closeModal, setCloseModal] = useState(null); // "resolved" | "false_positive"
  const [closeNote, setCloseNote] = useState("");
  const [addEventsOpen, setAddEventsOpen] = useState(false);
  const [addEventsInput, setAddEventsInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.get(`/incidents?q=${number}&status=new&status=triage&status=investigating&status=contained&status=resolved&status=false_positive`);
      const found = list.items.find((i) => String(i.number) === String(number));
      if (!found) {
        toast.error(`INC-${number} not found`);
        navigate("/incidents");
        return;
      }
      const [detail, linkedEvents, hist] = await Promise.all([
        api.get(`/incidents/${found.id}`),
        api.get(`/incidents/${found.id}/events`).catch(() => []),
        api.get(`/incidents/${found.id}/history`).catch(() => []),
      ]);
      setIncident(detail);
      setTitleDraft(detail.title);
      setEvents(linkedEvents);
      setHistory(hist);
    } catch (err) {
      toast.error(err.message || "Could not load incident");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [number]);

  useEffect(() => {
    load();
  }, [load]);

  const patch = async (body) => {
    setBusy(true);
    try {
      const updated = await api.patch(`/incidents/${incident.id}`, { version: incident.version, ...body });
      setIncident((i) => ({ ...i, ...updated }));
      return updated;
    } catch (err) {
      toast.error(err.message || "Update failed");
      throw err;
    } finally {
      setBusy(false);
    }
  };

  const saveTitle = async () => {
    if (titleDraft.trim() && titleDraft !== incident.title) await patch({ title: titleDraft.trim() });
    setEditingTitle(false);
  };

  const changeStatus = async (targetStatus, note) => {
    setBusy(true);
    try {
      const updated = await api.post(`/incidents/${incident.id}/status`, {
        version: incident.version,
        status: targetStatus,
        note,
      });
      setIncident((i) => ({ ...i, ...updated }));
      toast.success(`Status changed to ${STATUS_LABEL[targetStatus]}`);
      load();
    } catch (err) {
      toast.error(err.message || "Status change failed");
    } finally {
      setBusy(false);
    }
  };

  const assign = async (userId) => {
    setBusy(true);
    try {
      const updated = await api.post(`/incidents/${incident.id}/assign`, { version: incident.version, user_id: userId });
      setIncident((i) => ({ ...i, ...updated }));
      toast.success(userId ? "Assigned" : "Unassigned");
      load();
    } catch (err) {
      toast.error(err.message || "Assignment failed");
    } finally {
      setBusy(false);
    }
  };

  const submitComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    try {
      await api.post(`/incidents/${incident.id}/comments`, { note: comment.trim() });
      setComment("");
      load();
    } catch (err) {
      toast.error(err.message || "Could not add comment");
    } finally {
      setBusy(false);
    }
  };

  const submitClose = async () => {
    await changeStatus(closeModal, closeNote.trim());
    setCloseModal(null);
    setCloseNote("");
  };

  const addEvents = async () => {
    const ids = addEventsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map(Number)
      .filter((n) => !Number.isNaN(n));
    if (!ids.length) return;
    setBusy(true);
    try {
      await api.post(`/incidents/${incident.id}/events`, { event_ids: ids });
      toast.success(`Linked ${ids.length} event(s)`);
      setAddEventsOpen(false);
      setAddEventsInput("");
      load();
    } catch (err) {
      toast.error(err.message || "Could not link events");
    } finally {
      setBusy(false);
    }
  };

  const unlinkEvent = async (eventId) => {
    try {
      await api.del(`/incidents/${incident.id}/events/${eventId}`);
      load();
    } catch (err) {
      toast.error(err.message || "Could not unlink event");
    }
  };

  if (loading || !incident) {
    return <p className="text-sm text-slate-400">Loading…</p>;
  }

  const legalTargets = FORWARD_TRANSITIONS[incident.status] || [];
  const canReopen = TERMINAL_STATUSES.has(incident.status) && isAdmin;

  return (
    <>
      <PageHeader
        title={
          <div className="flex items-center gap-2">
            <span className="font-mono text-slate-500">INC-{incident.number}</span>
            {editingTitle ? (
              <input
                autoFocus
                value={titleDraft}
                onChange={(e) => setTitleDraft(e.target.value)}
                onBlur={saveTitle}
                onKeyDown={(e) => e.key === "Enter" && saveTitle()}
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-lg"
              />
            ) : (
              <button
                disabled={!canEdit}
                onClick={() => setEditingTitle(true)}
                className="text-left hover:underline disabled:no-underline"
              >
                {incident.title}
              </button>
            )}
          </div>
        }
        description={`Opened ${relativeTime(incident.opened_at)} · MTTA ${incident.acknowledged_at ? relativeTime(incident.acknowledged_at) : "pending"}`}
        actions={
          <div className="flex items-center gap-2">
            <Button size="sm" variant="secondary" icon={FileText} onClick={() => setReportModalOpen(true)}>
              Generate report
            </Button>
            <Badge severity={incident.severity} />
            <Badge tone={STATUS_TONE[incident.status]}>{STATUS_LABEL[incident.status]}</Badge>
          </div>
        }
      />

      {canEdit && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          {legalTargets
            .filter((t) => !TERMINAL_STATUSES.has(t))
            .map((t) => (
              <Button key={t} size="sm" variant="secondary" onClick={() => changeStatus(t)} disabled={busy}>
                Move to {STATUS_LABEL[t]}
              </Button>
            ))}
          {legalTargets.includes("resolved") && (
            <Button size="sm" onClick={() => { setCloseModal("resolved"); setCloseNote(RESOLUTION_TEMPLATE); }}>
              Close: Resolved
            </Button>
          )}
          {legalTargets.includes("false_positive") && (
            <Button size="sm" variant="secondary" onClick={() => { setCloseModal("false_positive"); setCloseNote(FALSE_POSITIVE_TEMPLATE); }}>
              Close: False positive
            </Button>
          )}
          {canReopen && (
            <Button size="sm" variant="secondary" onClick={() => changeStatus("investigating")}>
              Reopen
            </Button>
          )}
          {incident.assigned_to === user?.id ? (
            <Button size="sm" variant="ghost" onClick={() => assign(null)} disabled={busy}>
              Unassign
            </Button>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => assign(user.id)} disabled={busy}>
              Assign to me
            </Button>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[18rem_minmax(0,1fr)_20rem]">
        <div className="space-y-4">
          <Card title="Description">
            <p className="whitespace-pre-wrap text-sm text-slate-300">{incident.description || "—"}</p>
          </Card>
          <Card title="Indicators">
            <dl className="space-y-3">
              <Field label="Source IP">
                {incident.src_ip ? (
                  <Link className="flex items-center gap-1 text-sky-300 hover:underline" to={`/events?ip=${incident.src_ip}/32`}>
                    {incident.src_ip} <ExternalLink size={11} />
                  </Link>
                ) : (
                  "—"
                )}
              </Field>
              <Field label="Destination IP">
                {incident.dst_ip ? (
                  <Link className="flex items-center gap-1 text-sky-300 hover:underline" to={`/events?ip=${incident.dst_ip}/32`}>
                    {incident.dst_ip} <ExternalLink size={11} />
                  </Link>
                ) : (
                  "—"
                )}
              </Field>
              <Field label="Rule">{incident.rule_name || "manual"}</Field>
              <Field label="Score">{incident.score}</Field>
            </dl>
          </Card>
          {incident.asset_hostname && (
            <Card title="Affected asset">
              <p className="text-sm text-slate-200">{incident.asset_hostname}</p>
            </Card>
          )}
        </div>

        <Card
          title={`Linked events (${events.length})`}
          actions={canEdit && <Button size="sm" icon={Plus} onClick={() => setAddEventsOpen(true)}>Add events</Button>}
        >
          <Table
            columns={[
              { key: "ts", header: "Time", render: (e) => relativeTime(e.ts) },
              { key: "severity", header: "Sev", render: (e) => <Badge severity={e.severity} /> },
              { key: "signature", header: "Signature", render: (e) => e.signature || "—" },
              { key: "src_ip", header: "Src → Dst", render: (e) => `${e.src_ip ?? "—"} → ${e.dst_ip ?? "—"}` },
              ...(canEdit
                ? [
                    {
                      key: "actions",
                      header: "",
                      render: (e) => (
                        <button onClick={() => unlinkEvent(e.id)} className="rounded p-1 text-slate-500 hover:bg-slate-700 hover:text-rose-300">
                          <X size={13} />
                        </button>
                      ),
                    },
                  ]
                : []),
            ]}
            rows={events}
            rowKey={(e) => e.id}
            empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No events linked yet.</p>}
          />
        </Card>

        <Card title="Activity">
          <div className="max-h-[28rem] space-y-3 overflow-y-auto">
            {history.map((h) => (
              <div key={h.id} className="text-xs">
                <div className="flex items-center justify-between text-slate-500">
                  <span>{h.username || "system"}</span>
                  <span title={absoluteTime(h.created_at)}>{relativeTime(h.created_at)}</span>
                </div>
                <p className="mt-0.5 text-slate-300">
                  {h.action === "commented" ? h.note : `${h.action.replace(/_/g, " ")}${h.from_value ? ` (${h.from_value} → ${h.to_value})` : ""}`}
                  {h.action !== "commented" && h.note && <span className="block text-slate-500">{h.note}</span>}
                </p>
              </div>
            ))}
            {history.length === 0 && <p className="text-xs text-slate-500">No activity yet.</p>}
          </div>

          {canEdit && (
            <div className="mt-3 flex gap-2 border-t border-slate-700 pt-3">
              <textarea
                rows={2}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Add a comment…"
                className="flex-1 rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              />
              <Button size="sm" icon={Check} onClick={submitComment} disabled={!comment.trim() || busy}>
                Post
              </Button>
            </div>
          )}
        </Card>
      </div>

      <Modal
        open={Boolean(closeModal)}
        onClose={() => setCloseModal(null)}
        title={`Close as ${closeModal ? STATUS_LABEL[closeModal] : ""}`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCloseModal(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={submitClose} loading={busy} disabled={!closeNote.trim()}>
              Close incident
            </Button>
          </>
        }
      >
        <label className="text-xs font-medium text-slate-300">Resolution note (required)</label>
        <textarea
          rows={5}
          autoFocus
          value={closeNote}
          onChange={(e) => setCloseNote(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
      </Modal>

      <Modal
        open={addEventsOpen}
        onClose={() => setAddEventsOpen(false)}
        title="Add events"
        description="Paste event IDs (comma-separated) — pivot from M6 search to find them."
        footer={
          <>
            <Button variant="ghost" onClick={() => setAddEventsOpen(false)}>
              Cancel
            </Button>
            <Button onClick={addEvents} loading={busy}>
              Link events
            </Button>
          </>
        }
      >
        <textarea
          rows={3}
          autoFocus
          value={addEventsInput}
          onChange={(e) => setAddEventsInput(e.target.value)}
          placeholder="123456, 123457, 123458"
          className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
        <Link
          to={`/events?from=${new Date(incident.first_event_ts || incident.opened_at).toISOString()}`}
          className="mt-2 inline-flex items-center gap-1 text-xs text-sky-300 hover:underline"
        >
          Open M6 search in this incident's window <ExternalLink size={11} />
        </Link>
      </Modal>

      <NewReportModal
        open={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        onCreated={() => toast.success("Report queued — check the Reports page")}
        prefill={{
          reportType: "incident_detail",
          incidentId: incident.id,
          title: `Incident report — INC-${incident.number}`,
        }}
      />
    </>
  );
}
