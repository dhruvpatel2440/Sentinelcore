import { Lock, Send } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Card from "../../components/Card";
import PageHeader from "../../components/PageHeader";
import { useToast } from "../../components/Toast";
import { FullPageSpinner } from "../../components/Spinner";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// Mirrors the A-E catalogue in docs/email.md. Locked ids come back from the
// API (`locked_types`) — this grouping is presentation only.
const TYPE_GROUPS = [
  {
    label: "A — Incident and detection",
    types: [
      { id: "E01", label: "New high/critical incident" },
      { id: "E02", label: "Incident escalated" },
      { id: "E03", label: "Incident assigned to you" },
      { id: "E04", label: "SLA reminder" },
      { id: "E05", label: "Incident resolved / reopened" },
      { id: "E06", label: "Threat-intel match" },
    ],
  },
  {
    label: "B — Containment",
    types: [
      { id: "E07", label: "Block applied" },
      { id: "E08", label: "Block expiring soon" },
      { id: "E09", label: "Block expired / revoked" },
      { id: "E10", label: "Block refused by protection guard" },
    ],
  },
  {
    label: "C — Reports",
    types: [
      { id: "E11", label: "Scheduled report delivered" },
      { id: "E12", label: "Report ready" },
      { id: "E13", label: "Report failed" },
      { id: "E14", label: "Daily / weekly digest" },
    ],
  },
  {
    label: "D — System health (admin)",
    types: [
      { id: "E15", label: "Sensor down / recovered" },
      { id: "E16", label: "Pipeline backlog" },
      { id: "E17", label: "Threat-intel feed failing" },
      { id: "E18", label: "Firewall drift" },
    ],
  },
  {
    label: "E — Account and security",
    types: [
      { id: "E19", label: "Account created / password reset" },
      { id: "E20", label: "Role changed / deactivated / password changed" },
      { id: "E21", label: "Suspicious login activity" },
    ],
  },
];

export default function NotificationsPage() {
  const toast = useToast();
  const [prefs, setPrefs] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testBusy, setTestBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPrefs(await api.get("/me/email-preferences"));
    } catch (err) {
      toast.error(err.message || "Could not load notification preferences");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const save = async (patch) => {
    setSaving(true);
    try {
      const updated = await api.put("/me/email-preferences", patch);
      setPrefs(updated);
      toast.success("Notification preferences saved");
    } catch (err) {
      toast.error(err.message || "Could not save preferences");
    } finally {
      setSaving(false);
    }
  };

  const toggleType = (id) => {
    if (!prefs || prefs.locked_types.includes(id)) return;
    const disabled = prefs.types_disabled.includes(id)
      ? prefs.types_disabled.filter((t) => t !== id)
      : [...prefs.types_disabled, id];
    save({ types_disabled: disabled });
  };

  const sendTest = async () => {
    setTestBusy(true);
    try {
      await api.post("/email/test", {});
      toast.success("Test email queued — check your inbox shortly");
    } catch (err) {
      toast.error(err.message || "Could not send a test email");
    } finally {
      setTestBusy(false);
    }
  };

  if (loading || !prefs) return <FullPageSpinner />;

  return (
    <div>
      <PageHeader
        title="Notification preferences"
        description="Choose which SentinelCore alerts reach your inbox. Security notices (D/E above) cannot be disabled."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="General" className="lg:col-span-1">
          <div className="space-y-4 text-sm">
            <label className="flex items-center justify-between gap-3">
              <span className="text-slate-300">Email notifications enabled</span>
              <input
                type="checkbox"
                checked={prefs.enabled}
                onChange={(e) => save({ enabled: e.target.checked })}
                className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-sky-500"
              />
            </label>

            <div>
              <label className="block text-xs font-medium text-slate-400" htmlFor="min-severity">
                Minimum severity for incident alerts
              </label>
              <select
                id="min-severity"
                value={prefs.min_severity}
                onChange={(e) => save({ min_severity: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400" htmlFor="delivery-mode">
                Delivery
              </label>
              <select
                id="delivery-mode"
                value={prefs.delivery_mode}
                onChange={(e) => save({ delivery_mode: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100"
              >
                <option value="instant">Instant</option>
                <option value="digest">Digest</option>
              </select>
            </div>

            {prefs.delivery_mode === "digest" && (
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs font-medium text-slate-400" htmlFor="digest-frequency">
                    Frequency
                  </label>
                  <select
                    id="digest-frequency"
                    value={prefs.digest_frequency}
                    onChange={(e) => save({ digest_frequency: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400" htmlFor="digest-hour">
                    Send time (IST)
                  </label>
                  <select
                    id="digest-hour"
                    value={prefs.digest_hour_utc}
                    onChange={(e) => save({ digest_hour_utc: Number(e.target.value) })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100"
                  >
                    {Array.from({ length: 24 }, (_, h) => {
                      const mins = (h * 60 + 330) % 1440;
                      const label = `${String(Math.floor(mins / 60)).padStart(2, "0")}:${String(mins % 60).padStart(2, "0")}`;
                      return (
                        <option key={h} value={h}>
                          {label} IST
                        </option>
                      );
                    })}
                  </select>
                </div>
              </div>
            )}

            <Button icon={Send} variant="secondary" size="sm" loading={testBusy} onClick={sendTest} className="w-full">
              Send me a test email
            </Button>
          </div>
        </Card>

        <Card title="Alert types" description="Grouped as in the catalogue. Locked types are security-critical and always on." className="lg:col-span-2">
          <div className="space-y-5">
            {TYPE_GROUPS.map((group) => (
              <div key={group.label}>
                <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{group.label}</h4>
                <div className="grid gap-2 sm:grid-cols-2">
                  {group.types.map((t) => {
                    const locked = prefs.locked_types.includes(t.id);
                    const checked = locked || !prefs.types_disabled.includes(t.id);
                    return (
                      <label
                        key={t.id}
                        title={locked ? "This alert is security-critical and cannot be disabled" : undefined}
                        className={`flex items-center gap-2 rounded-md border border-slate-800 px-2.5 py-2 text-sm ${
                          locked ? "cursor-not-allowed opacity-60" : "cursor-pointer hover:border-slate-700"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={locked}
                          onChange={() => toggleType(t.id)}
                          className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-sky-500"
                        />
                        <span className="flex-1 text-slate-300">
                          <span className="mr-1.5 font-mono text-xs text-slate-500">{t.id}</span>
                          {t.label}
                        </span>
                        {locked && <Lock size={13} className="text-slate-500" aria-hidden="true" />}
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
