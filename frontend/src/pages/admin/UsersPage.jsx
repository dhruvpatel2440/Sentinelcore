import { KeyRound, Plus, Trash2, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import Modal from "../../components/Modal";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, relativeTime } from "../../lib/format";

const ROLES = ["viewer", "analyst", "admin"];
const MIN_PASSWORD_LENGTH = 12; // mirrors backend `_MIN_PASSWORD_LENGTH`

const ROLE_TONE = { admin: "danger", analyst: "accent", viewer: "neutral" };

export default function UsersPage() {
  const toast = useToast();
  const { user: me } = useAuth();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [resetFor, setResetFor] = useState(null);
  const [busy, setBusy] = useState(false);

  const [form, setForm] = useState({ username: "", password: "", email: "", full_name: "", role: "viewer" });
  const [newPassword, setNewPassword] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setUsers(await api.get("/users"));
    } catch (err) {
      toast.error(err.message || "Could not load users");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const createUser = async () => {
    setBusy(true);
    try {
      await api.post("/users", {
        username: form.username.trim(),
        password: form.password,
        email: form.email.trim() || null,
        full_name: form.full_name.trim() || null,
        role: form.role,
      });
      toast.success(`User ${form.username} created`);
      setCreateOpen(false);
      setForm({ username: "", password: "", email: "", full_name: "", role: "viewer" });
      load();
    } catch (err) {
      toast.error(err.message || "Could not create user");
    } finally {
      setBusy(false);
    }
  };

  // Role and activation changes take effect on the user's NEXT request: the
  // backend bumps tokens_valid_from, so existing sessions are revoked.
  const patchUser = async (u, body, what) => {
    try {
      await api.patch(`/users/${u.id}`, body);
      toast.success(`${u.username}: ${what}`);
      load();
    } catch (err) {
      toast.error(err.message || `Could not update ${u.username}`);
    }
  };

  const resetPassword = async () => {
    setBusy(true);
    try {
      await api.post(`/users/${resetFor.id}/password`, { new_password: newPassword });
      toast.success(`Password reset for ${resetFor.username} — their sessions are now revoked`);
      setResetFor(null);
      setNewPassword("");
    } catch (err) {
      toast.error(err.message || "Could not reset password");
    } finally {
      setBusy(false);
    }
  };

  const deleteUser = async (u) => {
    if (!window.confirm(`Delete ${u.username}? This cannot be undone.`)) return;
    try {
      await api.del(`/users/${u.id}`);
      toast.success(`${u.username} deleted`);
      load();
    } catch (err) {
      toast.error(err.message || "Could not delete user");
    }
  };

  const columns = [
    {
      key: "username",
      header: "Username",
      render: (u) => (
        <span className="text-slate-100">
          {u.username}
          {u.id === me?.id && <span className="ml-1.5 text-xs text-slate-500">(you)</span>}
        </span>
      ),
    },
    { key: "full_name", header: "Name", render: (u) => u.full_name || "—" },
    { key: "email", header: "Email", render: (u) => u.email || "—" },
    {
      key: "role",
      header: "Role",
      render: (u) => (
        <select
          value={u.role}
          disabled={u.id === me?.id}
          title={u.id === me?.id ? "You cannot change your own role" : undefined}
          onChange={(e) => patchUser(u, { role: e.target.value }, `role set to ${e.target.value}`)}
          className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 disabled:opacity-50"
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      ),
    },
    {
      key: "is_active",
      header: "Status",
      render: (u) => (
        <button
          disabled={u.id === me?.id}
          title={u.id === me?.id ? "You cannot deactivate yourself" : undefined}
          onClick={() => patchUser(u, { is_active: !u.is_active }, u.is_active ? "deactivated" : "reactivated")}
          className={`rounded-full px-2 py-0.5 text-xs ring-1 ring-inset disabled:opacity-50 ${
            u.is_active
              ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
              : "bg-slate-700/50 text-slate-400 ring-slate-600"
          }`}
        >
          {u.is_active ? "Active" : "Disabled"}
        </button>
      ),
    },
    {
      key: "last_login_at",
      header: "Last login",
      render: (u) =>
        u.last_login_at ? <span title={absoluteTime(u.last_login_at)}>{relativeTime(u.last_login_at)}</span> : "never",
    },
    { key: "created_at", header: "Created", render: (u) => relativeTime(u.created_at) },
    {
      key: "actions",
      header: "",
      render: (u) => (
        <div className="flex justify-end gap-1">
          <Button size="sm" variant="secondary" icon={KeyRound} onClick={() => setResetFor(u)}>
            Reset
          </Button>
          <Button size="sm" variant="ghost" icon={Trash2} disabled={u.id === me?.id} onClick={() => deleteUser(u)}>
            Delete
          </Button>
        </div>
      ),
    },
  ];

  const createValid =
    form.username.trim().length >= 3 && form.password.length >= MIN_PASSWORD_LENGTH;

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts, roles and access review. Role and status changes revoke the user's active sessions."
        actions={
          <Button icon={Plus} onClick={() => setCreateOpen(true)}>
            New user
          </Button>
        }
      />

      <Table
        columns={columns}
        rows={users}
        loading={loading}
        rowKey={(u) => u.id}
        empty={<EmptyState icon={Users} title="No users yet" />}
      />

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create user"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={createUser} loading={busy} disabled={!createValid}>
              Create
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Username</label>
            <input
              autoFocus
              value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              placeholder="letters, digits, . _ - only"
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-300">Password</label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            />
            <p className={`mt-1 text-xs ${form.password && form.password.length < MIN_PASSWORD_LENGTH ? "text-rose-400" : "text-slate-500"}`}>
              At least {MIN_PASSWORD_LENGTH} characters.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300">Full name</label>
              <input
                value={form.full_name}
                onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300">Role</label>
              <select
                value={form.role}
                onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-slate-300">Email (optional)</label>
            <input
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={Boolean(resetFor)}
        onClose={() => {
          setResetFor(null);
          setNewPassword("");
        }}
        title={`Reset password for ${resetFor?.username ?? ""}`}
        description="This immediately revokes every active session for that user."
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => {
                setResetFor(null);
                setNewPassword("");
              }}
            >
              Cancel
            </Button>
            <Button variant="danger" onClick={resetPassword} loading={busy} disabled={newPassword.length < MIN_PASSWORD_LENGTH}>
              Reset password
            </Button>
          </>
        }
      >
        <label className="text-xs font-medium text-slate-300">New password</label>
        <input
          type="password"
          autoFocus
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
        />
        <p className={`mt-1 text-xs ${newPassword && newPassword.length < MIN_PASSWORD_LENGTH ? "text-rose-400" : "text-slate-500"}`}>
          At least {MIN_PASSWORD_LENGTH} characters.
        </p>
      </Modal>
    </>
  );
}
