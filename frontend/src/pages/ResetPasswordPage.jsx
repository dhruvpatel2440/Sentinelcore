import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { ApiError, api } from "../api/client";
import Button from "../components/Button";

const MIN_PASSWORD_LENGTH = 12; // mirrors backend `_MIN_PASSWORD_LENGTH`

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get("token") || "";

  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    document.title = "Reset password · SentinelCore";
  }, []);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      return;
    }
    if (newPassword !== confirm) {
      setError("Passwords do not match");
      return;
    }

    setPending(true);
    try {
      await api.post("/auth/password-reset/confirm", { token, new_password: newPassword });
      setDone(true);
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message || "Invalid or expired token" : "Could not reach the server");
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <ShieldCheck size={32} className="text-sky-500" aria-hidden="true" />
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">SentinelCore</h1>
        </div>

        <div className="space-y-4 rounded-lg border border-slate-800 bg-slate-800/40 p-6">
          {!token ? (
            <p className="text-sm text-rose-300">This link is missing its token. Request a new one.</p>
          ) : done ? (
            <p className="text-sm text-emerald-300">Password set. Redirecting you to sign in…</p>
          ) : (
            <form onSubmit={onSubmit} className="space-y-4">
              <div>
                <label htmlFor="new_password" className="block text-xs font-medium text-slate-300">
                  New password
                </label>
                <input
                  id="new_password"
                  type="password"
                  autoComplete="new-password"
                  required
                  autoFocus
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              </div>
              <div>
                <label htmlFor="confirm" className="block text-xs font-medium text-slate-300">
                  Confirm password
                </label>
                <input
                  id="confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              </div>

              {error && (
                <p role="alert" className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                  {error}
                </p>
              )}

              <Button type="submit" loading={pending} className="w-full" size="md">
                Set new password
              </Button>
            </form>
          )}

          <p className="text-center text-xs text-slate-500">
            <Link to="/login" className="text-sky-400 hover:text-sky-300">
              Back to sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
