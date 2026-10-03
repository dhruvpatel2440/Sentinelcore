import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import Button from "../components/Button";

export default function ForgotPasswordPage() {
  const [username, setUsername] = useState("");
  const [pending, setPending] = useState(false);
  // The response is identical whether or not the account exists — shown
  // unconditionally once a request is submitted, never branched on by this
  // page, which is the whole point of the backend's generic reply.
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    document.title = "Forgot password · SentinelCore";
  }, []);

  const onSubmit = async (e) => {
    e.preventDefault();
    setPending(true);
    try {
      await api.post("/auth/password-reset/request", { username });
    } catch {
      // Intentionally ignored — the UI shows the same confirmation either way.
    } finally {
      setPending(false);
      setSubmitted(true);
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
          {submitted ? (
            <p className="text-sm text-slate-300">
              If that account exists, a password reset email has been sent. Check your inbox.
            </p>
          ) : (
            <form onSubmit={onSubmit} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-xs font-medium text-slate-300">
                  Username
                </label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  autoFocus
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              </div>
              <Button type="submit" loading={pending} className="w-full" size="md">
                Send reset link
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
