import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import Button from "../components/Button";
import { FullPageSpinner } from "../components/Spinner";

function messageForError(err) {
  if (!(err instanceof ApiError)) {
    return "Could not reach the server. Check your connection and try again.";
  }
  if (err.status === 401) return "Invalid credentials";
  if (err.status === 429) return "Too many attempts, try again shortly";
  if (err.status >= 500) return "The server is unavailable right now. Try again shortly.";
  return err.message || "Sign in failed";
}

export default function LoginPage() {
  const { isAuthenticated, isLoading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);

  const from = location.state?.from?.pathname ?? "/";

  useEffect(() => {
    document.title = "Sign in · SentinelCore";
  }, []);

  if (isLoading) return <FullPageSpinner />;
  if (isAuthenticated) return <Navigate to={from} replace />;

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(messageForError(err));
      setPassword("");
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
          <p className="text-sm text-slate-400">Network detection &amp; incident response</p>
        </div>

        <form
          onSubmit={onSubmit}
          className="space-y-4 rounded-lg border border-slate-800 bg-slate-800/40 p-6"
        >
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

          <div>
            <label htmlFor="password" className="block text-xs font-medium text-slate-300">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
            >
              {error}
            </p>
          )}

          <Button type="submit" loading={pending} className="w-full" size="md">
            {pending ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </div>
  );
}
