import { ChevronDown, LogOut, UserRound } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import Badge from "../components/Badge";

const ROLE_TONE = {
  admin: "danger",
  analyst: "accent",
  viewer: "neutral",
};

export default function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const containerRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (!containerRef.current?.contains(e.target)) setOpen(false);
    };
    const onKeyDown = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  if (!user) return null;

  const handleSignOut = async () => {
    setSigningOut(true);
    await logout();
    // `replace` so the back button cannot return to an authenticated view.
    navigate("/login", { replace: true });
  };

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-100"
      >
        <UserRound size={16} aria-hidden="true" />
        <span className="hidden max-w-[10rem] truncate sm:inline">{user.username}</span>
        <ChevronDown size={14} aria-hidden="true" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 z-50 mt-1 w-56 overflow-hidden rounded-md border border-slate-700 bg-slate-800 shadow-lg animate-fade-in"
        >
          <div className="border-b border-slate-700 px-3 py-2.5">
            <p className="truncate text-sm font-medium text-slate-100">
              {user.full_name || user.username}
            </p>
            <div className="mt-1.5 flex items-center gap-2">
              <Badge tone={ROLE_TONE[user.role] ?? "neutral"}>{user.role}</Badge>
              {user.email && (
                <span className="truncate text-xs text-slate-500">{user.email}</span>
              )}
            </div>
          </div>

          <button
            type="button"
            role="menuitem"
            onClick={handleSignOut}
            disabled={signingOut}
            className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm text-slate-300 hover:bg-slate-700 hover:text-slate-100 disabled:opacity-50"
          >
            <LogOut size={15} aria-hidden="true" />
            {signingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      )}
    </div>
  );
}
