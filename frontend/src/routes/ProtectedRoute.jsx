import { ShieldX } from "lucide-react";
import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { FullPageSpinner } from "../components/Spinner";

export function ForbiddenPage() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="max-w-md text-center">
        <ShieldX size={32} className="mx-auto text-rose-400" aria-hidden="true" />
        <h1 className="mt-3 text-lg font-semibold text-slate-100">Access denied</h1>
        <p className="mt-1 text-sm text-slate-400">
          Your role does not permit access to this area. If you believe this is a mistake,
          contact an administrator.
        </p>
      </div>
    </div>
  );
}

/**
 * Second layer of authorization. The backend is the real boundary — this
 * exists so the UI does not render a page the API will only reject, and so
 * hidden nav is never the only thing standing between a user and a route.
 */
export default function ProtectedRoute({ roles = null, children }) {
  const { isAuthenticated, isLoading, hasRole } = useAuth();
  const location = useLocation();

  if (isLoading) return <FullPageSpinner />;

  if (!isAuthenticated) {
    // Remember where they were headed so login can send them back.
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (roles && !hasRole(roles)) return <ForbiddenPage />;

  return children ?? <Outlet />;
}
