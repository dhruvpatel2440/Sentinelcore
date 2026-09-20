import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { ApiError, api, configureAuth, refreshAccessToken } from "../api/client";

const AuthContext = createContext(null);

/** Refresh this many ms before the access token actually expires. */
const REFRESH_LEAD_MS = 60_000;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // The access token lives in a ref, not state: the API client reads it
  // synchronously on every request, and re-rendering the whole tree each time
  // it rotates would be pointless churn. It is never persisted anywhere.
  const tokenRef = useRef(null);
  const refreshTimer = useRef(null);

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimer.current) {
      clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
    }
  }, []);

  const clearSession = useCallback(() => {
    tokenRef.current = null;
    setUser(null);
    clearRefreshTimer();
  }, [clearRefreshTimer]);

  /** Arm the silent refresh so an idle tab never falls out of its session. */
  const scheduleRefresh = useCallback((expiresInSeconds) => {
    clearRefreshTimer();
    const delay = Math.max((expiresInSeconds || 900) * 1000 - REFRESH_LEAD_MS, 5_000);
    refreshTimer.current = setTimeout(() => {
      // Failure here is not fatal: the next real request will hit a 401 and
      // the client's retry path takes over.
      refreshAccessToken().catch(() => {});
    }, delay);
  }, [clearRefreshTimer]);

  const applySession = useCallback(
    (data) => {
      tokenRef.current = data.access_token;
      if (data.user) setUser(data.user);
      scheduleRefresh(data.expires_in);
    },
    [scheduleRefresh],
  );

  // Register this provider with the module-level API client exactly once.
  useEffect(() => {
    configureAuth({
      tokenGetter: () => tokenRef.current,
      onTokenRefreshed: applySession,
      onSessionLost: clearSession,
    });
  }, [applySession, clearSession]);

  // Bootstrap: one refresh attempt on mount. Until it settles we render a
  // loader, so an already-signed-in user never sees the login screen flash.
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        await refreshAccessToken();
        const me = await api.get("/auth/me");
        if (!cancelled) setUser(me);
      } catch {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // Intentionally runs once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => clearRefreshTimer, [clearRefreshTimer]);

  const login = useCallback(
    async (username, password) => {
      const data = await api.post("/auth/login", { username, password });
      applySession(data);
      return data.user;
    },
    [applySession],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Even if the server call fails, drop local credentials — the user
      // asked to sign out and must end up signed out.
    } finally {
      clearSession();
    }
  }, [clearSession]);

  const hasRole = useCallback(
    (...roles) => {
      if (!user) return false;
      const wanted = roles.flat();
      return wanted.length === 0 || wanted.includes(user.role);
    },
    [user],
  );

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: Boolean(user),
      isLoading,
      login,
      logout,
      hasRole,
    }),
    [user, isLoading, login, logout, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside an <AuthProvider>");
  return ctx;
}

export { ApiError };
