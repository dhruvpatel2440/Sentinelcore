import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";

import clsx from "clsx";

const ToastContext = createContext(null);

const TONES = {
  success: { icon: CheckCircle2, ring: "ring-emerald-500/30", text: "text-emerald-300" },
  error: { icon: XCircle, ring: "ring-rose-500/30", text: "text-rose-300" },
  warning: { icon: AlertTriangle, ring: "ring-amber-500/30", text: "text-amber-300" },
  info: { icon: Info, ring: "ring-sky-500/30", text: "text-sky-300" },
};

const DEFAULT_DURATION = 5000;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef(new Map());
  const nextId = useRef(0);

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (toast) => {
      const id = ++nextId.current;
      const duration = toast.duration ?? DEFAULT_DURATION;
      setToasts((list) => [...list, { ...toast, id }]);

      if (duration > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), duration),
        );
      }
      return id;
    },
    [dismiss],
  );

  const value = useMemo(
    () => ({
      toast: push,
      success: (message, opts) => push({ ...opts, tone: "success", message }),
      error: (message, opts) => push({ ...opts, tone: "error", message }),
      warning: (message, opts) => push({ ...opts, tone: "warning", message }),
      info: (message, opts) => push({ ...opts, tone: "info", message }),
      dismiss,
    }),
    [push, dismiss],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      {createPortal(
        <div
          className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2"
          role="region"
          aria-live="polite"
        >
          {toasts.map((t) => {
            const tone = TONES[t.tone] ?? TONES.info;
            const Icon = tone.icon;
            return (
              <div
                key={t.id}
                className={clsx(
                  "pointer-events-auto flex items-start gap-3 rounded-lg border border-slate-700",
                  "bg-slate-800 px-3 py-2.5 shadow-lg ring-1 animate-slide-up",
                  tone.ring,
                )}
              >
                <Icon size={16} className={clsx("mt-0.5 shrink-0", tone.text)} aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  {t.title && <p className="text-sm font-medium text-slate-100">{t.title}</p>}
                  <p className="text-xs text-slate-300">{t.message}</p>
                </div>
                <button
                  type="button"
                  onClick={() => dismiss(t.id)}
                  aria-label="Dismiss notification"
                  className="rounded p-0.5 text-slate-500 hover:bg-slate-700 hover:text-slate-200"
                >
                  <X size={14} />
                </button>
              </div>
            );
          })}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside a <ToastProvider>");
  return ctx;
}
