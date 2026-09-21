import { X } from "lucide-react";
import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";

import clsx from "clsx";

const WIDTHS = {
  md: "max-w-md",
  lg: "max-w-xl",
  xl: "max-w-2xl",
};

/**
 * Side panel sliding in from the right, used wherever a row needs a detail
 * view without navigating away from the list behind it (M6 events, M8
 * incidents, M11 flows). Distinct from `Modal`, which is centered and for
 * short-lived actions rather than "keep browsing while this stays open".
 */
export default function Drawer({ open, onClose, title, description, footer, width = "lg", children }) {
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;

    const onKeyDown = (e) => {
      if (e.key === "Escape") onClose?.();
    };
    document.addEventListener("keydown", onKeyDown);
    panelRef.current?.focus();

    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-slate-950/60 animate-fade-in" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={clsx(
          "relative flex h-full w-full flex-col border-l border-slate-700 bg-slate-800 shadow-2xl outline-none animate-slide-in-right",
          WIDTHS[width] ?? WIDTHS.lg,
        )}
      >
        <header className="flex items-start justify-between gap-4 border-b border-slate-700 px-4 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-slate-100">{title}</h2>
            {description && <p className="mt-0.5 truncate text-xs text-slate-400">{description}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100"
          >
            <X size={16} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-4 py-4 text-sm text-slate-300">{children}</div>

        {footer && <footer className="flex justify-end gap-2 border-t border-slate-700 px-4 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}
