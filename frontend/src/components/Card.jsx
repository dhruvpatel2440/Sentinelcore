import clsx from "clsx";

export default function Card({ title, description, actions, className, bodyClassName, children }) {
  const hasHeader = title || description || actions;

  return (
    <section
      className={clsx(
        "rounded-lg border border-slate-800 bg-slate-800/40 shadow-sm",
        className,
      )}
    >
      {hasHeader && (
        <header className="flex items-start justify-between gap-4 border-b border-slate-800 px-4 py-3">
          <div className="min-w-0">
            {title && <h3 className="text-sm font-semibold text-slate-100">{title}</h3>}
            {description && <p className="mt-0.5 text-xs text-slate-400">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}
