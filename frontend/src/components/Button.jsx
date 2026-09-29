import clsx from "clsx";

import Spinner from "./Spinner";

const VARIANTS = {
  primary: "bg-sky-600 text-white hover:bg-sky-500 focus-visible:outline-sky-400",
  secondary:
    "bg-slate-700 text-slate-100 hover:bg-slate-600 focus-visible:outline-slate-400",
  danger: "bg-rose-600 text-white hover:bg-rose-500 focus-visible:outline-rose-400",
  ghost:
    "bg-transparent text-slate-300 hover:bg-slate-800 hover:text-slate-100 focus-visible:outline-slate-500",
};

const SIZES = {
  sm: "px-2.5 py-1.5 text-xs gap-1.5",
  md: "px-3.5 py-2 text-sm gap-2",
};

export default function Button({
  variant = "primary",
  size = "md",
  loading = false,
  disabled = false,
  icon: Icon,
  className,
  children,
  type = "button",
  ...props
}) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={clsx(
        "inline-flex items-center justify-center rounded-md font-medium transition-colors",
        "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
        "disabled:cursor-not-allowed disabled:opacity-50",
        VARIANTS[variant] ?? VARIANTS.primary,
        SIZES[size] ?? SIZES.md,
        className,
      )}
      {...props}
    >
      {loading ? (
        <Spinner size={size === "sm" ? 12 : 14} />
      ) : (
        Icon && <Icon size={size === "sm" ? 14 : 16} aria-hidden="true" />
      )}
      {children}
    </button>
  );
}
