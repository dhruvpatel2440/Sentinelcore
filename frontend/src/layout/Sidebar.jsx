import { ShieldCheck, X } from "lucide-react";
import { NavLink } from "react-router-dom";

import clsx from "clsx";

import { useAuth } from "../auth/AuthContext";
import { NAV_GROUPS } from "./navigation";

function NavItem({ item, collapsed, onNavigate }) {
  const Icon = item.icon;
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onNavigate}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        clsx(
          "group flex items-center gap-3 rounded-md px-2.5 py-2 text-sm transition-colors",
          collapsed && "justify-center px-0",
          isActive
            ? "bg-sky-500/10 text-sky-300"
            : "text-slate-400 hover:bg-slate-800 hover:text-slate-100",
        )
      }
    >
      <Icon size={18} className="shrink-0" aria-hidden="true" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </NavLink>
  );
}

export default function Sidebar({ collapsed, mobileOpen, onCloseMobile }) {
  const { hasRole } = useAuth();

  // Items the role cannot reach are removed entirely, not disabled — a
  // disabled control still advertises that the capability exists.
  const groups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.roles || hasRole(item.roles)),
  })).filter((group) => group.items.length > 0);

  const content = (
    <>
      <div
        className={clsx(
          "flex h-topbar items-center gap-2 border-b border-slate-800 px-4",
          collapsed && "justify-center px-0",
        )}
      >
        <ShieldCheck size={20} className="shrink-0 text-sky-500" aria-hidden="true" />
        {!collapsed && (
          <span className="truncate font-semibold tracking-tight text-slate-100">
            SentinelCore
          </span>
        )}
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation"
          className="ml-auto rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100 md:hidden"
        >
          <X size={18} />
        </button>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-2 py-4">
        {groups.map((group, gi) => (
          <div key={group.label ?? `group-${gi}`}>
            {group.label && !collapsed && (
              <p className="px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                {group.label}
              </p>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavItem
                  key={item.to}
                  item={item}
                  collapsed={collapsed}
                  onNavigate={onCloseMobile}
                />
              ))}
            </div>
          </div>
        ))}
      </nav>
    </>
  );

  return (
    <>
      {/* Off-canvas drawer below md */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-950/70 md:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        className={clsx(
          "fixed inset-y-0 left-0 z-50 flex w-sidebar flex-col border-r border-slate-800 bg-slate-900",
          "transition-transform duration-200 md:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          collapsed ? "md:w-sidebar-collapsed" : "md:w-sidebar",
        )}
      >
        {content}
      </aside>
    </>
  );
}
