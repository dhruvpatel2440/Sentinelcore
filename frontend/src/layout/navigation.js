import {
  Activity,
  BarChart3,
  FileSearch,
  GitMerge,
  LayoutDashboard,
  Radar,
  ServerCog,
  ShieldAlert,
  ShieldBan,
  Target,
  Users,
} from "lucide-react";

/**
 * Single source of truth for navigation *and* route-level role requirements.
 * `ProtectedRoute` reads the same `roles` value the sidebar filters on, so a
 * hidden item and a blocked route can never drift apart.
 *
 * `roles: null` means any authenticated user.
 */
export const NAV_GROUPS = [
  {
    label: null,
    items: [{ to: "/", label: "Overview", icon: LayoutDashboard, roles: null, end: true }],
  },
  {
    label: "Detect",
    items: [
      { to: "/events", label: "Events", icon: Activity, roles: null },
      { to: "/correlation", label: "Correlation", icon: GitMerge, roles: null },
      { to: "/incidents", label: "Incidents", icon: ShieldAlert, roles: null },
      { to: "/intel", label: "Threat Intel", icon: Target, roles: null },
    ],
  },
  {
    label: "Inventory",
    items: [
      { to: "/assets", label: "Assets", icon: Radar, roles: null },
      { to: "/pcap", label: "PCAP", icon: FileSearch, roles: null },
    ],
  },
  {
    label: "Respond",
    items: [
      { to: "/firewall", label: "Firewall", icon: ShieldBan, roles: ["admin"] },
      { to: "/sensor", label: "Sensor", icon: ServerCog, roles: ["admin"] },
    ],
  },
  {
    label: "Reports",
    items: [{ to: "/reports", label: "Reports", icon: BarChart3, roles: null }],
  },
  {
    label: "Admin",
    items: [{ to: "/admin/users", label: "Users", icon: Users, roles: ["admin"] }],
  },
];

/** Flat lookup used for the top-bar page title. */
export const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);

export function titleForPath(pathname) {
  if (pathname === "/") return "Overview";
  const match = NAV_ITEMS.filter((i) => i.to !== "/")
    .sort((a, b) => b.to.length - a.to.length)
    .find((i) => pathname === i.to || pathname.startsWith(`${i.to}/`));
  return match?.label ?? "SentinelCore";
}
