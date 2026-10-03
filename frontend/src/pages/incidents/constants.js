export const STATUS_TONE = {
  new: "accent",
  triage: "warning",
  investigating: "warning",
  contained: "accent",
  resolved: "success",
  false_positive: "neutral",
};

export const STATUS_LABEL = {
  new: "New",
  triage: "Triage",
  investigating: "Investigating",
  contained: "Contained",
  resolved: "Resolved",
  false_positive: "False positive",
};

export const TERMINAL_STATUSES = new Set(["resolved", "false_positive"]);

export const FORWARD_TRANSITIONS = {
  new: ["triage", "false_positive"],
  triage: ["investigating", "false_positive"],
  investigating: ["contained", "false_positive"],
  contained: ["resolved", "false_positive"],
  resolved: [],
  false_positive: [],
};

export const QUEUE_TABS = [
  { key: "my_open", label: "My open" },
  { key: "unassigned", label: "Unassigned" },
  { key: "all_open", label: "All open" },
  { key: "critical", label: "Critical" },
  { key: "recently_closed", label: "Recently closed" },
];

export function paramsForTab(key, userId) {
  const params = new URLSearchParams();
  switch (key) {
    case "my_open":
      params.set("assigned_to", "me");
      break;
    case "unassigned":
      params.set("assigned_to", "unassigned");
      break;
    case "critical":
      params.set("severity", "critical");
      break;
    case "recently_closed":
      params.set("status", "resolved");
      params.append("status", "false_positive");
      break;
    default:
      break;
  }
  return params;
}

export function ageTone(openedAt) {
  const hours = (Date.now() - new Date(openedAt).getTime()) / 3_600_000;
  if (hours > 48) return "text-rose-300";
  if (hours > 8) return "text-amber-300";
  return "text-slate-300";
}
