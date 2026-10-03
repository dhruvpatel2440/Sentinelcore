/*
 * One card per integrated module. Edit here; the Modules page renders it.
 * `sees` names real dashboard pages (sidebar labels in the app).
 * Facts come from the project README and module specs; nothing here is a measured result.
 */
export const MODULES = [
  {
    id: "M0",
    name: "Infrastructure",
    summary:
      "Everything runs as containers on one machine. A small privileged helper is the only part with raw-network capability; every other service is unprivileged.",
    tools: ["Docker Compose", "PostgreSQL 16", "Redis 7", "nginx"],
    sees: ["Service health indicator in the top bar", "Pipeline status indicator"],
    detail:
      "PostgreSQL stores everything durable, Redis holds queues and rate-limit counters, nginx is the only service that publishes ports.",
  },
  {
    id: "M1",
    name: "Authentication and roles",
    summary:
      "Sign-in with Argon2-hashed passwords, short-lived access tokens, refresh cookies and login throttling. Three roles decide what each person can do.",
    tools: ["FastAPI", "Argon2", "JWT"],
    sees: ["Login page", "Profile and notification settings", "Users (admin)"],
    detail: "Access tokens last 15 minutes, refresh tokens 7 days. Repeated failures lock the account and username pair for a while.",
  },
  {
    id: "M2",
    name: "App shell",
    summary: "The dashboard frame: sidebar grouped by Detect, Inventory, Respond, Reports and Admin, with items hidden when your role cannot use them.",
    tools: ["React", "Tailwind CSS"],
    sees: ["Sidebar navigation", "Top bar with live health", "Overview"],
    detail: "The sidebar and the route guards read the same role table, so a hidden item and a blocked page cannot disagree.",
  },
  {
    id: "M3",
    name: "Asset discovery",
    summary: "Finds the devices on the monitored network and what they expose, and keeps an inventory you can search and annotate.",
    tools: ["Nmap", "Scapy"],
    sees: ["Assets list", "Asset detail with open ports", "Scan dialog"],
    detail: "Scans are requested through the API but executed by the privileged helper, never by the web process.",
  },
  {
    id: "M4",
    name: "Suricata sensor",
    summary: "Starts, stops and reloads the Suricata detection engine, manages rule sources and per-rule overrides, and tests configuration before applying it.",
    tools: ["Suricata", "suricata-update", "privileged helper"],
    sees: ["Sensor page (admin)", "Rule sources", "Rule overrides", "Sensor events"],
    detail: "Rule files are staged by the API and verified by the helper before Suricata loads them.",
  },
  {
    id: "M5",
    name: "Event pipeline",
    summary: "Reads Suricata's EVE JSON log, normalises each record, removes duplicates and stores it in a time-partitioned events table with automatic retention.",
    tools: ["Suricata EVE JSON", "PostgreSQL (partitioned)", "Redis"],
    sees: ["Events page", "Pipeline indicator", "Overview counters"],
    detail: "A separate worker container remembers its read position, so an API restart never loses or repeats events.",
  },
  {
    id: "M6",
    name: "Search",
    summary: "Fast, filterable event search with facet counts, saved searches and bounded time windows so a query cannot run away.",
    tools: ["PostgreSQL", "Redis (facet cache)"],
    sees: ["Events filter bar", "Facets sidebar", "Saved searches", "Event detail"],
    detail: "Facet counts are cached for a short time; the maximum window is configurable.",
  },
  {
    id: "M7",
    name: "Correlation",
    summary: "Rule-based engine that groups related events into incident candidates. Rule types include threshold, sequence, beaconing and rare-event detection.",
    tools: ["Python correlation engine", "PostgreSQL", "Redis"],
    sees: ["Correlation page", "Rule editor", "Candidates tab"],
    detail: "Every candidate shows the rule that produced it and the events behind it. There is no machine learning in the detection path.",
  },
  {
    id: "M8",
    name: "Incidents",
    summary: "Turns candidates into incidents, tracks triage status and history, links evidence and records who did what.",
    tools: ["FastAPI", "PostgreSQL"],
    sees: ["Incidents queue", "Incident detail with history and evidence"],
    detail: "Related incidents merge inside a time window; high-scoring candidates are promoted automatically.",
  },
  {
    id: "M9",
    name: "Reporting",
    summary: "Generates reports on demand or on a schedule, in PDF, CSV or JSON, with limits so one user cannot overload the system.",
    tools: ["WeasyPrint", "Matplotlib", "Jinja2"],
    sees: ["Reports page", "Schedules tab (admin)", "New report dialog"],
    detail: "Reports are built by the worker and stored on a volume, not inside the image.",
  },
  {
    id: "M10",
    name: "Firewall containment",
    summary: "Blocks an address on the host firewall for a limited time. Every block has a TTL, protected addresses cannot be blocked, and expiry is enforced even if the web process restarts.",
    tools: ["iptables (nftables backend)", "privileged helper", "Redis"],
    sees: ["Firewall page (admin)", "New block dialog", "Active and expired blocks"],
    detail: "A reconciliation loop compares the kernel's rules with the database and repairs differences.",
  },
  {
    id: "M11",
    name: "PCAP analysis",
    summary: "Upload a packet capture and browse its flows, extracted artefacts and individual packets, or follow a stream, then attach findings to an incident.",
    tools: ["tshark", "capinfos"],
    sees: ["PCAP page", "Flow table and filters", "Flow detail drawer", "Attach to incident"],
    detail: "Captures are untrusted input, so they are parsed by an unprivileged process with time and memory limits, never by the privileged helper.",
  },
  {
    id: "M12",
    name: "Threat intelligence",
    summary: "Keep indicators of compromise, ingest feeds you choose, match live traffic against them and run retrospective hunts over stored events.",
    tools: ["PostgreSQL", "Feed ingestion worker"],
    sees: ["Threat Intel page", "IOC detail", "Sources tab", "Matches tab"],
    detail: "Feeds are fetched only from sources you add; each has size, time and row limits.",
  },
];

export const TOOLS = [
  { name: "Suricata", role: "Network intrusion detection engine; produces the alerts and flow records." },
  { name: "Nmap", role: "Host and service discovery for the asset inventory." },
  { name: "Scapy", role: "ARP sweep and packet crafting in the privileged helper." },
  { name: "tshark", role: "Offline PCAP parsing for flows, artefacts and stream follow." },
  { name: "iptables (nftables backend)", role: "Applies and removes TTL-bound firewall blocks via the helper." },
  { name: "PostgreSQL", role: "Durable storage: events, incidents, assets, intel, audit log." },
  { name: "Redis", role: "Queues, caches and login throttling." },
  { name: "FastAPI", role: "The API, running unprivileged." },
  { name: "React and Tailwind CSS", role: "The dashboard you use in the browser." },
  { name: "nginx", role: "Terminates HTTPS and is the only service that publishes ports." },
  { name: "Docker Compose", role: "Runs and supervises every service." },
];
