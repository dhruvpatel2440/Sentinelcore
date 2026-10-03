/* Feature sections for the Features page. Plain statements of what the product does, no measured claims. */
export const FEATURES = [
  {
    id: "assets",
    title: "Asset discovery",
    text: "See what is on your network before an alert mentions it. SentinelCore sweeps the monitored range and records each device and the ports it exposes, so an alert about 192.168.56.20 can be read as 'the file server' instead of a bare address.",
    tools: ["Nmap", "Scapy"],
  },
  {
    id: "detection",
    title: "Suricata detection",
    text: "Suricata inspects the traffic on your capture interface against rule sets you choose. Start, stop and reload it from the dashboard, add rule sources, and override individual rules without editing files.",
    tools: ["Suricata", "suricata-update"],
  },
  {
    id: "pipeline",
    title: "Event pipeline",
    text: "Raw alerts, flows, DNS, HTTP and TLS records are normalised, de-duplicated and stored with automatic retention. The reader remembers where it stopped, so restarts neither lose nor repeat events.",
    tools: ["EVE JSON", "PostgreSQL"],
  },
  {
    id: "search",
    title: "Search and facets",
    text: "Filter events by time, address, signature or severity, narrow with facet counts, and save the searches you repeat. Time windows are capped so a careless query cannot stall the system.",
    tools: ["PostgreSQL"],
  },
  {
    id: "correlation",
    title: "Correlation into incidents",
    text: "Rules group related events: too many of something in a window (threshold), steps in an order (sequence), regular check-ins (beaconing) and things that almost never happen (rare). Each candidate shows which rule fired and why, so you can read the logic.",
    tools: ["Correlation engine"],
  },
  {
    id: "incidents",
    title: "Incident workflow",
    text: "Candidates become incidents with a score, a status and a history. Analysts triage, add evidence and resolve; related incidents merge within a time window so one attacker is not twenty tickets.",
    tools: ["FastAPI", "PostgreSQL"],
  },
  {
    id: "firewall",
    title: "Firewall containment with TTL and protected IPs",
    text: "Block a hostile address on the host firewall for a fixed time. There is no permanent block: every rule expires. Your gateway, DNS servers and the SentinelCore machine itself are protected and can never be blocked, however the request arrives.",
    tools: ["iptables (nftables)", "privileged helper"],
  },
  {
    id: "pcap",
    title: "PCAP investigation",
    text: "Upload a capture and explore it in the browser: flow list, per-flow detail, extracted artefacts, packet view and stream follow. Attach what you find to an incident.",
    tools: ["tshark"],
  },
  {
    id: "intel",
    title: "Threat intelligence",
    text: "Maintain indicators of compromise by hand or from feeds you add, match them against live traffic, and run a retrospective hunt over events you already stored.",
    tools: ["IOC store", "Feed ingestion"],
  },
  {
    id: "reports",
    title: "Reports",
    text: "Produce PDF, CSV or JSON reports on demand or on a schedule. Generation runs in the background with per-user limits and a retention period.",
    tools: ["WeasyPrint", "Matplotlib"],
  },
  {
    id: "audit",
    title: "Audit log",
    text: "Every action that changes something is recorded with who, what, when and from where. The database refuses to update or delete audit rows, and a hash chain makes tampering detectable.",
    tools: ["PostgreSQL"],
  },
  {
    id: "roles",
    title: "Roles",
    text: "Viewer, analyst and admin. Viewers read, analysts triage and investigate, admins also run the sensor, the firewall and user management.",
    tools: ["RBAC"],
  },
  {
    id: "email",
    title: "Email notifications (optional)",
    text: "Get notified about new incidents, SLA breaches, threat-intel matches and suspicious sign-ins. Off by default; you choose the provider settings and which recipients are allowed.",
    tools: ["Brevo (optional)"],
  },
];

export const PROOF_POINTS = [
  {
    title: "Every alert traces to a rule you can read",
    text: "Detection comes from Suricata signatures and correlation rules. There is no machine learning in the detection path, so there is no black box to trust.",
  },
  {
    title: "Blocks always expire",
    text: "Firewall containment has a mandatory time limit and a protected list that includes your gateway, DNS and this machine. You cannot lock yourself out.",
  },
  {
    title: "It runs on your machine",
    text: "Install it on your own Linux computer. Your traffic, events and settings stay there. It reaches the internet only for things you switch on, such as rule updates.",
  },
];

export const HOW_IT_WORKS = [
  { title: "Capture", text: "Suricata watches a mirrored or promiscuous network interface." },
  { title: "Normalise", text: "The pipeline stores alerts and flows as clean, searchable events." },
  { title: "Correlate", text: "Rules group related events into a short list of incidents." },
  { title: "Respond", text: "Triage, investigate, and contain with a firewall block that expires." },
];
