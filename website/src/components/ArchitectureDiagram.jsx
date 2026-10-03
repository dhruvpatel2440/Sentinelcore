/*
 * Inline SVG architecture diagram. Node fills come from tokens.css through the
 * .diagram classes in global.css, so the diagram follows the theme. Each node
 * has a hard offset shadow drawn as a black rect behind it.
 */
function Node({ x, y, w = 140, h = 56, kind = "", title, sub }) {
  return (
    <g>
      <rect className="shadow" x={x + 4} y={y + 4} width={w} height={h} rx="10" />
      <rect className={`node ${kind ? `node--${kind}` : ""}`} x={x} y={y} width={w} height={h} rx="10" />
      <text x={x + w / 2} y={sub ? y + h / 2 - 3 : y + h / 2 + 5} textAnchor="middle">
        {title}
      </text>
      {sub && (
        <text className="sub" x={x + w / 2} y={y + h / 2 + 15} textAnchor="middle">
          {sub}
        </text>
      )}
    </g>
  );
}

const Edge = ({ d, dash }) => <path className={`edge${dash ? " edge--dash" : ""}`} d={d} markerEnd="url(#arrow)" />;
const Label = ({ x, y, children, anchor = "middle" }) => (
  <text className="sub label-text" x={x} y={y} textAnchor={anchor}>
    {children}
  </text>
);

export default function ArchitectureDiagram() {
  return (
    <div className="diagram glass glass--lg">
      <svg viewBox="0 0 960 500" role="img" aria-labelledby="arch-title arch-desc">
        <title id="arch-title">SentinelCore architecture</title>
        <desc id="arch-desc">
          Your browser connects over HTTPS to nginx, which serves the React dashboard and proxies the API. The API uses
          PostgreSQL and Redis and sends privileged requests over a Unix socket to the privileged helper. The helper
          controls Suricata and applies firewall rules and discovery scans. Suricata writes an EVE JSON log that the
          event pipeline stores as events. The correlation engine turns events into incidents. Uploaded packet captures
          are parsed by tshark inside the unprivileged backend.
        </desc>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M0 0 10 5 0 10z" />
          </marker>
        </defs>

        {/* privileged zone */}
        <rect className="zone" x="712" y="14" width="228" height="330" rx="22" />
        <text className="zone-label" x="728" y="34">PRIVILEGED BOUNDARY</text>

        {/* front door and API */}
        <Node x={20} y={150} w={130} kind="ui" title="Browser" sub="HTTPS" />
        <Node x={200} y={150} w={130} title="nginx" sub="only open ports" />
        <Node x={390} y={40} w={140} title="React" sub="static dashboard" />
        <Node x={390} y={150} w={140} title="FastAPI" sub="API, unprivileged" />
        <Node x={390} y={260} w={140} kind="data" title="PostgreSQL" sub="and Redis" />
        <Node x={190} y={260} w={150} title="PCAP parser" sub="tshark, unprivileged" />

        {/* privileged side */}
        <Node x={730} y={40} w={190} title="Firewall + Nmap" sub="iptables-nft, Scapy" />
        <Node x={730} y={150} w={190} kind="priv" title="Privileged helper" sub="Unix socket only" />
        <Node x={730} y={260} w={190} kind="sensor" title="Suricata" sub="detection engine" />

        {/* event flow */}
        <Node x={730} y={410} w={190} kind="sensor" title="Event pipeline" sub="reads eve.json" />
        <Node x={500} y={410} w={150} kind="data" title="Events" sub="partitioned table" />
        <Node x={290} y={410} w={150} title="Correlation" sub="rules to candidates" />
        <Node x={80} y={410} w={150} kind="data" title="Incidents" sub="triage + history" />

        <Edge d="M150 178 H198" />
        <Edge d="M330 164 L388 74" />
        <Edge d="M330 178 H388" />
        <Edge d="M460 206 V258" />
        <Edge dash d="M410 206 L338 258" />
        <Edge dash d="M530 178 H728" />
        <Label x={629} y={168}>Unix socket</Label>
        <Edge d="M825 150 V98" />
        <Edge d="M825 206 V258" />
        <Edge d="M825 316 V408" />
        <Label x={835} y={368} anchor="start">eve.json</Label>
        <Edge d="M730 438 H652" />
        <Edge d="M500 438 H442" />
        <Edge d="M290 438 H232" />
        <Label x={360} y={346}>uploads go through the API</Label>
      </svg>
      <ul className="muted" style={{ fontSize: 14, marginTop: 16 }}>
        <li>Browser → nginx → dashboard and API. nginx is the only service with published ports.</li>
        <li>API → privileged helper over a Unix socket. Scans, sensor control and firewall changes all cross this one boundary.</li>
        <li>Suricata → eve.json → event pipeline → events → correlation → incidents.</li>
        <li>Packet captures are parsed by tshark inside the unprivileged backend, never by the helper.</li>
      </ul>
    </div>
  );
}
