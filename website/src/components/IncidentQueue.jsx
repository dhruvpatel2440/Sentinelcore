import { Severity } from "./ui.jsx";

/* Hero illustration: many raw alerts collapse into a few incidents. All figures are sample data. */
const INCIDENTS = [
  { level: "critical", title: "Possible ransomware staging", meta: "10.0.4.17 → file server", count: "212 alerts" },
  { level: "high", title: "Repeated SSH password guessing", meta: "203.0.113.50 → 3 hosts", count: "96 alerts" },
  { level: "medium", title: "Regular beacon to rare domain", meta: "10.0.4.33 → every 60 s", count: "41 alerts" },
  { level: "low", title: "Outdated TLS version in use", meta: "printer-2.lan", count: "9 alerts" },
];

export default function IncidentQueue() {
  return (
    <section className="queue glass glass--lg" aria-labelledby="queue-title">
      <div className="queue__head">
        <h2 id="queue-title" style={{ fontSize: 20, margin: 0 }}>
          Incident queue
        </h2>
        <span className="badge badge--violet">Sample data</span>
      </div>
      <div className="queue__collapse" aria-label="Raw alerts reduced to incidents">
        <span className="big">358</span>
        <span>raw alerts</span>
        <span className="queue__arrow" aria-hidden="true">→</span>
        <span className="big">{INCIDENTS.length}</span>
        <span>incidents</span>
      </div>
      <ul>
        {INCIDENTS.map((i) => (
          <li key={i.title}>
            <Severity level={i.level} />
            <div>
              <div className="title">{i.title}</div>
              <div className="meta">{i.meta}</div>
            </div>
            <span className="count">{i.count}</span>
          </li>
        ))}
      </ul>
      <p className="queue__foot">Illustration with invented figures. Not a measurement.</p>
    </section>
  );
}
