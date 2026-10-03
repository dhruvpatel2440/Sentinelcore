import { Link } from "react-router-dom";
import { PageHead } from "../components/ui.jsx";
import { FEATURES } from "../data/features.js";

export default function Features() {
  return (
    <>
      <PageHead title="Features" label="What it does">
        From finding your devices to blocking an attacker, each capability is a separate part of the dashboard.
      </PageHead>
      <div className="container">
        <ul className="anchor-list" aria-label="Jump to a feature">
          {FEATURES.map((f) => (
            <li key={f.id}>
              <a href={`#${f.id}`}>{f.title.replace(/ with TTL and protected IPs/, "")}</a>
            </li>
          ))}
        </ul>
        <h2 className="sr-only">All features</h2>
        <div className="grid grid--2">
          {FEATURES.map((f) => (
            <section key={f.id} id={f.id} className="glass feature" style={{ scrollMarginTop: 88 }}>
              <h3>{f.title}</h3>
              <p>{f.text}</p>
              <ul className="tags" aria-label="Powered by">
                {f.tools.map((t) => (
                  <li key={t}>
                    <span className="tool-tag">{t}</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <p style={{ marginTop: 32 }}>
          Want the detail per module? <Link to="/modules">Modules and tools</Link>.
        </p>
      </div>
    </>
  );
}
