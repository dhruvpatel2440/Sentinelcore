import { Link } from "react-router-dom";
import IncidentQueue from "../components/IncidentQueue.jsx";
import { usePageTitle } from "../components/ui.jsx";
import { HOW_IT_WORKS, PROOF_POINTS } from "../data/features.js";
import { TOOLS } from "../data/modules.js";

export default function Home() {
  usePageTitle("");
  return (
    <>
      <section className="hero">
        <div className="container hero__grid">
          <div>
            <p className="label" data-enter style={{ "--i": 0 }}>
              Network detection and incident response
            </p>
            <h1 data-enter style={{ "--i": 1 }}>
              Hundreds of alerts in. A <span className="hl">short list</span> of incidents out.
            </h1>
            <p className="hero__lead" data-enter style={{ "--i": 2 }}>
              SentinelCore watches your network, groups related alerts into incidents you can act on, and lets you
              block an attacker for a limited time. It installs on your own Linux machine and runs entirely there.
            </p>
            <div className="hero__cta" data-enter style={{ "--i": 3 }}>
              <Link className="btn btn--big" to="/download">
                Download for Linux
              </Link>
              <Link className="btn btn--ghost btn--big" to="/how-it-works">
                See how it works
              </Link>
            </div>
          </div>
          <div data-enter style={{ "--i": 2 }}>
            <IncidentQueue />
          </div>
        </div>
      </section>

      <section className="section--tight">
        <div className="container">
          <div className="grid grid--3">
            {PROOF_POINTS.map((p) => (
              <article key={p.title} className="glass card proof">
                <h3>{p.title}</h3>
                <p className="muted">{p.text}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <h2>How it works</h2>
          <p className="muted" style={{ maxWidth: "60ch" }}>
            Four stages, from packets to a decision. Each stage is a separate part you can inspect.
          </p>
          <ol className="how">
            {HOW_IT_WORKS.map((s) => (
              <li key={s.title} className="glass">
                <strong>{s.title}</strong>
                <span className="muted" style={{ fontSize: 14 }}>
                  {s.text}
                </span>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="section--tight">
        <div className="container">
          <h2>Built on tools you may already know</h2>
          <ul className="tags">
            {TOOLS.map((t) => (
              <li key={t.name}>
                <span className="tool-tag">{t.name}</span>
              </li>
            ))}
          </ul>
          <p>
            <Link to="/modules">See every module and the tool behind it</Link>
          </p>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="glass glass--lg cta-band">
            <h2>Try it on a lab network</h2>
            <p className="muted" style={{ maxWidth: "56ch", marginInline: "auto" }}>
              A guided setup asks for your capture interface, the network to monitor, protected addresses and an
              admin account, then installs and starts everything.
            </p>
            <div className="hero__cta">
              <Link className="btn btn--big" to="/download">
                Download for Linux
              </Link>
              <Link className="btn btn--ghost btn--big" to="/docs">
                Read the docs
              </Link>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
