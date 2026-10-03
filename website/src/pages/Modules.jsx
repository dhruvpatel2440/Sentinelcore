import { PageHead } from "../components/ui.jsx";
import { MODULES, TOOLS } from "../data/modules.js";

export default function Modules() {
  return (
    <>
      <PageHead title="Modules and tools" label="Under the hood">
        SentinelCore is thirteen modules, M0 to M12. For each one: what it does, which tool powers it, and what you see
        in the dashboard.
      </PageHead>
      <div className="container">
        <ul className="anchor-list" aria-label="Jump to a module">
          {MODULES.map((m) => (
            <li key={m.id}>
              <a href={`#${m.id}`}>
                {m.id} {m.name}
              </a>
            </li>
          ))}
        </ul>

        <h2 className="sr-only">Modules M0 to M12</h2>
        <div className="grid grid--2">
          {MODULES.map((m) => (
            <article key={m.id} id={m.id} className="glass module" style={{ scrollMarginTop: 88 }}>
              <span className="module__id">{m.id}</span>
              <h3>{m.name}</h3>
              <p>{m.summary}</p>
              <dl>
                <dt>Powered by</dt>
                <dd>
                  <ul className="tags" style={{ margin: 0 }}>
                    {m.tools.map((t) => (
                      <li key={t}>
                        <span className="tool-tag">{t}</span>
                      </li>
                    ))}
                  </ul>
                </dd>
                <dt>You see in the dashboard</dt>
                <dd>
                  <ul>
                    {m.sees.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                </dd>
                <dt>Good to know</dt>
                <dd>{m.detail}</dd>
              </dl>
            </article>
          ))}
        </div>

        <h2 style={{ marginTop: 56 }}>The tools, in one place</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Tool</th>
                <th scope="col">What it does here</th>
              </tr>
            </thead>
            <tbody>
              {TOOLS.map((t) => (
                <tr key={t.name}>
                  <th scope="row" style={{ textTransform: "none", letterSpacing: 0, fontSize: 14, background: "transparent" }}>
                    {t.name}
                  </th>
                  <td>{t.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
