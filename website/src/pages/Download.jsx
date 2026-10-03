import { useRef } from "react";
import { Link } from "react-router-dom";
import { CodeBlock, PageHead } from "../components/ui.jsx";
import releases from "../data/releases.json";
import { SUPPORTED, UNSUPPORTED } from "../data/platforms.js";

const isReleased = (d) => releases.status === "available" && Boolean(d.url);
const anyReleased = releases.downloads.some(isReleased);

function DownloadChooser({ dialogRef }) {
  const close = () => dialogRef.current?.close();
  return (
    <dialog
      ref={dialogRef}
      className="chooser"
      aria-labelledby="chooser-title"
      onClick={(e) => {
        if (e.target === dialogRef.current) close();
      }}
    >
      <div className="chooser__head">
        <div>
          <h3 id="chooser-title">Choose how to install</h3>
          <p className="muted" style={{ margin: 0, fontSize: 14 }}>
            {anyReleased
              ? `Version ${releases.version}${releases.released ? `, released ${releases.released}` : ""}`
              : "The installer is not published yet. Nothing below is a working link."}
          </p>
        </div>
        <button type="button" className="icon-btn" onClick={close} aria-label="Close">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" aria-hidden="true">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>
      <div className="chooser__body">
        {releases.downloads.map((d) => {
          const ready = isReleased(d);
          return (
            <section key={d.id} className="option" aria-labelledby={`opt-${d.id}`}>
              <h4 id={`opt-${d.id}`}>
                {d.label}
                {d.recommended && <span className="badge badge--mint">Recommended</span>}
                {!ready && <span className="badge badge--medium">Coming soon</span>}
              </h4>
              <p className="muted" style={{ fontSize: 14, marginBottom: 8 }}>
                {d.summary}
              </p>
              <p className="mono muted" style={{ marginBottom: 8 }}>
                {d.file}
              </p>
              {ready && d.command && <pre>{d.command}</pre>}
              {ready ? (
                <a className="btn" href={d.url} style={{ marginTop: 12 }}>
                  Download {d.file}
                </a>
              ) : (
                <button type="button" className="btn" aria-disabled="true" disabled style={{ marginTop: 12 }}>
                  Installer coming soon
                </button>
              )}
            </section>
          );
        })}
      </div>
    </dialog>
  );
}

function PlatformTable() {
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Supported Linux distributions and their test status</caption>
        <thead>
          <tr>
            <th scope="col">Distribution</th>
            <th scope="col">Version</th>
            <th scope="col">Status</th>
            <th scope="col">Notes</th>
          </tr>
        </thead>
        <tbody>
          {SUPPORTED.map((p) => (
            <tr key={p.distro + p.version}>
              <td>{p.distro}</td>
              <td>{p.version}</td>
              <td>
                {p.status === "tested" ? (
                  <span className="badge badge--mint">Tested</span>
                ) : (
                  <span className="badge badge--info">Expected to work, untested</span>
                )}
              </td>
              <td className="muted">{p.notes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Download() {
  const dialogRef = useRef(null);
  const open = () => dialogRef.current?.showModal();
  const hashed = releases.downloads.filter((d) => d.sha256);

  return (
    <>
      <PageHead title="Download" label="Get SentinelCore">
        SentinelCore installs on your own Linux machine. A guided wizard asks a few questions, writes the configuration,
        then installs and starts everything.
      </PageHead>
      <div className="container">
        <section className="glass glass--lg cta-band" aria-labelledby="dl-cta">
          <h2 id="dl-cta" className="sr-only">
            Download
          </h2>
          <button type="button" className="btn btn--big" onClick={open}>
            Download SentinelCore
          </button>
          <p className="muted" style={{ marginTop: 16, marginBottom: 0 }}>
            {anyReleased ? (
              <>Version {releases.version} for Linux. Choose a one-line installer, a .deb package or an offline bundle.</>
            ) : (
              <>
                <strong>Installer coming soon.</strong> The first signed release has not been published yet. Pick an
                option to see what each one will be.
              </>
            )}
          </p>
        </section>

        <div className="grid grid--2" style={{ marginTop: 32, alignItems: "start" }}>
          <section className="glass card">
            <h3>Latest version</h3>
            <p className="mono" style={{ fontSize: 20 }}>
              {anyReleased ? releases.version : "No release published yet"}
            </p>
            <p className="muted">Supported: Ubuntu 24.04 on x86_64 (the target platform; see the table below for test status).</p>
          </section>
          <section className="glass card">
            <h3>Installation</h3>
            <ol>
              <li>Download</li>
              <li>Run the installer: <code className="inline">sudo ./install.sh</code></li>
              <li>Complete the setup wizard</li>
              <li>Open the dashboard</li>
            </ol>
          </section>
        </div>

        <h2 style={{ marginTop: 56 }}>System requirements</h2>
        <div className="stat-row">
          <div className="glass req"><span className="big">Linux</span>Ubuntu or Debian family. Not Windows, macOS or WSL.</div>
          <div className="glass req"><span className="big">4 GB RAM</span>2 CPU cores recommended.</div>
          <div className="glass req"><span className="big">10 GB disk</span>More for captures and long event retention.</div>
          <div className="glass req"><span className="big">1 interface</span>One that sees the traffic: a mirror (SPAN) port, or a VirtualBox adapter set to promiscuous "Allow All".</div>
          <div className="glass req"><span className="big">Ports 80, 443</span>Free on the listen address; changeable in a custom install.</div>
          <div className="glass req"><span className="big">Docker</span>Engine and Compose v2. The installer can add them with your consent.</div>
        </div>

        <h2 style={{ marginTop: 56 }}>Supported Linux distributions</h2>
        <PlatformTable />
        <p className="muted" style={{ marginTop: 12, fontSize: 14 }}>
          "Tested" means the installer was run end to end on a clean virtual machine. Everything else is the same family
          of system and should work, but nobody has installed it there yet. Not supported:{" "}
          {UNSUPPORTED.map((u) => `${u.distro} (${u.notes.replace(/\.$/, "").toLowerCase()})`).join("; ")}. No ISO image is
          offered.
        </p>

        <h2 style={{ marginTop: 56 }}>Checksums</h2>
        {hashed.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {hashed.map((d) => (
                  <tr key={d.id}>
                    <td className="mono">{d.file}</td>
                    <td className="mono hash">{d.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">
            SHA-256 checksums are published with each release, together with a signature you can verify. See{" "}
            <Link to="/docs#verify">verifying a download</Link>.
          </p>
        )}
        {releases.signingKey.fingerprint && (
          <p>
            Release signing key fingerprint: <code className="inline hash">{releases.signingKey.fingerprint}</code>
          </p>
        )}

        <h2 style={{ marginTop: 56 }}>What the setup wizard asks</h2>
        <div className="grid grid--2" style={{ alignItems: "start" }}>
          <ol className="steps">
            <li>
              <div>
                <h3 className="h4">Capture interface</h3>
                <p className="muted">The network card Suricata watches. The wizard lists real interfaces with their state and warns if you pick the one carrying your own connection.</p>
              </div>
            </li>
            <li>
              <div>
                <h3 className="h4">Monitored network</h3>
                <p className="muted">The range you are allowed to watch, pre-filled from the interface, for example 192.168.56.0/24.</p>
              </div>
            </li>
            <li>
              <div>
                <h3 className="h4">Protected IPs</h3>
                <p className="muted">Addresses that can never be blocked. Your gateway and DNS are detected; this machine is added automatically. The list cannot be empty.</p>
              </div>
            </li>
            <li>
              <div>
                <h3 className="h4">Admin account</h3>
                <p className="muted">A username and a password of at least 12 characters, or let the installer generate one and show it once.</p>
              </div>
            </li>
            <li>
              <div>
                <h3 className="h4">Ports and access</h3>
                <p className="muted">Quick install keeps the dashboard on this machine at HTTPS port 443. Custom lets you choose a LAN address and ports.</p>
              </div>
            </li>
          </ol>
          <div>
            <CodeBlock title="sudo sentinelcore install" label="Illustration of a wizard screen">
              <span className="acc">SentinelCore setup</span>
              {"\n"}
              <span className="dim">────────────────────────────────────────</span>
              {"\n"}
              <span className="vio">Capture interface</span>
              {"\n\n"}
              {"  enp0s3   up, 10.0.2.15/24  "}
              <span className="dim">(management)</span>
              {"\n"}
              {"> "}
              <span className="acc">enp0s8   up, 192.168.56.102/24</span>
              {"\n\n"}
              <span className="dim">{"<Select>   <Back>"}</span>
              {"\n\n"}
              <span className="dim">Illustration. Real screens depend on your machine.</span>
            </CodeBlock>
          </div>
        </div>

        <h2 style={{ marginTop: 56 }}>After the install</h2>
        <ol className="steps">
          <li>
            <div>
              <h3 className="h4">Open the dashboard</h3>
              <p>
                Go to <code className="inline">https://localhost</code> (or the address shown at the end of setup). Your
                browser will warn about the certificate because it is self-signed for your machine. That is expected;
                you can replace it later.
              </p>
            </div>
          </li>
          <li>
            <div>
              <h3 className="h4">Sign in as the admin</h3>
              <p>Use the username and password from the wizard. The sensor is already running on your chosen interface.</p>
            </div>
          </li>
          <li>
            <div>
              <h3 className="h4">Check health any time</h3>
              <p>
                Run <code className="inline">sudo sentinelcore status</code>, or{" "}
                <code className="inline">sudo sentinelcore doctor</code> if something looks wrong. More in the{" "}
                <Link to="/docs">docs</Link>.
              </p>
            </div>
          </li>
        </ol>
      </div>
      <DownloadChooser dialogRef={dialogRef} />
    </>
  );
}
