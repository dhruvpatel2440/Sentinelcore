import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { PageHead } from "../components/ui.jsx";

const TOC = [
  ["install", "Install"],
  ["first-run", "First run"],
  ["roles", "Roles"],
  ["backup-update", "Backup and update"],
  ["verify", "Verify a download"],
  ["uninstall", "Uninstall"],
  ["troubleshooting", "Troubleshooting"],
  ["faq", "FAQ"],
];

const C = ({ children }) => <code className="inline">{children}</code>;

export default function Docs() {
  const { hash } = useLocation();
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView();
  }, [hash]);

  return (
    <>
      <PageHead title="Docs" label="Using SentinelCore">
        Everything from the first install to uninstalling. Commands need administrator rights, so they start with{" "}
        <C>sudo</C>.
      </PageHead>
      <div className="container docs-layout">
        <nav className="glass docs-toc" aria-label="On this page">
          <ul>
            {TOC.map(([id, label]) => (
              <li key={id}>
                <a href={`#${id}`}>{label}</a>
              </li>
            ))}
          </ul>
        </nav>

        <div>
          <section id="install" className="glass doc-section">
            <h2>Install</h2>
            <p>You need a Linux machine (Ubuntu or Debian family) with an interface that can see the traffic to watch.</p>
            <ol>
              <li>Download from the <a href="/download">Download page</a>: the one-line installer, the .deb, or the offline bundle.</li>
              <li>Run the installer. With the .deb: <C>sudo apt install ./sentinelcore_&lt;version&gt;_all.deb</C>, then <C>sudo sentinelcore install</C>.</li>
              <li>Answer the wizard. Use <strong>Back</strong> to change an earlier answer; the last screen lets you review everything before installing.</li>
              <li>Wait for the progress list to finish. It ends with a verification of the API, containers, sensor and admin sign-in.</li>
            </ol>
            <p>
              Want to review the settings first? <C>sudo sentinelcore install --generate-only</C> writes the configuration
              and installs nothing. To repeat a setup on another machine, copy{" "}
              <C>/etc/sentinelcore/install-profile.yaml</C> (it contains no secrets) and run{" "}
              <C>sudo sentinelcore install --config install-profile.yaml --non-interactive</C> with the admin password in
              the <C>SENTINELCORE_ADMIN_PASSWORD</C> environment variable. New secrets are generated per machine.
            </p>
          </section>

          <section id="first-run" className="glass doc-section">
            <h2>First run</h2>
            <ol>
              <li>Open <C>https://localhost</C>. Accept the self-signed certificate warning once.</li>
              <li>Sign in with the admin account from setup.</li>
              <li><strong>Sensor:</strong> confirm Suricata is running and add or update rule sources.</li>
              <li><strong>Assets:</strong> run a first discovery scan of your monitored network.</li>
              <li><strong>Users:</strong> create analyst and viewer accounts for your team.</li>
            </ol>
            <p className="muted">If you see no traffic, run <C>sudo sentinelcore doctor</C>. The most common cause is an interface that does not receive a copy of the network's traffic.</p>
          </section>

          <section id="roles" className="glass doc-section">
            <h2>Roles</h2>
            <p><strong>Viewer</strong> reads. <strong>Analyst</strong> triages incidents, runs scans, analyses captures, manages indicators and generates reports. <strong>Admin</strong> also controls the sensor and firewall and manages users. The full table is on the <a href="/roles">Roles page</a>.</p>
          </section>

          <section id="backup-update" className="glass doc-section">
            <h2>Backup and update</h2>
            <p><strong>Back up:</strong></p>
            <pre className="terminal" style={{ padding: 16, overflowX: "auto" }}>sudo sentinelcore backup</pre>
            <p>This writes one encrypted file (database and configuration) protected by a passphrase you choose. The passphrase cannot be recovered, so store it safely. Restore with <C>sudo sentinelcore restore &lt;file&gt;</C>; it asks you to type the host name because a restore replaces the current database.</p>
            <p><strong>Update:</strong></p>
            <pre className="terminal" style={{ padding: 16, overflowX: "auto" }}>sudo sentinelcore update</pre>
            <p>It checks the release channel, verifies the signature and checksum, takes a backup, installs the new version and checks health. If the new version does not become healthy it puts the previous release back.</p>
          </section>

          <section id="verify" className="glass doc-section">
            <h2>Verify a download</h2>
            <p>Every release publishes a checksum file and a signature made with the release key. The one-line installer and <C>sentinelcore update</C> check both automatically. To check by hand:</p>
            <pre className="terminal" style={{ padding: 16, overflowX: "auto" }}>{`gpg --show-keys release-key.asc     # compare the fingerprint with this site
gpg --import release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS`}</pre>
          </section>

          <section id="uninstall" className="glass doc-section">
            <h2>Uninstall</h2>
            <p><C>sudo sentinelcore uninstall</C> stops and removes the services but <strong>keeps your data</strong> and configuration, so you can reinstall later. <C>sudo sentinelcore uninstall --purge</C> deletes everything, including the database, and asks you to type the host name to confirm. To remove the program files too: <C>sudo apt remove sentinelcore</C>.</p>
          </section>

          <section id="troubleshooting" className="glass doc-section">
            <h2>Troubleshooting</h2>
            <p>Start with <C>sudo sentinelcore doctor</C>. It checks the capture interface, promiscuous mode, Suricata packet drops, ports, the system clock, file permissions and the certificate, and suggests a fix for each problem.</p>
            <details><summary>The dashboard does not open</summary><p>Run <C>sudo sentinelcore status</C>. If services are down, <C>sudo sentinelcore start</C>. If ports 80 or 443 are used by another program, free them or reinstall with other ports (Custom install).</p></details>
            <details><summary>The browser warns about the certificate</summary><p>Expected: the installer creates a self-signed certificate for your machine. Proceed once, or replace the files in <C>/etc/sentinelcore/tls</C> with your own and run <C>sudo sentinelcore restart</C>.</p></details>
            <details><summary>No events appear</summary><p>The capture interface must receive the traffic. On a switch use a mirror (SPAN) port. In VirtualBox set the adapter's Promiscuous Mode to "Allow All". Then check <C>sudo sentinelcore doctor</C>.</p></details>
            <details><summary>I forgot the admin password</summary><p>Another admin can reset it from Users. If there is none, see the support notes in the repository documentation; the generated password is shown only once during setup.</p></details>
            <details><summary>Where are the logs?</summary><p>Install log: <C>/var/log/sentinelcore-install.log</C>. Service logs: <C>sudo sentinelcore logs backend</C> (or any service name).</p></details>
          </section>

          <section id="faq" className="glass doc-section">
            <h2>FAQ</h2>
            <details open><summary>Does anything leave my machine?</summary>
              <p>Your traffic, events, incidents and settings stay on your machine. The application makes outbound connections only for features you switch on: Suricata rule sources you enable, threat-intelligence feeds you add, and email delivery if you configure a provider. The installer and updater contact the release channel and the container registry when you install or update. This website loads nothing from other sites and uses no analytics.</p>
            </details>
            <details><summary>Does it use machine learning?</summary><p>No. Detections come from Suricata signatures and correlation rules you can read.</p></details>
            <details><summary>Can it block my own computer or router?</summary><p>No. Your gateway, DNS servers and the SentinelCore machine are protected and cannot be blocked, and every block expires on its own.</p></details>
            <details><summary>Can I run it on Windows or WSL?</summary><p>No. It needs a real Linux network interface for capture; WSL cannot provide one.</p></details>
            <details><summary>Is it safe to point at my school or work network?</summary><p>Only with written permission. It scans and can block hosts, so use it on networks you own or are authorised to test.</p></details>
          </section>
        </div>
      </div>
    </>
  );
}
