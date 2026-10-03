import { Link } from "react-router-dom";
import { PageHead } from "../components/ui.jsx";

const ITEMS = [
  {
    title: "Privilege separation",
    text: "The API and the pipeline run as an ordinary user with every Linux capability dropped. Only the privileged helper holds the few capabilities needed for scanning, Suricata control and firewall rules, and it is reachable only through a Unix socket that other users on the machine cannot open. It never runs in full privileged mode.",
  },
  {
    title: "Blocks that always expire",
    text: "Every firewall block has a time limit, from one minute to twenty-four hours. Nothing can be blocked forever, and a background check keeps the kernel's rules in step with what the database says should exist.",
  },
  {
    title: "Protected addresses",
    text: "Your gateway, your DNS servers and the SentinelCore machine itself cannot be blocked. The check lives in the privileged helper, so it holds even if something upstream asks for it. The setup wizard will not accept an empty protected list.",
  },
  {
    title: "Append-only audit log",
    text: "Every change is recorded. The database refuses to update or delete audit rows, even for the table owner, and a hash chain makes tampering visible.",
  },
  {
    title: "Role-based access",
    text: "Viewer, analyst and admin. Sensitive pages and actions are limited to the roles that need them, and the same table drives both the menu and the route checks so they cannot drift apart.",
  },
  {
    title: "Strong sign-in",
    text: "Passwords are hashed with Argon2. Access tokens last fifteen minutes and refresh tokens seven days, and repeated failed attempts are throttled.",
  },
  {
    title: "Untrusted captures are isolated",
    text: "Packet captures can be hostile, so they are parsed by a separate unprivileged process with time and memory limits, never inside the privileged helper.",
  },
  {
    title: "Everything runs locally",
    text: "Your traffic, events and settings stay on your machine. Outbound connections happen only for things you turn on: Suricata rule sources, threat-intelligence feeds you add, and email delivery if you configure it.",
  },
];

export default function Security() {
  return (
    <>
      <PageHead title="Security" label="Design">
        A tool that can scan networks and block hosts has to be careful about its own power. These are the limits built
        into it.
      </PageHead>
      <div className="container">
        <h2 className="sr-only">Security controls</h2>
        <div className="grid grid--2">
          {ITEMS.map((i) => (
            <article key={i.title} className="glass card">
              <h3>{i.title}</h3>
              <p className="muted">{i.text}</p>
            </article>
          ))}
        </div>

        <aside className="glass callout callout--warn" style={{ marginTop: 32 }}>
          <h4>Use it only where you are allowed to</h4>
          <p>
            SentinelCore actively scans and can block hosts. Run discovery and containment only against networks and
            machines you own or have written permission to test. Never point it at school, employer or third-party
            infrastructure.
          </p>
        </aside>

        <p style={{ marginTop: 24 }}>
          Looking for the release side of security (signatures and checksums)? See{" "}
          <Link to="/docs#verify">verifying a download</Link>.
        </p>
      </div>
    </>
  );
}
