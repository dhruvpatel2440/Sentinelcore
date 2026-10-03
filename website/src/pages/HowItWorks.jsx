import ArchitectureDiagram from "../components/ArchitectureDiagram.jsx";
import { PageHead } from "../components/ui.jsx";

export default function HowItWorks() {
  return (
    <>
      <PageHead title="How it works" label="Architecture">
        Two flows share one machine: requests from your browser, and events flowing from the network up to incidents.
      </PageHead>
      <div className="container">
        <h2 className="sr-only">Architecture diagram</h2>
        <ArchitectureDiagram />

        <div className="grid grid--2" style={{ marginTop: 32 }}>
          <section className="glass card">
            <h3>Your requests</h3>
            <p>
              Your browser talks HTTPS to nginx. nginx serves the dashboard and forwards <code className="inline">/api</code>{" "}
              to the API. The API reads and writes PostgreSQL and Redis. When an action needs raw-network power, such as
              a scan, starting Suricata or changing the firewall, the API asks the privileged helper over a Unix socket.
            </p>
          </section>
          <section className="glass card">
            <h3>Your events</h3>
            <p>
              Suricata writes what it sees to a log file. The event pipeline reads it, normalises each record and stores
              it. The correlation engine applies your rules to the stored events and produces incident candidates, which
              become the incidents in your queue.
            </p>
          </section>
        </div>
      </div>
    </>
  );
}
