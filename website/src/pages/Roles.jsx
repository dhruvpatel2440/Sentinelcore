import { PageHead } from "../components/ui.jsx";

const Y = <span className="yes"><span className="sr-only">Yes</span></span>;
const N = <span className="no" aria-label="No">-</span>;

const ROWS = [
  ["Browse events, incidents, assets, reports and indicators", true, true, true],
  ["Search and filter events", true, true, true],
  ["Triage and resolve incidents", false, true, true],
  ["Run asset discovery scans", false, true, true],
  ["Upload and analyse packet captures", false, true, true],
  ["Manage threat-intelligence indicators and run hunts", false, true, true],
  ["Generate reports", false, true, true],
  ["Start, stop and tune the Suricata sensor and its rules", false, false, true],
  ["Block and unblock addresses on the firewall", false, false, true],
  ["Configure threat-intelligence feeds and report schedules", false, false, true],
  ["Manage users and email settings", false, false, true],
];

export default function Roles() {
  return (
    <>
      <PageHead title="Roles" label="Access control">
        Three roles, from read-only to full control. The menu hides what a role cannot use, and the server enforces the
        same rules.
      </PageHead>
      <div className="container">
        <div className="table-wrap">
          <table>
            <caption className="sr-only">What each role can do</caption>
            <thead>
              <tr>
                <th scope="col">Capability</th>
                <th scope="col">Viewer</th>
                <th scope="col">Analyst</th>
                <th scope="col">Admin</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(([what, v, a, ad]) => (
                <tr key={what}>
                  <th scope="row" style={{ textTransform: "none", letterSpacing: 0, fontSize: 14, background: "transparent", fontWeight: 600 }}>
                    {what}
                  </th>
                  <td>{v ? Y : N}</td>
                  <td>{a ? Y : N}</td>
                  <td>{ad ? Y : N}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted" style={{ marginTop: 16 }}>
          The first administrator is created during setup. Admins create the other accounts.
        </p>
      </div>
    </>
  );
}
