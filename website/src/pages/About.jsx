import { Link } from "react-router-dom";
import { PageHead } from "../components/ui.jsx";

/* Mentors and institution are not recorded in the repository (README: "Team, mentors, licence").
   Fill the two constants below; the page hides a block that is still empty. */
const MENTORS = [];
const INSTITUTION = "";

export default function About() {
  return (
    <>
      <PageHead title="About" label="The project">
        SentinelCore is a student-built network detection and incident response platform.
      </PageHead>
      <div className="container">
        <h2 className="sr-only">Project details</h2>
        <div className="grid grid--2">
          <section className="glass card">
            <h3>Team</h3>
            <ul>
              <li><strong>Dhruv Patel</strong></li>
              <li><strong>Nisarg Dedakiya</strong></li>
            </ul>
          </section>
          {INSTITUTION && (
            <section className="glass card">
              <h3>Institution</h3>
              <p>{INSTITUTION}</p>
            </section>
          )}
          {MENTORS.length > 0 && (
            <section className="glass card">
              <h3>Mentors</h3>
              <ul>
                {MENTORS.map((m) => (
                  <li key={m}>{m}</li>
                ))}
              </ul>
            </section>
          )}
          <section className="glass card">
            <h3>Licence</h3>
            <p>
              All rights reserved. The source code is private. Binary releases are licensed under the End User Licence
              Agreement shown during installation: use it on networks you own or are authorised to monitor.
            </p>
          </section>
        </div>
        <p style={{ marginTop: 24 }}>
          Ready to try it? <Link to="/download">Go to the download page</Link>.
        </p>
      </div>
    </>
  );
}
