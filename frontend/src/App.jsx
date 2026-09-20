import { Route, Routes } from "react-router-dom";

import Layout from "./layout/Layout";
import AssetsPage from "./pages/assets/AssetsPage";
import LoginPage from "./pages/LoginPage";
import SensorPage from "./pages/sensor/SensorPage";
import NotFoundPage from "./pages/NotFoundPage";
import Placeholder from "./pages/Placeholder";
import ProtectedRoute from "./routes/ProtectedRoute";

/**
 * Route table. Role requirements mirror `layout/navigation.js` — an item
 * hidden from the sidebar is also blocked here, because hidden nav is not
 * authorization. The backend remains the real enforcement point.
 */
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route
            index
            element={
              <Placeholder
                title="Overview"
                description="Platform-wide detection and response posture."
                milestone="M2+"
                capabilities={[
                  "Live event volume and severity breakdown",
                  "Open incidents and sensor health at a glance",
                ]}
              />
            }
          />

          <Route path="assets" element={<AssetsPage />} />

          <Route
            path="events"
            element={
              <Placeholder
                title="Events"
                description="Normalized detections from the Suricata sensor."
                milestone="M5 + M6"
                capabilities={["EVE JSON ingest pipeline", "Full-text and field search"]}
              />
            }
          />

          <Route
            path="incidents"
            element={
              <Placeholder
                title="Incidents"
                description="Triage queue for correlated activity."
                milestone="M8"
                capabilities={["Correlated event grouping", "Assignment and resolution workflow"]}
              />
            }
          />

          <Route
            path="intel"
            element={
              <Placeholder
                title="Threat Intel"
                description="Indicators of compromise and enrichment feeds."
                milestone="M12"
                capabilities={["IOC matching against live events", "Feed management"]}
              />
            }
          />

          <Route
            path="pcap"
            element={
              <Placeholder
                title="PCAP"
                description="Packet capture retrieval and analysis."
                milestone="M11"
                capabilities={["Flow-scoped capture extraction", "Stream reassembly"]}
              />
            }
          />

          <Route
            path="reports"
            element={
              <Placeholder
                title="Reports"
                description="Scheduled and ad-hoc reporting."
                milestone="M9"
                capabilities={["Incident and detection summaries", "Export to PDF/CSV"]}
              />
            }
          />

          {/* Admin-only — mirrored in navigation.js */}
          <Route
            path="sensor"
            element={
              <ProtectedRoute roles={["admin"]}>
                <SensorPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="firewall"
            element={
              <ProtectedRoute roles={["admin"]}>
                <Placeholder
                  title="Firewall"
                  description="Containment actions against hostile hosts."
                  milestone="M10"
                  capabilities={["TTL-bounded block rules", "Protected-IP safeguards"]}
                />
              </ProtectedRoute>
            }
          />

          <Route
            path="admin/users"
            element={
              <ProtectedRoute roles={["admin"]}>
                <Placeholder
                  title="Users"
                  description="Accounts, roles and access review."
                  milestone="M1"
                  capabilities={["Create and deactivate accounts", "Role assignment"]}
                />
              </ProtectedRoute>
            }
          />
        </Route>
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
