import { Route, Routes } from "react-router-dom";

import Layout from "./layout/Layout";
import AssetsPage from "./pages/assets/AssetsPage";
import CorrelationPage from "./pages/correlation/CorrelationPage";
import EventsPage from "./pages/events/EventsPage";
import IncidentDetail from "./pages/incidents/IncidentDetail";
import IncidentsPage from "./pages/incidents/IncidentsPage";
import LoginPage from "./pages/LoginPage";
import SensorPage from "./pages/sensor/SensorPage";
import NotFoundPage from "./pages/NotFoundPage";
import Placeholder from "./pages/Placeholder";
import ReportsPage from "./pages/reports/ReportsPage";
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

          <Route path="events" element={<EventsPage />} />

          <Route path="correlation" element={<CorrelationPage />} />

          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:number" element={<IncidentDetail />} />

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

          <Route path="reports" element={<ReportsPage />} />

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
