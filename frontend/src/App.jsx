import { Route, Routes } from "react-router-dom";

import Layout from "./layout/Layout";
import AssetsPage from "./pages/assets/AssetsPage";
import CorrelationPage from "./pages/correlation/CorrelationPage";
import EventsPage from "./pages/events/EventsPage";
import FirewallPage from "./pages/firewall/FirewallPage";
import IncidentDetail from "./pages/incidents/IncidentDetail";
import IncidentsPage from "./pages/incidents/IncidentsPage";
import LoginPage from "./pages/LoginPage";
import SensorPage from "./pages/sensor/SensorPage";
import NotFoundPage from "./pages/NotFoundPage";
import PcapDetail from "./pages/pcap/PcapDetail";
import PcapPage from "./pages/pcap/PcapPage";
import IntelPage from "./pages/intel/IntelPage";
import IocDetail from "./pages/intel/IocDetail";
import OverviewPage from "./pages/overview/OverviewPage";
import UsersPage from "./pages/admin/UsersPage";
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
          <Route index element={<OverviewPage />} />

          <Route path="assets" element={<AssetsPage />} />

          <Route path="events" element={<EventsPage />} />

          <Route path="correlation" element={<CorrelationPage />} />

          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:number" element={<IncidentDetail />} />

          <Route path="intel" element={<IntelPage />} />
          <Route path="intel/:id" element={<IocDetail />} />

          <Route path="pcap" element={<PcapPage />} />
          <Route path="pcap/:id" element={<PcapDetail />} />

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
                <FirewallPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="admin/users"
            element={
              <ProtectedRoute roles={["admin"]}>
                <UsersPage />
              </ProtectedRoute>
            }
          />
        </Route>
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
