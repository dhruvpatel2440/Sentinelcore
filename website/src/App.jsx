import { Link, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import { PageHead } from "./components/ui.jsx";
import About from "./pages/About.jsx";
import Docs from "./pages/Docs.jsx";
import Download from "./pages/Download.jsx";
import Features from "./pages/Features.jsx";
import Home from "./pages/Home.jsx";
import HowItWorks from "./pages/HowItWorks.jsx";
import Modules from "./pages/Modules.jsx";
import Roles from "./pages/Roles.jsx";
import Security from "./pages/Security.jsx";

function NotFound() {
  return (
    <>
      <PageHead title="Page not found">That page does not exist.</PageHead>
      <div className="container">
        <Link className="btn" to="/">
          Back to home
        </Link>
      </div>
    </>
  );
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="features" element={<Features />} />
        <Route path="modules" element={<Modules />} />
        <Route path="how-it-works" element={<HowItWorks />} />
        <Route path="security" element={<Security />} />
        <Route path="roles" element={<Roles />} />
        <Route path="download" element={<Download />} />
        <Route path="docs" element={<Docs />} />
        <Route path="about" element={<About />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
