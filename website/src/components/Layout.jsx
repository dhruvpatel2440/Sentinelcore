import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";

const NAV = [
  { to: "/", label: "Home", end: true },
  { to: "/features", label: "Features" },
  { to: "/modules", label: "Modules" },
  { to: "/how-it-works", label: "How it works" },
  { to: "/security", label: "Security" },
  { to: "/roles", label: "Roles" },
  { to: "/docs", label: "Docs" },
  { to: "/about", label: "About" },
];

const Icon = {
  sun: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  ),
  moon: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
    </svg>
  ),
  menu: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" aria-hidden="true">
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  ),
  close: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" aria-hidden="true">
      <path d="M6 6l12 12M18 6 6 18" />
    </svg>
  ),
};

function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function ThemeToggle() {
  const [theme, setTheme] = useState(currentTheme);
  const next = theme === "dark" ? "light" : "dark";
  const toggle = () => {
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("sc-theme", next);
    } catch {
      /* storage can be blocked; the theme still changes for this visit */
    }
    setTheme(next);
  };
  return (
    <button type="button" className="icon-btn" onClick={toggle} aria-label={`Switch to ${next} theme`}>
      {theme === "dark" ? Icon.sun : Icon.moon}
    </button>
  );
}

function Header() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);

  return (
    <header className="site-header">
      <div className="container">
        <Link to="/" className="brand" aria-label="SentinelCore home">
          <span className="brand__mark" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0b0b14" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3 20 6v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z" />
              <path d="m8.5 12 2.5 2.5 4.5-5" />
            </svg>
          </span>
          SentinelCore
        </Link>
        <nav className="site-nav" aria-label="Main">
          <ul>
            {NAV.slice(1).map((item) => (
              <li key={item.to}>
                <NavLink className="nav-link" to={item.to} end={item.end}>
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
          <Link className="btn" to="/download" style={{ minHeight: 40, padding: "8px 18px", fontSize: 14, marginLeft: 8 }}>
            Download
          </Link>
          <ThemeToggle />
          <button
            type="button"
            className="icon-btn menu-toggle"
            aria-expanded={open}
            aria-controls="mobile-nav"
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpen((o) => !o)}
          >
            {open ? Icon.close : Icon.menu}
          </button>
        </nav>
      </div>
      {open && (
        <nav id="mobile-nav" className="mobile-nav" aria-label="Mobile">
          <ul>
            {NAV.map((item) => (
              <li key={item.to}>
                <NavLink to={item.to} end={item.end}>
                  {item.label}
                </NavLink>
              </li>
            ))}
            <li>
              <NavLink to="/download">Download</NavLink>
            </li>
          </ul>
        </nav>
      )}
    </header>
  );
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="container">
        <div className="footer-grid">
          <div>
            <p className="brand" style={{ fontSize: 20 }}>
              SentinelCore
            </p>
            <p className="muted" style={{ maxWidth: "40ch" }}>
              Network detection and incident response that you install and run on your own Linux machine.
            </p>
          </div>
          <div>
            <p className="label">Product</p>
            <ul>
              <li><Link to="/features">Features</Link></li>
              <li><Link to="/modules">Modules and tools</Link></li>
              <li><Link to="/how-it-works">How it works</Link></li>
              <li><Link to="/security">Security</Link></li>
            </ul>
          </div>
          <div>
            <p className="label">Get started</p>
            <ul>
              <li><Link to="/download">Download</Link></li>
              <li><Link to="/docs">Docs</Link></li>
              <li><Link to="/roles">Roles</Link></li>
            </ul>
          </div>
          <div>
            <p className="label">Project</p>
            <ul>
              <li><Link to="/about">About and licence</Link></li>
            </ul>
          </div>
        </div>
        <p className="footer-note">
          Use SentinelCore only on networks you own or have written permission to monitor. All rights reserved.
          This website loads nothing from other sites and uses no analytics.
        </p>
      </div>
    </footer>
  );
}

export default function Layout() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <Header />
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <Footer />
    </>
  );
}
