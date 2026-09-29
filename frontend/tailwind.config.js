/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // One severity scale for the whole platform. M5 normalizes Suricata's
        // 1-4 priority onto these names; M7 scoring and M9 reports reuse them.
        // Changing a colour here changes it everywhere — that is the point.
        severity: {
          critical: "#f43f5e", // rose-500
          high: "#fb923c", // orange-400
          medium: "#facc15", // yellow-400
          low: "#38bdf8", // sky-400
          info: "#94a3b8", // slate-400
        },
        // Semantic surfaces so pages never hardcode a slate shade.
        surface: {
          DEFAULT: "#0f172a", // slate-900 — page background
          raised: "#1e293b", // slate-800 — cards, sidebar
          overlay: "#334155", // slate-700 — modals, hover
          border: "#1e293b",
        },
      },
      spacing: {
        sidebar: "16rem",
        "sidebar-collapsed": "4.5rem",
        topbar: "3.5rem",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 120ms ease-out",
        "slide-up": "slide-up 160ms ease-out",
      },
    },
  },
  plugins: [],
};
