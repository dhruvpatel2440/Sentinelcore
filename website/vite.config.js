import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Download page reads ../docs/supported-platforms.md at build time so the
// two can never drift; allow Vite to read one level above this folder.
export default defineConfig({
  plugins: [react()],
  server: { fs: { allow: [".."] } },
  build: { sourcemap: false, target: "es2020" },
});
