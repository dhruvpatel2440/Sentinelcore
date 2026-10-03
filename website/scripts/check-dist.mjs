// Post-build checks: no external requests, no sourcemaps, page weight budget.
// Run: npm run build && npm run check
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist", import.meta.url));
const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    statSync(p).isDirectory() ? walk(p) : files.push(p);
  }
})(dist);

let bad = 0;
const fail = (msg) => { console.error("FAIL", msg); bad++; };

// 1. Nothing loaded from another origin: no http(s) src/href/@import/url() in HTML/CSS,
//    and no fetch/XHR/WebSocket/beacon target in JS other than the site's own paths.
for (const f of files.filter((f) => [".html", ".css"].includes(extname(f)))) {
  const text = readFileSync(f, "utf8");
  const re = /(?:src|href)=["']https?:\/\/[^"']+["']|url\(\s*["']?https?:\/\/|@import\s+["']?https?:/gi;
  for (const m of text.matchAll(re)) fail(`${f}: external reference ${m[0]}`);
}
for (const f of files.filter((f) => extname(f) === ".js")) {
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(/(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource)\b[^;]{0,80}https?:\/\/[^"'`\s)]+/g)) {
    fail(`${f}: possible external request: ${m[0].slice(0, 120)}`);
  }
}

// 2. No sourcemaps.
for (const f of files) if (f.endsWith(".map")) fail(`sourcemap shipped: ${f}`);

// 3. Page weight excluding screenshots (HTML + CSS + JS + fonts that a first visit loads).
const weight = files
  .filter((f) => !/screens[\/]/.test(f) && !/\.(png|jpe?g|webp)$/i.test(f))
  .filter((f) => !/\.woff$/.test(f)) // browsers that support woff2 never fetch the woff fallback
  .reduce((n, f) => n + statSync(f).size, 0);
console.log(`transfer-relevant weight (uncompressed, woff2 only): ${(weight / 1024).toFixed(0)} KB`);
if (weight > 1024 * 1024) fail("over the 1 MB budget");

console.log(bad ? `${bad} problem(s)` : "dist checks passed");
process.exit(bad ? 1 : 0);
