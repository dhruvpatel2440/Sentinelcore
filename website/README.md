# SentinelCore website

A static product website: Vite + React, built to `dist/`. It is separate from the
app (`frontend/`, `backend/`, `helper/` are untouched) and never exposes source
code. No CDN, no external scripts, no analytics: every font is self-hosted.

## Develop and build

```bash
cd website
npm install
npm run dev        # http://localhost:5173
npm run build      # static site in website/dist/
npm run check      # fails on external requests, sourcemaps, or > 1 MB weight
python scripts/contrast.py   # WCAG contrast audit of the colour tokens
```

## Where things live

| To change | Edit |
|---|---|
| Colours, radii, spacing, type, outlines, shadows, glass | `src/styles/tokens.css` (the only place these values exist) |
| Modules and tools (one card each) | `src/data/modules.js` |
| Feature sections, proof points, how-it-works strip | `src/data/features.js` |
| Download buttons, checksums, signing key, "coming soon" state | `src/data/releases.json` |
| Supported distributions table | `../docs/supported-platforms.md` (parsed at build time) |
| Mentors / institution on the About page | the two constants at the top of `src/pages/About.jsx` |

## Publishing a release on the Download page

Until a real signed release exists, `releases.json` has `"status": "coming-soon"`
and every URL is `null`; the page shows **Installer coming soon** and no dead links.
After a release, set `status` to `"available"`, `version`, `released`, and for each
download its `url`, `sha256` (from `SHA256SUMS`) and, for the installer, the `command`.
Add the signing key `fingerprint`. Rebuild and deploy.

## Screenshots

`BrowserFrame` / `Screenshot` (in `src/components/ui.jsx`) show a real screenshot if a
file named after the slot exists in `src/assets/screens/` (`.png`, `.webp`, `.jpg`),
otherwise a labelled illustration with sample data. Capture panels from the running
app as it is today (single-panel crops look best against this style). The hero uses
an illustrated incident queue labelled "Sample data" because no validation results
exist yet; do not replace its figures with real numbers until they are measured.

## Hosting `dist/` from the private repo

The site contains no source, so it can be public even though the repo is private.

**Cloudflare Pages**

1. Dashboard -> Workers & Pages -> Create -> Pages -> Connect to Git -> pick the private repo.
2. Framework preset: none. **Root directory:** `website`. **Build command:** `npm ci && npm run build`. **Output directory:** `dist`.
3. Environment variable `NODE_VERSION` = `20`.
4. `public/_redirects` already makes client-side routes (`/download`, `/docs`, ...) work on refresh.

**Netlify**

1. Add new site -> Import from Git -> pick the repo.
2. **Base directory:** `website`. **Build command:** `npm ci && npm run build`. **Publish directory:** `website/dist`.
3. `public/_redirects` is honoured as-is.

The Download page parses `../docs/supported-platforms.md` at build time, so the
build must have the whole repository checked out (both hosts do this by default).

No CI changes are required and none were made to existing workflows.

## Checks that guard the Download page

- `npm run build` first runs `scripts/check-releases.mjs` (npm `prebuild`). If `status` is
  `available` but any URL, SHA-256, version or signing-key fingerprint is empty, or any file name
  still contains `<version>`, `preview` or `OWNER`, the build fails. If `status` is `coming-soon` and
  any link is present, the build also fails. `npm test` covers these rules.
- After a release, the release workflow runs `scripts/release/update_website_releases.py` and opens a
  pull request that fills `releases.json` from the signed `latest.json` and `SHA256SUMS`. Review and merge it;
  your host (Cloudflare Pages or Netlify) then redeploys.
- `.github/workflows/website-ci.yml` runs install, tests, build, the dist checks and the contrast audit on
  every change under `website/`.
