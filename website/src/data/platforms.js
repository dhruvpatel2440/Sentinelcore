/*
 * Supported platforms, read from docs/supported-platforms.md at build time so
 * the website and the repository can never disagree. Only rows marked "tested"
 * are shown as tested; everything else is "expected to work, untested".
 */
import md from "../../../docs/supported-platforms.md?raw";

function clean(cell) {
  return cell
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/`(.+?)`/g, "$1")
    .replace(/\[(.+?)\]\(.+?\)/g, "$1")
    .trim();
}

export function parsePlatforms(text) {
  const rows = [];
  let inTable = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\|\s*Distribution\s*\|/i.test(line)) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    if (/^\|\s*-/.test(line)) continue;
    if (!line.startsWith("|")) break;
    const cells = line.split("|").slice(1, -1).map(clean);
    if (cells.length < 3) continue;
    const [distro, version, status, notes = ""] = cells;
    const s = status.toLowerCase();
    rows.push({
      distro,
      version,
      notes,
      status: s.startsWith("tested") ? "tested" : s.startsWith("not supported") ? "unsupported" : "untested",
    });
  }
  return rows;
}

export const PLATFORMS = parsePlatforms(md);
export const SUPPORTED = PLATFORMS.filter((p) => p.status !== "unsupported");
export const UNSUPPORTED = PLATFORMS.filter((p) => p.status === "unsupported");
