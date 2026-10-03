// Fails the website build when releases.json claims more than exists.
// Runs automatically before `npm run build` (package.json "prebuild").
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function validate(data) {
  const problems = [];
  const downloads = Array.isArray(data.downloads) ? data.downloads : [];
  if (!["available", "coming-soon"].includes(data.status)) problems.push(`status must be 'available' or 'coming-soon', got '${data.status}'`);

  if (data.status === "available") {
    if (!data.version) problems.push("status is 'available' but version is empty");
    if (!data.released) problems.push("status is 'available' but released is empty");
    if (!/^[0-9A-Fa-f]{40}$/.test(data.signingKey?.fingerprint ?? "")) problems.push("status is 'available' but signingKey.fingerprint is not a 40-hex fingerprint");
    if (!data.signingKey?.url) problems.push("status is 'available' but signingKey.url is empty");
    for (const d of downloads) {
      if (!/^https:\/\//.test(d.url ?? "")) problems.push(`${d.id}: url must be an https URL`);
      if (!/^[0-9a-f]{64}$/.test(d.sha256 ?? "")) problems.push(`${d.id}: sha256 must be 64 hex characters`);
      if (/<version>|preview|OWNER/i.test(`${d.file} ${d.url}`)) problems.push(`${d.id}: placeholder or preview text in file/url`);
    }
  } else {
    for (const d of downloads) {
      if (d.url || d.sha256) problems.push(`${d.id}: has a url/sha256 but status is 'coming-soon'`);
    }
  }
  if (downloads.length === 0) problems.push("no downloads listed");
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = fileURLToPath(new URL("../src/data/releases.json", import.meta.url));
  const problems = validate(JSON.parse(readFileSync(path, "utf8")));
  if (problems.length) {
    console.error("releases.json is inconsistent:\n - " + problems.join("\n - "));
    process.exit(1);
  }
  console.log("releases.json OK");
}
