import test from "node:test";
import assert from "node:assert/strict";
import { validate } from "./check-releases.mjs";

const sha = "a".repeat(64);
const dl = (id) => ({ id, file: `${id}.bin`, url: `https://example.com/${id}.bin`, sha256: sha });
const good = {
  status: "available",
  version: "1.0.0",
  released: "2026-01-01",
  signingKey: { fingerprint: "A".repeat(40), url: "https://example.com/key.asc" },
  downloads: [dl("package"), dl("deb")],
};

test("a complete available release passes", () => assert.deepEqual(validate(good), []));

test("coming-soon with no urls passes", () => {
  const d = { status: "coming-soon", downloads: [{ id: "x", url: null, sha256: null }] };
  assert.deepEqual(validate(d), []);
});

test("available with a null url, sha or fingerprint fails", () => {
  assert.ok(validate({ ...good, downloads: [{ ...dl("a"), url: null }] }).length);
  assert.ok(validate({ ...good, downloads: [{ ...dl("a"), sha256: null }] }).length);
  assert.ok(validate({ ...good, signingKey: { fingerprint: null, url: "https://x" } }).length);
});

test("coming-soon must not carry a download link", () => {
  assert.ok(validate({ status: "coming-soon", downloads: [dl("a")] }).length);
});

test("placeholder or preview text is rejected", () => {
  assert.ok(validate({ ...good, downloads: [{ ...dl("a"), file: "pkg-<version>.tar.gz" }] }).length);
  assert.ok(validate({ ...good, downloads: [{ ...dl("a"), url: "https://example.com/x-preview.tar.gz" }] }).length);
});
