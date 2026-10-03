import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const read = name => fs.readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
const manifest = JSON.parse(read("manifest.json"));

test("manifest keeps permissions scoped to extension behavior", () => {
  assert.deepEqual(manifest.permissions.sort(), ["storage", "tabs", "webNavigation"]);
  assert.ok(manifest.host_permissions.includes("http://127.0.0.1:5000/*"));
  assert.equal(manifest.background.service_worker, "background.js");
});

test("all extension scripts are external and use the backend as source of truth", () => {
  const popup = read("popup.js");
  const background = read("background.js");
  assert.match(background, /\/scan/);
  assert.doesNotMatch(background, /PHISHING_THRESHOLD|SAFE_THRESHOLD|predict_proba|innerHTML/);
  assert.doesNotMatch(popup, /innerHTML|insertAdjacentHTML|eval\(/);
  assert.match(popup, /textContent/);
});

test("blocked UX has explicit back and deliberate one-time bypass actions", () => {
  const html = read("blocked.html");
  const script = read("blocked.js");
  assert.match(html, /Go back to safety/);
  assert.match(html, /Proceed anyway/);
  assert.match(script, /BYPASS_ONCE/);
  assert.match(script, /GO_BACK/);
  assert.match(script, /textContent/);
});

test("extension surfaces include reduced-motion and responsive rules", () => {
  assert.match(read("popup.css"), /prefers-reduced-motion/);
  assert.match(read("blocked.css"), /prefers-reduced-motion/);
  assert.match(read("blocked.css"), /@media\(max-width:560px\)/);
});
