import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./background.js", import.meta.url), "utf8");

function loadWorker(fetchImpl) {
  const listeners = {};
  const storage = new Map();
  const chrome = {
    runtime: {
      getURL: path => `chrome-extension://vigil/${path}`,
      onMessage: {addListener: listener => {listeners.message = listener;}}
    },
    webNavigation: {onBeforeNavigate: {addListener: listener => {listeners.navigation = listener;}}},
    tabs: {
      query: async () => [{id: 7, url: "https://fast.com/"}],
      update: async () => undefined,
      goBack: async () => undefined,
      onUpdated: {addListener: listener => {listeners.updated = listener;}},
      onRemoved: {addListener: listener => {listeners.removed = listener;}}
    },
    action: {setBadgeText: () => undefined, setBadgeBackgroundColor: () => undefined},
    storage: {session: {
      set: async value => {for (const [key, item] of Object.entries(value)) storage.set(key, item);},
      get: async key => ({[key]: storage.get(key)}),
      remove: async key => storage.delete(key)
    }}
  };
  const context = {chrome, fetch: fetchImpl, AbortController, setTimeout, clearTimeout, crypto: {randomUUID: () => "test-token"}, console};
  vm.runInNewContext(source, context);
  return listeners.message;
}

function send(listener, message) {
  return new Promise((resolve, reject) => {
    try { listener(message, {}, resolve); } catch (error) { reject(error); }
  });
}

test("worker reports backend connectivity separately from scan state", async () => {
  const listener = loadWorker(async url => new Response(JSON.stringify(url.endsWith("/health")
    ? {status: "ok", model_loaded: true, model_version: "v2.1.0"}
    : {label: "SAFE", risk_score: 0, probability: 0.06, evidence: [], features: {}, model_version: "v2.1.0"}), {status: 200}));
  const health = await send(listener, {type: "HEALTH_CHECK"});
  assert.equal(health.state, "CONNECTED");
  assert.equal(health.model_version, "v2.1.0");
  const result = await send(listener, {type: "SCAN_CURRENT_TAB"});
  assert.equal(result.state, "RESULT");
  assert.equal(result.result.label, "SAFE");
});

test("worker reports backend offline without inventing a verdict", async () => {
  const listener = loadWorker(async () => { throw new Error("connection refused"); });
  const health = await send(listener, {type: "HEALTH_CHECK"});
  assert.equal(health.state, "BACKEND_OFFLINE");
  const result = await send(listener, {type: "SCAN_CURRENT_TAB"});
  assert.equal(result.state, "OFFLINE");
});

test("same tab and URL share one active scan request", async () => {
  let scanCalls = 0;
  let release;
  const pending = new Promise(resolve => {release = resolve;});
  const listener = loadWorker(async url => {
    if (url.endsWith("/health")) return new Response(JSON.stringify({status: "ok", model_loaded: true}), {status: 200});
    scanCalls += 1;
    await pending;
    return new Response(JSON.stringify({label: "SAFE", risk_score: 0, probability: 0.06, evidence: [], features: {}}), {status: 200});
  });
  const first = send(listener, {type: "SCAN_CURRENT_TAB"});
  const second = send(listener, {type: "SCAN_CURRENT_TAB"});
  release();
  await Promise.all([first, second]);
  assert.equal(scanCalls, 1);
});
