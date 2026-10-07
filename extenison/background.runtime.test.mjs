import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./background.js", import.meta.url), "utf8");

function loadWorker(fetchImpl, {shortTimeouts = false} = {}) {
  const listeners = {};
  const storage = new Map();
  const updates = [];
  let activeUrl = "https://fast.com/";
  const chrome = {
    runtime: {
      getURL: path => `chrome-extension://vigil/${path}`,
      onMessage: {addListener: listener => {listeners.message = listener;}}
    },
    webNavigation: {onBeforeNavigate: {addListener: listener => {listeners.navigation = listener;}}},
    tabs: {
      query: async () => [{id: 7, url: activeUrl}],
      update: async (tabId, update) => {
        updates.push({tabId, ...update});
        if (update.url) activeUrl = update.url;
      },
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
  const context = {
    chrome,
    fetch: fetchImpl,
    AbortController,
    URL,
    setTimeout: shortTimeouts ? (callback, _delay) => setTimeout(callback, 10) : setTimeout,
    clearTimeout,
    crypto: {randomUUID: () => "test-token"},
    console
  };
  vm.runInNewContext(source, context);
  return {
    message: listeners.message,
    navigate: details => listeners.navigation(details),
    setActiveUrl: url => {activeUrl = url;},
    updates
  };
}

function send(listener, message, sender = {}) {
  return new Promise((resolve, reject) => {
    try { listener(message, sender, resolve); } catch (error) { reject(error); }
  });
}

const waitForWorker = () => new Promise(resolve => setTimeout(resolve, 20));

test("worker reports backend connectivity separately from scan state", async () => {
  const worker = loadWorker(async url => new Response(JSON.stringify(url.endsWith("/health")
    ? {status: "ok", model_loaded: true, model_version: "v2.1.0"}
    : {label: "SAFE", risk_score: 0, probability: 0.06, evidence: [], features: {}, model_version: "v2.1.0"}), {status: 200}));
  const health = await send(worker.message, {type: "HEALTH_CHECK"});
  assert.equal(health.state, "CONNECTED");
  assert.equal(health.model_version, "v2.1.0");
  const result = await send(worker.message, {type: "SCAN_CURRENT_TAB"});
  assert.equal(result.state, "RESULT");
  assert.equal(result.result.label, "SAFE");
});

test("worker reports backend offline without inventing a verdict", async () => {
  const worker = loadWorker(async () => { throw new Error("connection refused"); });
  const health = await send(worker.message, {type: "HEALTH_CHECK"});
  assert.equal(health.state, "BACKEND_OFFLINE");
  const result = await send(worker.message, {type: "SCAN_CURRENT_TAB"});
  assert.equal(result.state, "OFFLINE");
});

test("same tab and URL share one active scan request", async () => {
  let scanCalls = 0;
  let release;
  const pending = new Promise(resolve => {release = resolve;});
  const worker = loadWorker(async url => {
    if (url.endsWith("/health")) return new Response(JSON.stringify({status: "ok", model_loaded: true}), {status: 200});
    scanCalls += 1;
    await pending;
    return new Response(JSON.stringify({label: "SAFE", risk_score: 0, probability: 0.06, evidence: [], features: {}}), {status: 200});
  });
  const first = send(worker.message, {type: "SCAN_CURRENT_TAB"});
  const second = send(worker.message, {type: "SCAN_CURRENT_TAB"});
  release();
  await Promise.all([first, second]);
  assert.equal(scanCalls, 1);
});

test("SAFE and SUSPICIOUS verdicts allow top-level navigation", async t => {
  for (const label of ["SAFE", "SUSPICIOUS"]) {
    await t.test(label, async () => {
      const worker = loadWorker(async () => new Response(JSON.stringify({
        label, risk_score: 8, probability: 0.17, evidence: [], features: {}
      }), {status: 200}));
      await worker.navigate({tabId: 7, frameId: 0, url: "https://ordinary.example/"});
      await waitForWorker();
      assert.deepEqual(worker.updates, []);
    });
  }
});

test("only an explicit PHISHING verdict redirects to the blocked page", async () => {
  const worker = loadWorker(async () => new Response(JSON.stringify({
    label: "PHISHING", risk_score: 100, probability: 0.99, evidence: [], features: {}
  }), {status: 200}));
  await worker.navigate({tabId: 7, frameId: 0, url: "http://secure-login-paypal-account.xyz/"});
  await waitForWorker();
  assert.equal(worker.updates.length, 1);
  assert.match(worker.updates[0].url, /^chrome-extension:\/\/vigil\/blocked\.html\?token=/);
});

test("blocked-page bypass remains one-time and does not re-scan its redirect", async () => {
  let scanCalls = 0;
  const worker = loadWorker(async () => {
    scanCalls += 1;
    return new Response(JSON.stringify({label: "PHISHING", risk_score: 100, probability: 0.99, evidence: [], features: {}}), {status: 200});
  });
  const url = "http://secure-login-paypal-account.xyz/";
  await worker.navigate({tabId: 7, frameId: 0, url});
  await waitForWorker();
  const blocked = await send(worker.message, {type: "GET_BLOCKED_STATE", token: "test-token"});
  assert.equal(blocked.url, url);

  await send(worker.message, {type: "BYPASS_ONCE", token: "test-token"}, {tab: {id: 7}});
  await waitForWorker();
  await worker.navigate({tabId: 7, frameId: 0, url});
  await waitForWorker();
  assert.equal(scanCalls, 1);
  assert.equal(worker.updates.length, 2);
  assert.equal(worker.updates[1].url, url);
});

test("backend errors, malformed verdicts, and timeout all fail open", async t => {
  const cases = [
    ["backend offline", async () => { throw new Error("connection refused"); }],
    ["scan error", async () => new Response(JSON.stringify({error: "internal_error"}), {status: 500})],
    ["malformed response", async () => new Response("not JSON", {status: 200})],
    ["unknown verdict", async () => new Response(JSON.stringify({label: "UNKNOWN"}), {status: 200})],
    ["missing verdict", async () => new Response(JSON.stringify({probability: 0.99}), {status: 200})],
    ["timeout", (url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new Error("request timed out")));
    })],
    ["response body timeout", (_url, options) => Promise.resolve({
      ok: true,
      json: () => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new Error("response body timed out")));
      })
    })]
  ];
  for (const [name, fetchImpl] of cases) {
    await t.test(name, async () => {
      const worker = loadWorker(fetchImpl, {shortTimeouts: name.includes("timeout")});
      await worker.navigate({tabId: 7, frameId: 0, url: "https://ordinary.example/"});
      await waitForWorker();
      assert.deepEqual(worker.updates, []);
    });
  }
});

test("cache entries are isolated by tab and normalized URL", async () => {
  const scannedUrls = [];
  const worker = loadWorker(async (_url, options) => {
    const {url} = JSON.parse(options.body);
    scannedUrls.push(url);
    const label = url.includes("evil.example") ? "PHISHING" : "SAFE";
    return new Response(JSON.stringify({label, probability: 0.99, risk_score: 100, evidence: [], features: {}}), {status: 200});
  });
  worker.setActiveUrl("https://evil.example/");
  const malicious = await send(worker.message, {type: "SCAN_CURRENT_TAB"});
  assert.equal(malicious.result.label, "PHISHING");
  worker.setActiveUrl("https://google.com/");
  const legitimate = await send(worker.message, {type: "SCAN_CURRENT_TAB"});
  assert.equal(legitimate.result.label, "SAFE");
  assert.equal(scannedUrls.length, 2);
  assert.equal(new Set(scannedUrls).size, 2);
});

test("a late PHISHING response cannot block a newer navigation in the same tab", async () => {
  let releasePhishing;
  const phishingResponse = new Promise(resolve => {releasePhishing = resolve;});
  const worker = loadWorker(async (_url, options) => {
    const {url} = JSON.parse(options.body);
    if (url.includes("secure-login-paypal")) {
      await phishingResponse;
      return new Response(JSON.stringify({label: "PHISHING", risk_score: 100, probability: 0.99, evidence: [], features: {}}), {status: 200});
    }
    return new Response(JSON.stringify({label: "SAFE", risk_score: 0, probability: 0.01, evidence: [], features: {}}), {status: 200});
  });
  const oldNavigation = worker.navigate({tabId: 7, frameId: 0, url: "http://secure-login-paypal-account.xyz/"});
  await worker.navigate({tabId: 7, frameId: 0, url: "https://google.com/"});
  releasePhishing();
  await oldNavigation;
  await waitForWorker();
  assert.deepEqual(worker.updates, []);
});
