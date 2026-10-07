// VIGIL's service worker is the only extension-side coordinator. It delegates
// classification to the Flask API and never implements a second verdict rule.
const API_BASE = "http://127.0.0.1:5000";
const CACHE_TTL_MS = 30_000;
const scans = new Map();
const inFlight = new Map();
const bypasses = new Map();
const latestNavigations = new Map();

function debugUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}/`;
  } catch {
    return "unavailable";
  }
}

function logScan(url, result) {
  if (globalThis.VIGIL_DEBUG !== true) return;
  console.info(`[SCAN]\nURL: ${debugUrl(url)}\nVERDICT: ${result?.label || "ERROR"}\nPROBABILITY: ${result?.probability ?? "n/a"}\nRISK: ${result?.risk_score ?? "n/a"}`);
}

function logBlockDecision(url, verdict, action) {
  if (globalThis.VIGIL_DEBUG !== true) return;
  console.info(`[BLOCK DECISION]\nURL: ${debugUrl(url)}\nVERDICT: ${verdict}\nACTION: ${action}`);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {...options, signal: controller.signal});
    const data = await response.json().catch(() => null);
    return {response, data};
  }
  finally { clearTimeout(timeout); }
}

function isExtensionPage(url) {
  return typeof url === "string" && (url.startsWith(chrome.runtime.getURL("")) || url.startsWith("chrome-extension://"));
}

function isScannableUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url) && !isExtensionPage(url);
}

function cacheKey(tabId, url) {
  return `${tabId}:${new URL(url).href}`;
}

function badgeFor(label) {
  if (label === "PHISHING") return {text: "!", color: "#d96b6b"};
  if (label === "SUSPICIOUS") return {text: "?", color: "#d6a84f"};
  return {text: "", color: "#69c995"};
}

function setBadge(tabId, label, offline = false) {
  const badge = offline ? {text: "–", color: "#7e8b92"} : badgeFor(label);
  chrome.action.setBadgeText({tabId, text: badge.text});
  chrome.action.setBadgeBackgroundColor({tabId, color: badge.color});
}

async function scanUrl(tabId, url) {
  const normalizedUrl = new URL(url).href;
  const key = cacheKey(tabId, normalizedUrl);
  const cached = scans.get(key);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
    logScan(normalizedUrl, cached.result);
    return cached.result;
  }
  if (inFlight.has(key)) return inFlight.get(key);

  const request = fetchWithTimeout(`${API_BASE}/scan`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url: normalizedUrl})
  }).then(({response, data}) => {
    if (!response.ok) throw new Error(data?.message || "The VIGIL backend rejected the scan.");
    if (!data || !["SAFE", "SUSPICIOUS", "PHISHING"].includes(data.label)) throw new Error("The VIGIL backend returned an invalid result.");
    scans.set(key, {at: Date.now(), result: data});
    logScan(normalizedUrl, data);
    const navigation = latestNavigations.get(tabId);
    if (!navigation || navigation.url === normalizedUrl) setBadge(tabId, data.label);
    return data;
  }).catch(error => {
    logScan(normalizedUrl, null);
    const navigation = latestNavigations.get(tabId);
    if (!navigation || navigation.url === normalizedUrl) setBadge(tabId, null, true);
    throw error;
  }).finally(() => inFlight.delete(key));

  inFlight.set(key, request);
  return request;
}

async function saveBlockedState(tabId, url, result) {
  const token = crypto.randomUUID();
  await chrome.storage.session.set({[`blocked:${token}`]: {tabId, url, result, createdAt: Date.now()}});
  return token;
}

async function blockNavigation(details, navigation) {
  try {
    const result = await scanUrl(details.tabId, details.url);
    if (latestNavigations.get(details.tabId) !== navigation) {
      logBlockDecision(details.url, result.label, "ALLOW (navigation changed)");
      return;
    }
    if (result.label !== "PHISHING") {
      logBlockDecision(details.url, result.label, "ALLOW");
      return;
    }
    const token = await saveBlockedState(details.tabId, details.url, result);
    if (latestNavigations.get(details.tabId) !== navigation) {
      await chrome.storage.session.remove(`blocked:${token}`);
      logBlockDecision(details.url, result.label, "ALLOW (navigation changed)");
      return;
    }
    const blockedUrl = chrome.runtime.getURL(`blocked.html?token=${encodeURIComponent(token)}`);
    logBlockDecision(details.url, result.label, "BLOCK");
    await chrome.tabs.update(details.tabId, {url: blockedUrl});
  } catch {
    logBlockDecision(details.url, "ERROR", "ALLOW");
    // Fail open with an honest offline state. A failed request is not a phishing verdict.
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  const navigation = {url: isScannableUrl(details.url) ? new URL(details.url).href : null};
  latestNavigations.set(details.tabId, navigation);
  if (!isScannableUrl(details.url)) return;
  const bypassUrl = bypasses.get(details.tabId);
  if (bypassUrl === navigation.url) {
    bypasses.delete(details.tabId);
    return;
  }
  return blockNavigation(details, navigation);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !isScannableUrl(tab.url)) return;
  void scanUrl(tabId, tab.url).catch(() => undefined);
});

chrome.tabs.onRemoved.addListener(tabId => {
  for (const key of scans.keys()) if (key.startsWith(`${tabId}:`)) scans.delete(key);
  for (const key of inFlight.keys()) if (key.startsWith(`${tabId}:`)) inFlight.delete(key);
  bypasses.delete(tabId);
  latestNavigations.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "HEALTH_CHECK") {
    fetchWithTimeout(`${API_BASE}/health`).then(({response, data}) => {
      if (!response.ok || data?.status !== "ok" || data?.model_loaded !== true) return {state: "BACKEND_OFFLINE"};
      return {state: "CONNECTED", model_version: data.model_version || null};
    }).catch(() => ({state: "BACKEND_OFFLINE"})).then(sendResponse);
    return true;
  }

  if (message?.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({active: true, currentWindow: true}).then(async tabs => {
      const tab = tabs[0];
      if (tab?.url?.startsWith(chrome.runtime.getURL("blocked.html"))) {
        const token = new URL(tab.url).searchParams.get("token");
        const stored = token ? await chrome.storage.session.get(`blocked:${token}`) : {};
        const state = token ? stored[`blocked:${token}`] : null;
        if (state) return {state: "RESULT", blocked: true, url: state.url, result: state.result};
      }
      if (!tab?.url || !isScannableUrl(tab.url)) return {state: "UNSUPPORTED", url: tab?.url || ""};
      try { return {state: "RESULT", url: tab.url, result: await scanUrl(tab.id, tab.url)}; }
      catch (error) { return {state: "OFFLINE", url: tab.url, message: error.message}; }
    }).then(sendResponse);
    return true;
  }

  if (message?.type === "GET_BLOCKED_STATE") {
    chrome.storage.session.get(`blocked:${message.token}`).then(data => sendResponse(data[`blocked:${message.token}`] || null));
    return true;
  }

  if (message?.type === "GO_BACK" && sender.tab?.id !== undefined) {
    chrome.tabs.goBack(sender.tab.id).catch(() => chrome.tabs.update(sender.tab.id, {url: "about:blank"}));
    sendResponse({ok: true});
    return false;
  }

  if (message?.type === "BYPASS_ONCE" && sender.tab?.id !== undefined) {
    chrome.storage.session.get(`blocked:${message.token}`).then(async data => {
      const state = data[`blocked:${message.token}`];
      if (!state || state.tabId !== sender.tab.id) return;
      bypasses.set(sender.tab.id, new URL(state.url).href);
      await chrome.tabs.update(sender.tab.id, {url: state.url});
      await chrome.storage.session.remove(`blocked:${message.token}`);
    });
    sendResponse({ok: true});
    return false;
  }

});
