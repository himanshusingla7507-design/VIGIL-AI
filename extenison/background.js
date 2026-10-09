// VIGIL's service worker is the only extension-side coordinator. It delegates
// classification to the Flask API and never implements a second verdict rule.
const API_BASE = "http://127.0.0.1:5000";
const inFlight = new Map();
const bypasses = new Map();
const latestNavigations = new Map();

function isTabClosedError(error) {
  if (!error) return false;
  const msg = error?.message || String(error);
  return (
    msg.includes("No tab with id") ||
    msg.includes("Tabs cannot be queried") ||
    msg.includes("tab was closed") ||
    msg.includes("Invalid tab ID") ||
    msg.includes("The tab was closed")
  );
}

function logScan(url, result) {
  if (globalThis.VIGIL_DEBUG !== true) return;
  console.info("[SCAN]", JSON.stringify({
    normalized_url: url,
    hostname: new URL(url).hostname,
    api_endpoint: result?.backend?.api_endpoint || `${API_BASE}/scan`,
    request_id: result?.request_id || null,
    client_scan_id: result?.diagnostics?.client_scan_id || null,
    backend_pid: result?.backend?.backend_pid || null,
    backend_instance_id: result?.backend?.backend_instance_id || null,
    model_version: result?.model_version || null,
    model_fingerprint: result?.model_fingerprint || null,
    raw_fold_probabilities: result?.diagnostics?.raw_fold_probabilities || null,
    calibrated_probability: result?.model_probability ?? null,
    effective_probability: result?.effective_probability ?? null,
    thresholds: result?.thresholds || null,
    verdict: result?.label || "ERROR",
    risk_score: result?.risk_score ?? null,
    cache_hit: result?.diagnostics?.cache_hit ?? false
  }));
}

function logBlockDecision(url, verdict, action, result = null) {
  if (globalThis.VIGIL_DEBUG !== true) return;
  const normalizedUrl = new URL(url).href;
  console.info("[BLOCK DECISION]", JSON.stringify({
    normalized_url: normalizedUrl,
    hostname: new URL(normalizedUrl).hostname,
    verdict,
    action,
    request_id: result?.request_id || null,
    model_fingerprint: result?.model_fingerprint || null
  }));
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

function isValidScanResult(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (!["SAFE", "SUSPICIOUS", "PHISHING"].includes(data.label)) return false;
  if (!Number.isFinite(data.model_probability) || data.model_probability < 0 || data.model_probability > 1) return false;
  if (!Number.isFinite(data.effective_probability) || data.effective_probability < 0 || data.effective_probability > 1) return false;
  if (!["model", "verified_official_route_policy", "local_host_policy"].includes(data.probability_source)) return false;
  if (!data.reputation || typeof data.reputation.applied !== "boolean" || typeof data.reputation.source !== "string") return false;
  if (!Number.isInteger(data.risk_score) || data.risk_score < 0 || data.risk_score > 100) return false;
  const {safe, phishing} = data.thresholds || {};
  if (!Number.isFinite(safe) || !Number.isFinite(phishing) || safe < 0 || safe >= phishing || phishing > 1) return false;
  if (typeof data.normalized_url !== "string" || typeof data.model_version !== "string") return false;
  if (typeof data.model_fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(data.model_fingerprint)) return false;
  if (typeof data.request_id !== "string" || !/^[0-9a-f-]{36}$/i.test(data.request_id)) return false;
  if (!data.backend || typeof data.backend.api_endpoint !== "string"
    || !Number.isInteger(data.backend.backend_pid)
    || typeof data.backend.backend_instance_id !== "string") return false;
  return true;
}

function isValidHealth(data) {
  return data?.status === "ok"
    && data.model_loaded === true
    && typeof data.model_fingerprint === "string"
    && /^[a-f0-9]{64}$/.test(data.model_fingerprint)
    && typeof data.backend?.backend_instance_id === "string";
}

function badgeFor(label) {
  if (label === "PHISHING") return {text: "!", color: "#d96b6b"};
  if (label === "SUSPICIOUS") return {text: "?", color: "#d6a84f"};
  return {text: "", color: "#69c995"};
}

async function setBadge(tabId, label, offline = false) {
  if (typeof tabId !== "number" || tabId < 0) return;
  const badge = offline ? {text: "–", color: "#7e8b92"} : badgeFor(label);
  try {
    await Promise.all([
      chrome.action.setBadgeText({tabId, text: badge.text}),
      chrome.action.setBadgeBackgroundColor({tabId, color: badge.color})
    ]);
  } catch (error) {
    if (!isTabClosedError(error) && globalThis.VIGIL_DEBUG === true) {
      console.warn("[BADGE ERROR]", error?.message || error);
    }
  }
}

async function scanUrl(tabId, url) {
  const normalizedUrl = new URL(url).href;
  const key = cacheKey(tabId, normalizedUrl);
  const clientScanId = crypto.randomUUID();
  if (inFlight.has(key)) return inFlight.get(key);

  const request = fetchWithTimeout(`${API_BASE}/scan`, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Vigil-Request-Id": clientScanId},
    body: JSON.stringify({url: normalizedUrl})
  }).then(async ({response, data}) => {
    if (!response.ok) throw new Error(data?.message || "The VIGIL backend rejected the scan.");
    if (!isValidScanResult(data) || new URL(data.normalized_url).href !== normalizedUrl) {
      throw new Error("The VIGIL backend returned an invalid result.");
    }
    const result = {
      ...data,
      diagnostics: {...data.diagnostics, client_scan_id: clientScanId, cache_hit: false}
    };
    logScan(normalizedUrl, result);
    const navigation = latestNavigations.get(tabId);
    if (!navigation || navigation.url === normalizedUrl) {
      await setBadge(tabId, result.label);
    }
    return result;
  }).catch(async error => {
    logScan(normalizedUrl, null);
    const navigation = latestNavigations.get(tabId);
    if (!navigation || navigation.url === normalizedUrl) {
      await setBadge(tabId, null, true);
    }
    throw error;
  }).finally(() => inFlight.delete(key));

  inFlight.set(key, request);
  return request;
}

async function saveBlockedState(tabId, url, result) {
  const token = crypto.randomUUID();
  await chrome.storage.session.set({
    [`blocked:${token}`]: {
      tabId,
      url,
      result,
      createdAt: Date.now(),
      blockedAt: result.scanned_at || new Date().toISOString()
    }
  });
  return token;
}

async function blockNavigation(details, navigation) {
  try {
    const result = await scanUrl(details.tabId, details.url);
    if (latestNavigations.get(details.tabId) !== navigation) {
      logBlockDecision(details.url, result.label, "ALLOW (navigation changed)", result);
      return;
    }
    if (result.label !== "PHISHING") {
      logBlockDecision(details.url, result.label, "ALLOW", result);
      return;
    }
    const token = await saveBlockedState(details.tabId, details.url, result);
    if (latestNavigations.get(details.tabId) !== navigation) {
      await chrome.storage.session.remove(`blocked:${token}`).catch(() => undefined);
      logBlockDecision(details.url, result.label, "ALLOW (navigation changed)", result);
      return;
    }
    const blockedUrl = chrome.runtime.getURL(`blocked.html?token=${encodeURIComponent(token)}`);
    logBlockDecision(details.url, result.label, "BLOCK", result);
    try {
      await chrome.tabs.update(details.tabId, {url: blockedUrl});
    } catch (err) {
      if (!isTabClosedError(err) && globalThis.VIGIL_DEBUG === true) {
        console.warn("[UPDATE BLOCKED TAB ERROR]", err?.message || err);
      }
    }
  } catch (error) {
    logBlockDecision(details.url, "ERROR", "ALLOW");
    // Fail open with an honest offline state. A failed request is not a phishing verdict.
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  const navigation = {
    url: isScannableUrl(details.url) ? new URL(details.url).href : null,
    navigationId: details.navigationId || null,
    timestamp: Date.now()
  };
  latestNavigations.set(details.tabId, navigation);
  if (!isScannableUrl(details.url)) return;
  const bypassUrl = bypasses.get(details.tabId);
  if (bypassUrl === navigation.url) {
    bypasses.delete(details.tabId);
    return;
  }
  void blockNavigation(details, navigation).catch(err => {
    if (!isTabClosedError(err) && globalThis.VIGIL_DEBUG === true) {
      console.warn("[NAV BLOCK ERROR]", err?.message || err);
    }
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab?.url || !isScannableUrl(tab.url)) return;
  void scanUrl(tabId, tab.url).catch(() => undefined);
});

chrome.tabs.onRemoved.addListener(tabId => {
  for (const key of inFlight.keys()) {
    if (key.startsWith(`${tabId}:`)) inFlight.delete(key);
  }
  bypasses.delete(tabId);
  latestNavigations.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "HEALTH_CHECK") {
    fetchWithTimeout(`${API_BASE}/health`).then(({response, data}) => {
      if (!response.ok || !isValidHealth(data)) return {state: "BACKEND_OFFLINE"};
      return {
        state: "CONNECTED",
        model_version: data.model_version || null,
        model_fingerprint: data.model_fingerprint,
        backend: data.backend,
        api_endpoint: `${API_BASE}/health`
      };
    }).catch(() => ({state: "BACKEND_OFFLINE"})).then(sendResponse);
    return true;
  }

  if (message?.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({active: true, currentWindow: true}).then(async tabs => {
      const tab = tabs[0];
      if (!tab) return {state: "UNSUPPORTED", url: ""};
      if (tab?.url?.startsWith(chrome.runtime.getURL("blocked.html"))) {
        const token = new URL(tab.url).searchParams.get("token");
        const stored = token ? await chrome.storage.session.get(`blocked:${token}`) : {};
        const state = token ? stored[`blocked:${token}`] : null;
        if (state) return {state: "RESULT", blocked: true, url: state.url, result: state.result};
      }
      if (!tab?.url || !isScannableUrl(tab.url)) return {state: "UNSUPPORTED", url: tab?.url || ""};
      const requestedUrl = new URL(tab.url).href;
      try {
        const result = await scanUrl(tab.id, requestedUrl);
        const currentTabs = await chrome.tabs.query({active: true, currentWindow: true});
        if (
          !currentTabs[0] ||
          currentTabs[0].id !== tab.id ||
          !isScannableUrl(currentTabs[0].url) ||
          new URL(currentTabs[0].url).href !== requestedUrl
        ) {
          return {state: "STALE", url: requestedUrl};
        }
        return {state: "RESULT", url: requestedUrl, result};
      } catch (error) {
        return {state: "OFFLINE", url: tab.url, message: error.message};
      }
    }).catch(err => {
      return {state: "OFFLINE", url: "", message: err?.message || "Tab query failed"};
    }).then(sendResponse);
    return true;
  }

  if (message?.type === "GET_BLOCKED_STATE") {
    chrome.storage.session.get(`blocked:${message.token}`)
      .then(data => sendResponse(data[`blocked:${message.token}`] || null))
      .catch(() => sendResponse(null));
    return true;
  }

  if (message?.type === "GO_BACK" && sender.tab?.id !== undefined) {
    const tabId = sender.tab.id;
    chrome.tabs.goBack(tabId).catch(() => {
      return chrome.tabs.update(tabId, {url: "about:blank"}).catch(() => undefined);
    });
    sendResponse({ok: true});
    return false;
  }

  if (message?.type === "BYPASS_ONCE" && sender.tab?.id !== undefined) {
    const tabId = sender.tab.id;
    chrome.storage.session.get(`blocked:${message.token}`).then(async data => {
      const state = data[`blocked:${message.token}`];
      if (!state || state.tabId !== tabId) return;
      bypasses.set(tabId, new URL(state.url).href);
      try {
        await chrome.tabs.update(tabId, {url: state.url});
      } catch (err) {
        if (!isTabClosedError(err) && globalThis.VIGIL_DEBUG === true) {
          console.warn("[BYPASS TAB UPDATE ERROR]", err?.message || err);
        }
      }
      await chrome.storage.session.remove(`blocked:${message.token}`).catch(() => undefined);
    }).catch(err => {
      if (!isTabClosedError(err) && globalThis.VIGIL_DEBUG === true) {
        console.warn("[BYPASS ERROR]", err?.message || err);
      }
    });
    sendResponse({ok: true});
    return false;
  }
});
