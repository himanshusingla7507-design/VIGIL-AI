const $ = id => document.getElementById(id);
let currentUrl = "";
let activeRequest = null;

function hostLabel(url) {
  try { return new URL(url).hostname || url; } catch { return url || "Unavailable"; }
}

function setProtection(kind, text) {
  const node = $("protection");
  node.className = `protection ${kind}`;
  node.lastElementChild.textContent = text;
}

function setState(state, title, summary) {
  const panel = $("state-panel");
  panel.className = `state-panel ${state.toLowerCase()}`;
  $("state-title").textContent = title;
  $("state-summary").textContent = summary;
  $("state-icon").textContent = state === "SAFE" ? "✓" : state === "PHISHING" ? "!" : state === "SUSPICIOUS" ? "!" : state === "SCANNING" ? "…" : "•";
}

function clearResult() {
  $("metrics").hidden = true;
  $("evidence-section").hidden = true;
  $("details").hidden = true;
  $("notice").hidden = true;
  $("evidence-list").replaceChildren();
}

function sendWorkerMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, response => {
      const error = chrome.runtime.lastError;
      if (error) {
        const workerError = new Error("The VIGIL extension service worker is unavailable.");
        workerError.code = "WORKER_UNAVAILABLE";
        reject(workerError);
        return;
      }
      resolve(response);
    });
  });
}

function renderResult(result) {
  const label = result.label;
  const summary = label === "SAFE" ? "Low-risk URL characteristics detected." : label === "SUSPICIOUS" ? "Review this URL before continuing." : "High-risk URL detected. Navigation is blocked.";
  setState(label, label === "PHISHING" ? "BLOCKED" : label, summary);
  setProtection(label === "SAFE" ? "online" : "attention", label === "SAFE" ? "Protected" : "Attention required");
  $("metrics").hidden = false;
  $("risk").textContent = String(result.risk_score);
  $("probability").textContent = `${(Number(result.probability) * 100).toFixed(1)}%`;
  const evidence = Array.isArray(result.evidence) ? result.evidence : [];
  $("evidence-section").hidden = evidence.length === 0;
  $("signal-count").textContent = `${evidence.length} signal${evidence.length === 1 ? "" : "s"}`;
  const list = $("evidence-list");
  list.replaceChildren(...evidence.slice(0, 4).map(item => {
    const row = document.createElement("li");
    row.className = item.severity === "danger" ? "danger" : item.severity === "warning" ? "warning" : "";
    const title = document.createElement("strong"); title.textContent = item.title || "Observed signal";
    const detail = document.createElement("span"); detail.textContent = item.detail || "";
    row.append(title, detail); return row;
  }));
  $("details").hidden = false;
  $("https-value").textContent = result.features?.IsHTTPS ? "Enabled" : "Not enabled";
  $("ip-value").textContent = result.features?.IsDomainIP ? "Yes" : "No";
  $("subdomain-value").textContent = String(result.features?.SubdomainDepth ?? "—");
  $("model-value").textContent = result.model_version || "Unknown";
  $("copy-btn").disabled = false;
  $("scan-btn").textContent = "Refresh scan";
}

function renderUnsupported(url) {
  currentUrl = url || "";
  $("site-url").textContent = currentUrl ? hostLabel(currentUrl) : "This browser page";
  setProtection("attention", "Limited");
  setState("ERROR", "Cannot scan this page", "VIGIL only analyzes http:// and https:// pages.");
  $("notice").hidden = false; $("notice").textContent = "Chrome internal pages and extension pages cannot be scanned by an extension.";
  $("scan-btn").disabled = true; $("copy-btn").disabled = true;
}

async function scanCurrent() {
  if (activeRequest) return activeRequest;
  clearResult();
  $("scan-btn").disabled = true;
  setState("INITIALIZING", "Checking connection", "Connecting to VIGIL protection.");
  setProtection("", "Checking");
  activeRequest = sendWorkerMessage({type: "HEALTH_CHECK"}).then(health => {
    if (!health || health.state === "BACKEND_OFFLINE") {
      clearResult(); setState("ERROR", "Backend unavailable", "VIGIL could not reach the local Flask service."); setProtection("offline", "Offline");
      $("notice").hidden = false; $("notice").textContent = "Start the backend at http://127.0.0.1:5000, then choose Retry.";
      return null;
    }
    setState("SCANNING", "Scanning", "Analyzing the current URL with VIGIL.");
    setProtection("online", "Connected");
    return sendWorkerMessage({type: "SCAN_CURRENT_TAB"});
  }).then(response => {
    if (!response) return;
    if (!response || response.state === "UNSUPPORTED") return renderUnsupported(response?.url);
    currentUrl = response.url || currentUrl;
    $("site-url").textContent = hostLabel(currentUrl);
    if (response.state === "OFFLINE") {
      clearResult(); setState("ERROR", "Backend unavailable", "VIGIL could not complete this scan."); setProtection("offline", "Offline");
      $("notice").hidden = false; $("notice").textContent = "Try again when the local Flask service is running. No phishing verdict was assumed.";
      return;
    }
    renderResult(response.result);
  }).catch(error => {
    clearResult();
    if (error.code === "WORKER_UNAVAILABLE") {
      setState("ERROR", "Extension service unavailable", "Reload VIGIL from the browser extensions page, then retry.");
      setProtection("offline", "Extension error");
      $("notice").hidden = false; $("notice").textContent = "The popup could not reach the VIGIL service worker. The backend status is unknown.";
      return;
    }
    setState("ERROR", "Scan unavailable", "VIGIL could not complete this scan."); setProtection("offline", "Scan error");
    $("notice").hidden = false; $("notice").textContent = "The scan did not complete. Choose Retry to try again.";
  }).finally(() => { activeRequest = null; $("scan-btn").disabled = false; });
  return activeRequest;
}

$("scan-btn").addEventListener("click", scanCurrent);
$("copy-btn").addEventListener("click", async () => { if (!currentUrl) return; await navigator.clipboard?.writeText(currentUrl); $("copy-btn").textContent = "Copied"; setTimeout(() => { $("copy-btn").textContent = "Copy URL"; }, 1200); });
scanCurrent();
