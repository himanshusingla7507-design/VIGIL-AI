const params = new URLSearchParams(location.search);
const token = params.get("token");
const $ = id => document.getElementById(id);

let blockedUrlValue = "";

function formatLocalTimeWithZone(date) {
  try {
    const formatted = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    }).format(date);
    return formatted;
  } catch {
    return date.toLocaleString();
  }
}

function updateLiveClock() {
  const clockEl = $("live-clock");
  if (clockEl) {
    const now = new Date();
    clockEl.textContent = formatLocalTimeWithZone(now);
  }
}

// Start live clock ticking every second
updateLiveClock();
setInterval(updateLiveClock, 1000);

function sendWorkerMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) {
        reject(new Error("The VIGIL extension service worker is unavailable."));
        return;
      }
      resolve(response);
    });
  });
}

function renderState(state) {
  if (!state?.result) {
    $("error").hidden = false;
    $("error").textContent = "VIGIL could not load the scan details. The original URL remains blocked.";
    return;
  }
  const result = state.result;
  if (result.label !== "PHISHING") {
    $("error").hidden = false;
    $("error").textContent = "The saved scan verdict does not match this blocked navigation. The original URL remains blocked.";
    return;
  }

  // Display actual fixed event timestamp of blocking decision
  const blockDate = result.scanned_at ? new Date(result.scanned_at) : (state.createdAt ? new Date(state.createdAt) : new Date());
  $("blocked-timestamp").textContent = formatLocalTimeWithZone(blockDate);

  blockedUrlValue = state.url || "Unavailable";
  $("blocked-url").textContent = blockedUrlValue;
  $("verdict").textContent = result.label;
  $("risk").textContent = String(result.risk_score);
  $("probability").textContent = `${(Number(result.effective_probability) * 100).toFixed(1)}%`;
  
  if ($("raw-probability")) {
    const modelProb = result.model_probability !== undefined ? result.model_probability : result.probability;
    $("raw-probability").textContent = `${(Number(modelProb) * 100).toFixed(1)}%`;
  }

  $("model").textContent = result.model_version
    ? `Model ${result.model_version} · Request ${result.request_id || "unknown"}`
    : "";

  const evidence = Array.isArray(result.evidence) ? result.evidence : [];
  $("evidence-list").replaceChildren(...evidence.slice(0, 6).map(item => {
    const row = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = item.title || "Observed signal";
    const detail = document.createElement("span");
    detail.textContent = item.detail || "";
    row.append(title, detail);
    return row;
  }));
}

if (!token) {
  $("error").hidden = false;
  $("error").textContent = "This block record is no longer available. The navigation remains blocked.";
} else {
  sendWorkerMessage({type: "GET_BLOCKED_STATE", token})
    .then(renderState)
    .catch(() => {
      $("error").hidden = false;
      $("error").textContent = "The VIGIL service worker is unavailable. The navigation remains blocked.";
    });
}

$("back").addEventListener("click", () => {
  sendWorkerMessage({type: "GO_BACK"}).catch(() => {
    $("error").hidden = false;
    $("error").textContent = "VIGIL could not return to the previous page.";
  });
});

$("more").addEventListener("click", () => {
  const advanced = $("advanced");
  const open = advanced.hidden;
  advanced.hidden = !open;
  $("more").setAttribute("aria-expanded", String(open));
  $("more").textContent = open ? "Hide options" : "More options";
});

$("proceed").addEventListener("click", () => {
  sendWorkerMessage({type: "BYPASS_ONCE", token}).catch(() => {
    $("error").hidden = false;
    $("error").textContent = "VIGIL could not complete the one-time bypass.";
  });
});

const copyBtn = $("copy-url");
if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    if (!blockedUrlValue || blockedUrlValue === "Unavailable") return;
    try {
      await navigator.clipboard.writeText(blockedUrlValue);
      copyBtn.textContent = "Copied!";
      setTimeout(() => {
        copyBtn.textContent = "Copy URL";
      }, 1500);
    } catch {
      // Fallback
    }
  });
}
