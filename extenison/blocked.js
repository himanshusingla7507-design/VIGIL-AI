const params = new URLSearchParams(location.search);
const token = params.get("token");
const $ = id => document.getElementById(id);

function renderState(state) {
  if (!state?.result) { $("error").hidden = false; $("error").textContent = "VIGIL could not load the scan details. The original URL remains blocked."; return; }
  const result = state.result;
  $("blocked-url").textContent = state.url || "Unavailable";
  $("risk").textContent = String(result.risk_score);
  $("probability").textContent = `${(Number(result.probability) * 100).toFixed(1)}%`;
  $("model").textContent = result.model_version ? `Model ${result.model_version}` : "";
  const evidence = Array.isArray(result.evidence) ? result.evidence : [];
  $("evidence-list").replaceChildren(...evidence.slice(0, 6).map(item => {
    const row = document.createElement("li");
    const title = document.createElement("strong"); title.textContent = item.title || "Observed signal";
    const detail = document.createElement("span"); detail.textContent = item.detail || "";
    row.append(title, detail); return row;
  }));
}

if (!token) {
  $("error").hidden = false; $("error").textContent = "This block record is no longer available. The navigation remains blocked.";
} else {
  chrome.runtime.sendMessage({type: "GET_BLOCKED_STATE", token}).then(renderState).catch(() => { $("error").hidden = false; $("error").textContent = "The VIGIL service worker is unavailable. The navigation remains blocked."; });
}

$("back").addEventListener("click", () => { chrome.runtime.sendMessage({type: "GO_BACK"}); });
$("more").addEventListener("click", () => { const advanced = $("advanced"); const open = advanced.hidden; advanced.hidden = !open; $("more").setAttribute("aria-expanded", String(open)); $("more").textContent = open ? "Hide options" : "More options"; });
$("proceed").addEventListener("click", () => { chrome.runtime.sendMessage({type: "BYPASS_ONCE", token}); });
