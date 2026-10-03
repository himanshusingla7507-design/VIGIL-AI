// The extension reads the active tab URL and delegates all analysis to VIGIL.
const API_BASE = "http://127.0.0.1:5000";
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url || !/^https?:\/\//i.test(tab.url)) return;
  fetch(`${API_BASE}/scan`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({url: tab.url})})
    .then(r => r.json())
    .then(data => { const text = data.label === "PHISHING" ? "PHI" : data.label === "SUSPICIOUS" ? "WARN" : "OK"; chrome.action.setBadgeText({tabId, text}); })
    .catch(() => chrome.action.setBadgeText({tabId, text: "?"}));
});
