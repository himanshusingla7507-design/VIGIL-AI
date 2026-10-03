const resultDiv = document.getElementById("result");
const scanBtn = document.getElementById("scanBtn");
scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true; resultDiv.textContent = "Analyzing URL...";
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const response = await fetch("http://127.0.0.1:5000/scan", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url:tab.url})});
    const data = await response.json(); if (!response.ok) throw new Error(data.message || "Scan failed");
    const evidence = (data.evidence || []).slice(0, 3).map(x => `${x.title}: ${x.detail}`).join("\n");
    resultDiv.textContent = `${data.label} | risk ${data.risk_score}/100 | probability ${(data.probability * 100).toFixed(1)}%\n${evidence}`;
  } catch (error) { resultDiv.textContent = error.message || "Cannot reach the VIGIL API."; }
  finally { scanBtn.disabled = false; }
});
