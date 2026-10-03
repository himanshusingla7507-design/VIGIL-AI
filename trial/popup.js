const resultDiv = document.getElementById("result");
const scanBtn = document.getElementById("scanBtn");

let isScanning = false;

scanBtn.addEventListener("click", () => {
  if (isScanning) return;

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const url = tabs[0].url;

    isScanning = true;
    scanBtn.innerText = "SCANNING...";
    scanBtn.style.opacity = "0.6";
    scanBtn.disabled = true;

    // 🔄 Loading UI
    resultDiv.className = "";
    resultDiv.innerHTML = `
      <div style="font-size:13px;opacity:0.8;">
        ⏳ Initializing scan...
      </div>
    `;

    try {
      // ⏳ Smooth steps
      const steps = [
        "Parsing URL...",
        "Extracting features...",
        "Running AI model..."
      ];

      for (let step of steps) {
        resultDiv.innerHTML = `
          <div style="font-size:13px;opacity:0.8;">
            ⏳ ${step}
          </div>
        `;
        await new Promise(r => setTimeout(r, 300));
      }

      // ⏱️ Timeout safety
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 10000);

      // 🔗 API CALL
      const res = await fetch("https://vigil-api-5sed.onrender.com/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });

      const data = await res.json();
      const percent = Math.round(data.confidence * 100);

      // 🎯 Risk logic
      let cls = "result-safe";
      let message = "✅ Looks safe.";
      let icon = "✔️";

      if (percent >= 75) {
        cls = "result-danger";
        message = "🚨 High risk phishing site!";
        icon = "🚨";
      } else if (percent >= 45) {
        cls = "result-warn";
        message = "⚠️ Suspicious, proceed carefully.";
        icon = "⚠️";
      }

      resultDiv.className = cls;

      // 💎 FINAL UI
      resultDiv.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;gap:6px;">
          
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:20px;">${icon}</span>
            <span style="font-size:16px;font-weight:700;">
              ${data.result} (${percent}%)
            </span>
          </div>

          <div style="width:100%;height:6px;background:rgba(0,245,255,0.1);border-radius:4px;overflow:hidden;margin-top:6px;">
            <div style="
              width:${percent}%;
              height:100%;
              background:linear-gradient(90deg, ${percent>=70?'#ff2244':percent>=40?'#ffe600':'#00ff88'}, #00f5ff);
              transition:width 0.5s ease;
            "></div>
          </div>

          <div style="font-size:12px;margin-top:4px;color:rgba(200,240,255,0.6);text-align:center;">
            ${message}
          </div>

          <div style="margin-top:6px;font-size:10px;color:rgba(200,240,255,0.35);word-break:break-all;text-align:center;">
            ${url}
          </div>

        </div>
      `;

    } catch (err) {
      resultDiv.className = "result-danger";
      resultDiv.innerHTML = `
        <div style="font-size:14px;">❌ Connection Failed</div>
        <div style="font-size:11px;margin-top:5px;color:rgba(200,240,255,0.5);">
          Backend not running or unreachable
        </div>
      `;
    } finally {
      isScanning = false;
      scanBtn.innerText = "⬡ SCAN URL";
      scanBtn.style.opacity = "1";
      scanBtn.disabled = false;
    }
  });
});

// ⌨️ Enter key support
document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !isScanning) {
    scanBtn.click();
  }
});
resultDiv.addEventListener("click", () => {
  navigator.clipboard.writeText(resultDiv.innerText);
});
resultDiv.addEventListener("click", () => {
  navigator.clipboard.writeText(resultDiv.innerText);
  resultDiv.innerHTML += `<div style="font-size:10px;margin-top:4px;">📋 Copied</div>`;
});