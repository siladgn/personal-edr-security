const API_URL = "http://localhost:5000/predict";

// Listen to top-level navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level frame navigation (not sub-frames like iframes)
  if (details.frameId !== 0) return;

  const url = details.url;

  // Ignore internal chrome pages, localhost, and extension pages
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return;

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;

    // Check if the domain is temporarily whitelisted by the user
    const whitelistData = await chrome.storage.local.get(["whitelistedDomains"]);
    const whitelisted = whitelistData.whitelistedDomains || [];
    if (whitelisted.includes(hostname)) {
      console.log(`[EDR] Domain is whitelisted by user: ${hostname}`);
      return;
    }

    // Call the ML Phishing Detector Flask API
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      console.error("[EDR] ML Phishing Detector API response error:", response.status);
      return;
    }

    const data = await response.json();
    console.log(`[EDR] API Prediction for ${url}:`, data);

    if (data.is_phishing && data.risk_score >= 0.65) {
      console.warn(`[EDR] Phishing URL blocked: ${url} (Score: ${data.risk_score})`);
      
      // Redirect target tab to blocked.html page with URL and score parameters
      const blockedPageUrl = chrome.runtime.getURL("blocked.html") + 
        `?url=${encodeURIComponent(url)}` + 
        `&score=${encodeURIComponent(data.risk_score)}`;
      
      chrome.tabs.update(details.tabId, { url: blockedPageUrl });
    }
  } catch (error) {
    // If the Flask service is down, EDR fails-open to not block standard browsing, but logs the error
    console.error("[EDR] Failed to connect to ML Phishing Detector API. EDR service might be offline.", error);
  }
});
