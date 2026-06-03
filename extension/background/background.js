/**
 * background.js
 * -------------
 * SafeLink AI Chrome Extension - Service Worker
 *
 * Handles:
 * 1. Real-time URL protection (tab navigation)
 * 2. Download protection
 * 3. Periodic database updates
 * 4. Settings management
 */

const BACKEND_URL = "http://localhost:3001";

// ─── App State ────────────────────────────────────────────────────────────────
let settings = {
  realtime:      true,
  download:      true,
  block:         true,
  notifications: true,
};

// Cache of recently scanned URLs to avoid hammering the API
const scanCache = new Map(); // url → {result, timestamp}
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Tabs currently being blocked (to prevent infinite redirect loop)
const blockedTabs = new Set();

// URLs that the user explicitly chose to "Proceed Anyway" to
const temporaryWhitelist = new Set();

// ─── Initialization ───────────────────────────────────────────────────────────
async function initialize() {
  const stored = await chrome.storage.local.get([
    "realtime", "download", "block", "notifications"
  ]);
  // Always Active Mode: Force core protection features to true on startup
  settings = {
    realtime:      true,
    download:      true,
    block:         true,
    notifications: stored.notifications !== false,
  };

  // Persist the forced settings so the UI is in sync
  await chrome.storage.local.set({
    realtime: true,
    download: true,
    block:    true
  });

  updateBadge();

  console.log("[SafeLink AI] Always Active Mode initialized.");
  console.log("[SafeLink AI] Settings:", settings);

  // Clear any old/stale dynamic blocking rules from previous sessions
  if (chrome.declarativeNetRequest) {
    try {
      const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
      const oldRuleIds = oldRules.map(rule => rule.id);
      if (oldRuleIds.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: oldRuleIds });
        console.log(`[SafeLink AI] Cleared ${oldRuleIds.length} stale dynamic rules.`);
      }
      
      
      // Sync known malicious domains from backend for instant blocking
      await syncGlobalBlacklist();

      // PROTECTIVE SWEEP: Check all already-open tabs for malicious content
      console.log("[SafeLink AI] Performing retroactive protective sweep...");
      await scanAllOpenTabs();
    } catch(e) {
      console.warn("Could not sync/clear dynamic rules", e);
    }
  }
}

/**
 * Scan every open browser tab and block those that are malicious.
 * This handles tabs that were open before the extension started.
 */
async function scanAllOpenTabs() {
  try {
    const tabs = await chrome.tabs.query({ url: "http://*/*" });
    const httpsTabs = await chrome.tabs.query({ url: "https://*/*" });
    const allTabs = [...tabs, ...httpsTabs];

    console.log(`[SafeLink AI] Sweeping ${allTabs.length} open tabs...`);

    for (const tab of allTabs) {
      if (!tab.url) continue;
      
      const result = await scanURLBackground(tab.url);
      if (result && result.verdict === "malicious" && settings.block) {
        console.log(`[SafeLink AI] Existing tab found malicious: ${tab.url}`);
        await blockPage(tab.id, tab.url, result);
      }
    }
  } catch (err) {
    console.error("[SafeLink AI] Error during tab sweep:", err.message);
  }
}

/**
 * Fetch the global blacklist from the backend and add to DNR rules.
 */
async function syncGlobalBlacklist() {
  try {
    const response = await fetch(`${BACKEND_URL}/blacklist`);
    if (!response.ok) return;
    const { domains } = await response.json();
    
    if (domains && domains.length > 0) {
      console.log(`[SafeLink AI] Syncing ${domains.length} malicious domains into DNR...`);
      
      const BATCH_SIZE = 100;
      for (let i = 0; i < domains.length; i += BATCH_SIZE) {
        const batch = domains.slice(i, i + BATCH_SIZE);
        await addDomainsToBlocklist(batch);
      }
    }
  } catch (err) {
    console.warn("[SafeLink AI] Global blacklist sync failed:", err.message);
  }
}

initialize();

// ─── Message Handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SETTINGS_UPDATED") {
    settings = { ...settings, ...message.settings };
    updateBadge();
    console.log("[SafeLink AI] Settings updated:", settings);
  }

  if (message.type === "SCAN_URL") {
    scanURLBackground(message.url)
      .then((result) => sendResponse({ success: true, result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async
  }

  if (message.type === "GET_SCAN_RESULT") {
    const cached = getCached(message.url);
    sendResponse({ result: cached });
  }

  if (message.type === "CHECK_URL_SAFETY") {
    handleUrlSafetyCheck(message.url)
      .then(res => sendResponse(res))
      .catch(() => sendResponse({ isSafe: true }));
    return true;
  }

  if (message.type === "IGNORE_URL") {
    temporaryWhitelist.add(message.url);
    removeDynamicBlockRule(message.url);
    // Allow bypass for 5 minutes
    setTimeout(() => temporaryWhitelist.delete(message.url), 5 * 60 * 1000);
    sendResponse({ success: true });
  }
});

/**
 * Handle safety check request from content script.
 * Returns verdict and block status.
 */
async function handleUrlSafetyCheck(url) {
  const result = await scanURLBackground(url);
  if (!result) return { isSafe: true };

  if (result.verdict === "malicious" && settings.block) {
    // If not already on blocked page, redirect
    return { blocked: true, verdict: "malicious" };
  }
  
  return { 
    isSafe: result.verdict === "safe",
    verdict: result.verdict,
    riskScore: result.riskScore,
    explanation: result.explanation
  };
}

// ─── Real-time URL Protection ─────────────────────────────────────────────────

/**
 * PROACTIVE PROTECTION: Intercept navigation BEFORE it begins.
 * This prevents data from being sent to malicious hosts.
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const { tabId, url, frameId } = details;

  // Only scan main frame navigation with a real HTTP URL
  if (frameId !== 0) return;
  if (!settings.realtime) return;
  if (!url || !url.startsWith("http")) return;

  // Skip internal pages
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

  // Skip if user explicitly permitted in the last 5 minutes
  if (temporaryWhitelist.has(url)) return;

  try {
    const result = await scanURLBackground(url);
    if (!result) return;

    if (result.verdict === "malicious" && settings.block) {
      console.log(`[SafeLink AI] Proactively blocking malicious URL: ${url}`);
      
      // 1. Add to native DNR blocklist for immediate network suppression
      await addDynamicBlockRule(url, result.riskScore);

      // 2. Redirect the tab to our warning page
      await blockPage(tabId, url, result);
    }
  } catch (err) {
    console.error("[SafeLink AI] Proactive scan error:", err.message);
  }
});

/**
 * Listen to tab URL updates for suspicious overlays and notifications.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  const result = getCached(tab.url);
  if (!result) return;

  if (result.verdict === "suspicious") {
    await showWarning(tabId, result);
    if (settings.notifications) {
      showNotification(
        "⚠️ Suspicious URL Detected",
        `Risk Score: ${result.riskScore}/100\n${tab.url.slice(0, 60)}`,
        "warning"
      );
    }
  } else if (result.verdict === "malicious" && settings.notifications) {
    showNotification(
      "🚨 Malicious URL Blocked!",
      `SafeLink AI blocked a dangerous page.\n${tab.url.slice(0, 60)}`,
      "danger"
    );
  }
});

/**
 * Block a malicious page by redirecting to a warning page.
 */
async function blockPage(tabId, url, result) {
  blockedTabs.add(tabId);

  const warningUrl = chrome.runtime.getURL("blocked.html") +
    `?url=${encodeURIComponent(url)}&score=${result.riskScore}` +
    `&verdict=${result.verdict}`;

  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch (err) {
    // If redirect fails, still send warning via content script
    console.warn("[SafeLink AI] Could not redirect tab:", err.message);
    await showWarning(tabId, result);
  }
}

/**
 * Helper to add a batch of domains to the DNR blocklist with native REDIRECTION.
 */
async function addDomainsToBlocklist(domains, score = 99) {
  if (!chrome.declarativeNetRequest) return;
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = new Set(existingRules.map(r => r.id));
    
    const addRules = domains.map(domain => {
      const ruleId = generateRuleId(domain);
      if (existingIds.has(ruleId)) return null;

      const warningUrl = chrome.runtime.getURL("blocked.html") + 
                         `?url=${encodeURIComponent("http://" + domain)}&score=${score}&verdict=malicious`;

      return {
        id: ruleId,
        priority: 1,
        action: { 
          type: "redirect",
          redirect: { url: warningUrl }
        },
        condition: {
          urlFilter: `||${domain}`,
          resourceTypes: ["main_frame"]
        }
      };
    }).filter(r => r !== null);

    if (addRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: addRules
      });
    }
  } catch (err) {
    console.warn(`[SafeLink AI] DNR batch update failed:`, err.message);
  }
}

/**
 * Generate a consistent numeric ID for a domain.
 */
function generateRuleId(domain) {
  return domain.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) + 2000;
}

/**
 * Dynamically block a malicious domain using declarativeNetRequest
 */
async function addDynamicBlockRule(url, score = 99) {
  try {
    const parsed = new URL(url);
    await addDomainsToBlocklist([parsed.hostname], score);
  } catch (err) {
    console.error("[SafeLink AI] Failed to add DNR rule:", err.message);
  }
}

/**
 * Remove a dynamic block rule (for bypassing)
 */
async function removeDynamicBlockRule(url) {
  if (!chrome.declarativeNetRequest) return;
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const ruleId = generateRuleId(domain);
    
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId]
    });
    console.log(`[SafeLink AI] DNR block removed for: ${domain}`);
  } catch (err) {}
}

/**
 * Inject warning overlay into a suspicious page.
 */
async function showWarning(tabId, result) {
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "SHOW_WARNING",
      verdict: result.verdict,
      riskScore: result.riskScore,
      explanation: result.explanation,
    });
  } catch {
    // Content script may not be loaded yet — that's OK
  }
}

// ─── Download Protection ──────────────────────────────────────────────────────

/**
 * Monitor downloads and warn about dangerous files.
 */
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (!settings.download) return;

  // Only scan active, in-progress downloads. Skip already downloaded files.
  if (downloadItem.state !== "in_progress") return;

  // Only scan real web-downloads (ignore internal blobs, base64 data, etc.)
  if (!downloadItem.url || !downloadItem.url.startsWith("http")) return;

  // Validate the download was initiated within the last 30 seconds to avoid history-sync phantom scans
  const startTimeMs = new Date(downloadItem.startTime).getTime();
  if (Date.now() - startTimeMs > 30000) return;

  const filename = downloadItem.filename || downloadItem.url.split("/").pop() || "";
  const url = downloadItem.url;
  const ext = filename.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || "";

  try {
    // Do NOT pause the download so we don't trigger native OS "download paused/resumed" spam
    const result = await scanFileBackground(url, filename);
    
    if (result && result.verdict === "malicious") {
      // Cancel if still downloading, otherwise remove the file if completed
      chrome.downloads.cancel(downloadItem.id).catch(() => {});
      if (chrome.downloads.removeFile) {
        chrome.downloads.removeFile(downloadItem.id).catch(() => {});
      }

      showNotification(
        "🚨 Malicious File Blocked!",
        `Blocked download of ${filename}.\nRisk Score: ${result.riskScore}/100`,
        "danger"
      );

      // Show a blocked page
      const warningUrl = chrome.runtime.getURL("blocked-file.html") +
        `?filename=${encodeURIComponent(filename)}&score=${result.riskScore}` +
        `&hash=${result.hashes?.md5 || 'N/A'}` +
        `&ext=${encodeURIComponent(ext)}`;
      
      chrome.tabs.create({ url: warningUrl });
    }
    // If Safe, do nothing (silent by default)
  } catch {}
});

/**
 * Scan a file download via the backend API.
 * @param {string} url
 * @param {string} filename
 * @returns {Promise<object|null>}
 */
async function scanFileBackground(url, filename) {
  try {
    const controller = new AbortController();
    // Allow up to 60 seconds because backend must download the file itself
    const timeout = setTimeout(() => controller.abort(), 60000);

    const response = await fetch(`${BACKEND_URL}/scan-file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, filename }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) return null;

    return await response.json();
  } catch (err) {
    console.warn("[SafeLink AI] File backend API unavailable:", err.message);
    return null;
  }
}

// ─── URL Scanning (with Cache) ────────────────────────────────────────────────

/**
 * Scan a URL via the backend API, with caching.
 * @param {string} url
 * @returns {Promise<object|null>}
 */
async function scanURLBackground(url) {
  // Check cache
  const cached = getCached(url);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${BACKEND_URL}/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) return null;

    const result = await response.json();

    // Cache the result
    scanCache.set(url, { result, timestamp: Date.now() });

    return result;
  } catch (err) {
    if (err.name !== "AbortError") {
      console.warn("[SafeLink AI] API unavailable for background scan:", err.message);
    }
    return null;
  }
}

/**
 * Get cached scan result if still valid.
 */
function getCached(url) {
  const entry = scanCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    scanCache.delete(url);
    return null;
  }
  return entry.result;
}

// ─── Notifications ────────────────────────────────────────────────────────────

/**
 * Show a Chrome notification.
 */
function showNotification(title, message, type = "info") {
  if (!settings.notifications) return;

  chrome.notifications.create({
    type: "basic",
    iconUrl: `../icons/icon48.png`,
    title,
    message,
    priority: type === "danger" ? 2 : 1,
  }).catch(() => {});
}

/**
 * Update the extension icon badge to show "ON" when protection is active.
 */
function updateBadge() {
  const isActive = settings.realtime || settings.block;
  if (isActive) {
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#22c55e" }); // Emerald green
  } else {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#94a3b8" }); // Slate
  }
}

// ─── Periodic Cache Cleanup ───────────────────────────────────────────────────
chrome.alarms.create("cacheCleanup", { periodInMinutes: 10 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "cacheCleanup") {
    const now = Date.now();
    for (const [url, entry] of scanCache.entries()) {
      if (now - entry.timestamp > CACHE_TTL_MS) {
        scanCache.delete(url);
      }
    }
    console.log(`[SafeLink AI] Cache cleaned. Size: ${scanCache.size}`);
  }
});
