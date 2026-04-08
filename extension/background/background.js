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
  settings = {
    realtime:      stored.realtime !== false,
    download:      stored.download !== false,
    block:         stored.block !== false,
    notifications: stored.notifications !== false,
  };

  console.log("[SafeLink AI] Background service worker started.");
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
    } catch(e) {
      console.warn("Could not clear old dynamic rules", e);
    }
  }
}

initialize();

// ─── Message Handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SETTINGS_UPDATED") {
    settings = { ...settings, ...message.settings };
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

  if (message.type === "IGNORE_URL") {
    temporaryWhitelist.add(message.url);
    removeDynamicBlockRule(message.url);
    // Allow bypass for 5 minutes
    setTimeout(() => temporaryWhitelist.delete(message.url), 5 * 60 * 1000);
    sendResponse({ success: true });
  }
});

// ─── Real-time URL Protection ─────────────────────────────────────────────────

/**
 * Listen to tab URL changes and scan them.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only scan on complete navigation with a real URL
  if (changeInfo.status !== "complete") return;
  if (!settings.realtime) return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  // Skip extension internal pages
  if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) return;

  // Skip if this tab is currently being blocked (avoid loop)
  if (blockedTabs.has(tabId)) {
    blockedTabs.delete(tabId);
    return;
  }

  // Skip if user explicitly permitted in the last 5 minutes
  if (temporaryWhitelist.has(tab.url)) {
    return;
  }

  try {
    const result = await scanURLBackground(tab.url);

    if (!result) return;

    if (result.verdict === "malicious" && settings.block) {
      // Add dynamic declarative network rule to block future requests to domain
      await addDynamicBlockRule(tab.url);
      
      // Block the page
      await blockPage(tabId, tab.url, result);
    } else if (result.verdict === "suspicious") {
      // Show warning overlay via content script
      await showWarning(tabId, result);

      // Show notification
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
  } catch (err) {
    console.error("[SafeLink AI] Tab scan error:", err.message);
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

let ruleIdCounter = 1000;
const ruleIdMap = new Map(); // domain -> ruleId

/**
 * Dynamically block a malicious domain using declarativeNetRequest
 */
async function addDynamicBlockRule(url) {
  if (!chrome.declarativeNetRequest) return;
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    if (existingRules.some(r => r.condition.urlFilter === domain)) {
      return; // Already blocked
    }

    const ruleId = ruleIdCounter++;
    ruleIdMap.set(domain, ruleId);

    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id: ruleId,
        priority: 10,
        action: { type: "block" },
        condition: {
          urlFilter: domain,
          resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script"]
        }
      }],
      removeRuleIds: [ruleId]
    });
    console.log(`[SafeLink AI] Native browser block added for ${domain}`);
  } catch (err) {}
}

/**
 * Remove a dynamic block rule (for bypassing)
 */
async function removeDynamicBlockRule(url) {
  if (!chrome.declarativeNetRequest) return;
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const ruleId = ruleIdMap.get(domain);
    if (ruleId) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [ruleId]
      });
      ruleIdMap.delete(domain);
      console.log(`[SafeLink AI] Native browser block removed for ${domain}`);
    }
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
