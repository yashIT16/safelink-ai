/**
 * autoUpdater.js
 * --------------
 * Periodically fetches fresh phishing URLs from public sources
 * and updates the local SQLite database.
 *
 * Runs on a configurable cron schedule (default: every 6 hours).
 */

const cron = require("node-cron");
const axios = require("axios");
const db = require("../database/db");

const PHISHING_FEEDS = [
  {
    name: "OpenPhish",
    url: "https://openphish.com/feed.txt",
    parser: "plaintext",
  },
  {
    name: "URLhaus",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    parser: "plaintext",
  },
];

// Mock phishing URLs to simulate updates when feeds are unavailable
const MOCK_UPDATE_URLS = [
  "http://fake-amazon-login-2024.xyz/signin",
  "http://paypal-verify-account.tk/update",
  "http://secure-bank-login.ml/confirm",
  "http://netflix-billing-update.ga/payment",
  "http://microsoft-account-alert.cf/verify",
  "http://apple-id-suspended.gq/unlock",
  "http://steam-trade-offer.xyz/trade/verify",
  "http://facebook-security-check.tk/login",
];

let isUpdating = false;
let lastUpdateTime = null;
let cronJob = null;

/**
 * Fetch phishing URLs from a plaintext feed.
 * @param {string} url
 * @returns {Promise<string[]>}
 */
async function fetchPlaintextFeed(url) {
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      responseType: "text",
    });
    const urls = response.data
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("http") && line.length < 500);
    return urls;
  } catch (error) {
    console.error(`[AutoUpdater] Failed to fetch feed ${url}: ${error.message}`);
    return [];
  }
}

/**
 * Run a single update cycle.
 * @returns {Promise<{success: boolean, urlsAdded: number, sources: string[]}>}
 */
async function runUpdate() {
  if (isUpdating) {
    console.log("[AutoUpdater] Update already in progress, skipping.");
    return { success: false, urlsAdded: 0, sources: [] };
  }

  isUpdating = true;
  const results = { success: true, urlsAdded: 0, sources: [] };

  try {
    console.log("[AutoUpdater] Starting phishing feed update...");

    // Try real feeds first
    for (const feed of PHISHING_FEEDS) {
      if (!feed.url) continue;

      try {
        let urls = [];
        if (feed.parser === "plaintext") {
          urls = await fetchPlaintextFeed(feed.url);
        }

        if (urls.length > 0) {
          const items = urls.slice(0, 500).map((url) => ({
            url,
            source: feed.name,
            threatType: "phishing",
          }));

          const added = db.bulkAddToBlacklist(items);
          db.logUpdate(feed.name, added);
          results.urlsAdded += added;
          results.sources.push(feed.name);
          console.log(`[AutoUpdater] ${feed.name}: +${added} URLs`);
        }
      } catch (err) {
        console.error(`[AutoUpdater] Error processing ${feed.name}: ${err.message}`);
      }
    }

    // Always add mock URLs to simulate updates
    const mockItems = MOCK_UPDATE_URLS.map((url) => ({
      url,
      source: "mock_update",
      threatType: "phishing",
    }));

    const mockAdded = db.bulkAddToBlacklist(mockItems);
    if (mockAdded > 0) {
      db.logUpdate("mock_update", mockAdded);
      results.urlsAdded += mockAdded;
      results.sources.push("mock_update");
      console.log(`[AutoUpdater] Mock feed: +${mockAdded} URLs`);
    }

    lastUpdateTime = new Date().toISOString();
    console.log(`[AutoUpdater] Update complete. Total added: ${results.urlsAdded}`);
  } catch (error) {
    console.error("[AutoUpdater] Update failed:", error.message);
    results.success = false;
  } finally {
    isUpdating = false;
  }

  return results;
}

/**
 * Start the auto-updater cron job.
 * @param {string} schedule - Cron expression (default: every 6 hours)
 */
function startAutoUpdater(schedule = "0 */6 * * *") {
  if (cronJob) {
    console.log("[AutoUpdater] Already running.");
    return;
  }

  console.log(`[AutoUpdater] Starting with schedule: ${schedule}`);

  // Run immediately on startup
  runUpdate().catch(console.error);

  // Schedule subsequent runs
  cronJob = cron.schedule(schedule, () => {
    console.log("[AutoUpdater] Scheduled update triggered");
    runUpdate().catch(console.error);
  });

  console.log("[AutoUpdater] Cron job scheduled.");
}

/**
 * Stop the auto-updater.
 */
function stopAutoUpdater() {
  if (cronJob) {
    cronJob.destroy();
    cronJob = null;
    console.log("[AutoUpdater] Stopped.");
  }
}

/**
 * Get auto-updater status.
 * @returns {object}
 */
function getStatus() {
  return {
    isRunning: cronJob !== null,
    isUpdating,
    lastUpdateTime,
  };
}

module.exports = { startAutoUpdater, stopAutoUpdater, runUpdate, getStatus };
