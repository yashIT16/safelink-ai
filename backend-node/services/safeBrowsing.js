/**
 * safeBrowsing.js
 * ---------------
 * Google Safe Browsing API integration with mock fallback.
 *
 * To use real API:
 *   1. Get key from https://developers.google.com/safe-browsing
 *   2. Set GOOGLE_SAFE_BROWSING_KEY environment variable
 */

const axios = require("axios");

const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
const TIMEOUT_MS = 5000;

// Known safe domains that will always return clean (for mock mode)
const TRUSTED_DOMAINS = new Set([
  "google.com", "youtube.com", "facebook.com", "amazon.com",
  "twitter.com", "linkedin.com", "microsoft.com", "apple.com",
  "github.com", "stackoverflow.com", "wikipedia.org", "reddit.com",
  "netflix.com", "instagram.com", "bbc.com", "cnn.com",
]);

// Domains known to be malicious in mock mode
const MOCK_MALICIOUS = new Set([
  "secure-paypal-login.xyz",
  "amazon-account-suspended.tk",
  "login-verify-bank.ml",
  "google.com.fake-login.ga",
  "update-your-account.cf",
]);

/**
 * Check a URL against Google Safe Browsing API.
 *
 * @param {string} url
 * @returns {Promise<object>}
 *   { isMalicious: boolean, threatType: string|null, score: number }
 */
async function checkSafeBrowsing(url) {
  // Use real API if key is available
  if (API_KEY && API_KEY.length > 10) {
    return _callRealAPI(url);
  }

  // Mock mode
  return _mockCheck(url);
}

/**
 * Call real Google Safe Browsing API.
 * @param {string} url
 * @returns {Promise<object>}
 */
async function _callRealAPI(url) {
  try {
    const requestBody = {
      client: {
        clientId: "safelink-ai",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    };

    const response = await axios.post(API_URL, requestBody, { timeout: TIMEOUT_MS });

    if (response.data && response.data.matches && response.data.matches.length > 0) {
      const match = response.data.matches[0];
      return {
        isMalicious: true,
        threatType: match.threatType,
        platform: match.platformType,
        score: 90, // High confidence if GSB matches
        source: "google_safe_browsing",
      };
    }

    return {
      isMalicious: false,
      threatType: null,
      score: 0,
      source: "google_safe_browsing",
    };
  } catch (error) {
    console.error("[GSB] API error:", error.message);
    return _mockCheck(url);
  }
}

/**
 * Mock Safe Browsing check based on known patterns.
 * @param {string} url
 * @returns {object}
 */
function _mockCheck(url) {
  const lowerUrl = url.toLowerCase();

  // Check trusted domains
  for (const domain of TRUSTED_DOMAINS) {
    if (lowerUrl.includes(domain) && !lowerUrl.includes(`${domain}.`)) {
      return {
        isMalicious: false,
        threatType: null,
        score: 0,
        source: "google_sb_mock",
      };
    }
  }

  // Check mock malicious domains
  for (const domain of MOCK_MALICIOUS) {
    if (lowerUrl.includes(domain)) {
      return {
        isMalicious: true,
        threatType: "SOCIAL_ENGINEERING",
        score: 95,
        source: "google_sb_mock",
      };
    }
  }

  // Pattern-based mock detection
  const suspiciousPatterns = [
    /@/,                              // @ in URL
    /\.(xyz|tk|ml|ga|cf|gq)\//,      // Suspicious TLDs
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address
    /secure.*login|login.*secure/,    // login+secure combo
    /verify.*account|account.*verify/, // verify+account
  ];

  const matches = suspiciousPatterns.filter((p) => p.test(lowerUrl));
  if (matches.length >= 2) {
    return {
      isMalicious: true,
      threatType: "SOCIAL_ENGINEERING",
      score: 70,
      source: "google_sb_mock",
    };
  }

  return {
    isMalicious: false,
    threatType: null,
    score: 0,
    source: "google_sb_mock",
  };
}

module.exports = { checkSafeBrowsing };
