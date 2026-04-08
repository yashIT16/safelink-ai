/**
 * phishTank.js
 * ------------
 * PhishTank API integration with mock fallback.
 *
 * To use real API:
 *   1. Register at https://www.phishtank.com/api_register.php
 *   2. Set PHISHTANK_API_KEY environment variable
 */

const axios = require("axios");
const crypto = require("crypto");

const API_KEY = process.env.PHISHTANK_API_KEY || "";
const API_URL = "https://checkurl.phishtank.com/checkurl/";
const TIMEOUT_MS = 5000;

// Mock PhishTank database (for when API key is not available)
const MOCK_PHISHING_URLS = new Set([
  "http://secure-paypal-login.xyz/verify",
  "http://amazon-account-suspended.tk/billing",
  "http://login-verify-bank.ml/confirm",
  "http://google.com.fake-login.ga/signin",
  "http://update-your-account.cf/update",
  "http://192.168.1.1/admin/login",
]);

/**
 * Check a URL against PhishTank.
 *
 * @param {string} url
 * @returns {Promise<object>}
 *   { isPhishing: boolean, verified: boolean, score: number, source: string }
 */
async function checkPhishTank(url) {
  if (API_KEY && API_KEY.length > 5) {
    return _callRealAPI(url);
  }
  return _mockCheck(url);
}

/**
 * Call the real PhishTank API.
 * @param {string} url
 * @returns {Promise<object>}
 */
async function _callRealAPI(url) {
  try {
    // PhishTank requires URL to be base64 encoded
    const encodedUrl = Buffer.from(url).toString("base64");

    const params = new URLSearchParams({
      url: encodedUrl,
      format: "json",
      app_key: API_KEY,
    });

    const response = await axios.post(API_URL, params.toString(), {
      timeout: TIMEOUT_MS,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const data = response.data;
    if (data.results && data.results.in_database) {
      const isPhishing = data.results.valid === true;
      return {
        isPhishing,
        verified: data.results.verified === true,
        phishId: data.results.phish_id,
        score: isPhishing ? 85 : 0,
        source: "phishtank",
      };
    }

    return {
      isPhishing: false,
      verified: false,
      score: 0,
      source: "phishtank",
    };
  } catch (error) {
    console.error("[PhishTank] API error:", error.message);
    return _mockCheck(url);
  }
}

/**
 * Mock PhishTank check.
 * @param {string} url
 * @returns {object}
 */
function _mockCheck(url) {
  const lowerUrl = url.toLowerCase();

  // Check exact mock list
  if (MOCK_PHISHING_URLS.has(url) || MOCK_PHISHING_URLS.has(lowerUrl)) {
    return {
      isPhishing: true,
      verified: true,
      score: 90,
      source: "phishtank_mock",
    };
  }

  // Pattern match for suspicious URLs
  const suspiciousPatterns = [
    /\.xyz\//i,
    /\.tk\//i,
    /\.ml\//i,
    /\.ga\//i,
    /\.cf\//i,
    /secure.*paypal|paypal.*secure/i,
    /amazon.*suspended|suspended.*amazon/i,
    /bank.*verify|verify.*bank/i,
    /login.*secure.*\.(xyz|tk|ml|ga)/i,
  ];

  const matchCount = suspiciousPatterns.filter((p) => p.test(lowerUrl)).length;

  if (matchCount >= 2) {
    return {
      isPhishing: true,
      verified: false,
      score: 65,
      source: "phishtank_mock",
    };
  }

  return {
    isPhishing: false,
    verified: false,
    score: 0,
    source: "phishtank_mock",
  };
}

module.exports = { checkPhishTank };
