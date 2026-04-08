/**
 * aiService.js
 * ------------
 * Calls the Python Flask ML API to predict if a URL is phishing.
 */

const axios = require("axios");

const FLASK_API_URL = process.env.FLASK_API_URL || "http://localhost:5001";
const TIMEOUT_MS = 5000;

/**
 * Call the Flask ML model API to predict a URL.
 *
 * @param {string} url - The URL to analyze
 * @returns {Promise<object>} ML prediction result
 *   {
 *     prediction: 0 | 1,
 *     label: "safe" | "phishing",
 *     probability: 0.0–1.0,
 *     confidence: "low" | "medium" | "high",
 *     explanation: { summary, risk_factors, feature_values }
 *   }
 */
async function predictURL(url) {
  try {
    const response = await axios.post(
      `${FLASK_API_URL}/predict-url`,
      { url },
      {
        timeout: TIMEOUT_MS,
        headers: { "Content-Type": "application/json" },
      }
    );

    return {
      success: true,
      ...response.data,
    };
  } catch (error) {
    if (error.code === "ECONNREFUSED") {
      console.warn("[AI] Flask API unavailable, using heuristic fallback");
      return _heuristicFallback(url);
    }

    if (error.response) {
      console.error(`[AI] Flask API error: ${error.response.status}`, error.response.data);
    } else {
      console.error("[AI] Request failed:", error.message);
    }

    return _heuristicFallback(url);
  }
}

/**
 * Heuristic fallback when Flask API is unavailable.
 * Uses simple URL pattern matching.
 *
 * @param {string} url
 * @returns {object}
 */
function _heuristicFallback(url) {
  const lowerUrl = url.toLowerCase();

  const PHISHING_KEYWORDS = [
    "login", "verify", "secure", "bank", "account", "update",
    "confirm", "billing", "alert", "suspended", "validate",
    "paypal", "ebay", "password", "credential",
  ];

  const SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq"];

  let score = 0;
  const riskFactors = [];

  if (!lowerUrl.startsWith("https://")) {
    score += 15;
    riskFactors.push("URL does not use HTTPS");
  }

  if (lowerUrl.includes("@")) {
    score += 25;
    riskFactors.push('URL contains "@" symbol');
  }

  const keywordMatches = PHISHING_KEYWORDS.filter((kw) => lowerUrl.includes(kw));
  if (keywordMatches.length > 0) {
    score += Math.min(30, keywordMatches.length * 10);
    riskFactors.push(`Contains suspicious keywords: ${keywordMatches.join(", ")}`);
  }

  if (SUSPICIOUS_TLDS.some((tld) => lowerUrl.includes(tld))) {
    score += 20;
    riskFactors.push("Uses suspicious TLD (.xyz, .tk, .ml, etc.)");
  }

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lowerUrl)) {
    score += 30;
    riskFactors.push("Domain is an IP address");
  }

  const probability = Math.min(score / 100, 0.99);
  const prediction = probability > 0.5 ? 1 : 0;

  return {
    success: true,
    source: "heuristic_fallback",
    prediction,
    label: prediction === 1 ? "phishing" : "safe",
    probability,
    confidence: "low",
    explanation: {
      summary: riskFactors.length > 0
        ? "Heuristic analysis detected suspicious patterns."
        : "No obvious red flags detected (heuristic mode).",
      risk_factors: riskFactors.length > 0 ? riskFactors : ["No obvious red flags"],
    },
  };
}

/**
 * Check Flask API health.
 * @returns {Promise<boolean>}
 */
async function checkHealth() {
  try {
    const res = await axios.get(`${FLASK_API_URL}/health`, { timeout: 2000 });
    return res.data.status === "ok";
  } catch {
    return false;
  }
}

module.exports = { predictURL, checkHealth };
