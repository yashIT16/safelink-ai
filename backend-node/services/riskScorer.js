/**
 * riskScorer.js
 * -------------
 * Combines results from AI model, Google Safe Browsing, PhishTank,
 * and URL heuristics into a unified 0–100 risk score.
 *
 * Weights:
 *   AI Model          → 40%
 *   Google Safe Browsing → 30%
 *   PhishTank          → 20%
 *   URL Heuristics     → 10%
 */

const { URL } = require("url");

// Weights for scoring (must sum to 1.0)
const WEIGHTS = {
  ai: 0.40,
  googleSB: 0.30,
  phishTank: 0.20,
  heuristic: 0.10,
};

// Risk score thresholds
const THRESHOLDS = {
  safe: 30,       // 0–30  → Safe
  suspicious: 70, // 31–70 → Suspicious
  // 71–100 → Malicious
};

/**
 * Compute URL-based heuristic score independently.
 * (Supplements ML features with simpler pattern checks.)
 *
 * @param {string} url
 * @returns {number} Score 0–100
 */
function computeHeuristicScore(url) {
  let score = 0;
  const lowerUrl = url.toLowerCase();

  // No HTTPS
  if (!lowerUrl.startsWith("https://")) score += 20;

  // Contains @ symbol
  if (lowerUrl.includes("@")) score += 30;

  // Suspicious TLD
  if (/\.(xyz|tk|ml|ga|cf|gq)(\?|\/|$)/i.test(lowerUrl)) score += 25;

  // IP address domain
  if (/\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lowerUrl)) score += 35;

  // Too many subdomains
  try {
    const parsed = new URL(url);
    const parts = parsed.hostname.split(".");
    if (parts.length > 4) score += 15;
  } catch {
    score += 10; // Malformed URL
  }

  // Dashes in domain (e.g. secure-paypal-login)
  try {
    const parsed = new URL(url);
    const dashCount = (parsed.hostname.match(/-/g) || []).length;
    if (dashCount >= 2) score += 10;
    else if (dashCount === 1) score += 5;
  } catch {}

  // Very long URL
  if (url.length > 100) score += 5;
  if (url.length > 150) score += 10;

  return Math.min(score, 100);
}

/**
 * Combine all sources into a unified risk score.
 *
 * @param {object} params
 * @param {object} params.aiResult       - Result from aiService.predictURL()
 * @param {object} params.sbResult       - Result from safeBrowsing.checkSafeBrowsing()
 * @param {object} params.ptResult       - Result from phishTank.checkPhishTank()
 * @param {object} params.dnsResult      - Result from dnsCheck.checkDNS()
 * @param {string} params.url            - Original URL
 * @param {boolean} params.isBlacklisted - Whether URL is in local blacklist
 * @returns {object}
 *   {
 *     riskScore: number,
 *     verdict: "safe"|"suspicious"|"malicious",
 *     label: string,
 *     color: string,
 *     emoji: string,
 *     explanation: string,
 *     breakdown: object,
 *     actions: string[]
 *   }
 */
const fs = require("fs");
const path = require("path");

// ── Global Domain Allowlist ────────────────────────────────────────────────
const WHITELIST_DOMAINS = new Set([
  "google.com", "www.google.com",
  "linkedin.com", "www.linkedin.com",
  "virustotal.com", "www.virustotal.com",
  "github.com", "www.github.com",
  "microsoft.com", "www.microsoft.com",
  "apple.com", "www.apple.com",
  "amazon.com", "www.amazon.com",
  "netflix.com", "www.netflix.com",
  "facebook.com", "www.facebook.com"
]);

// Load the Top 200,000 domains natively
try {
  const listPath = path.join(__dirname, "..", "data", "top_200k_whitelist.txt");
  if (fs.existsSync(listPath)) {
    const lines = fs.readFileSync(listPath, "utf-8").split("\n");
    for (const line of lines) {
      if (line.trim()) {
        WHITELIST_DOMAINS.add(line.trim());
      }
    }
    console.log(`[RiskScorer] Loaded ${WHITELIST_DOMAINS.size} domains into Global Allowlist.`);
  }
} catch (e) {
  console.error("[RiskScorer] Could not load top 200k whitelist:", e.message);
}

function computeRiskScore({ aiResult, sbResult, ptResult, dnsResult, url, isBlacklisted = false }) {
  // ── Instant block for blacklisted URLs ─────────────────────────────────────
  if (isBlacklisted) {
    return _buildResult(100, {
      ai: 100,
      googleSB: 100,
      phishTank: 100,
      heuristic: 100,
    }, url, "URL is in the local blacklist — confirmed malicious.");
  }

  // ── Instant safe for whitelisted URLs ──────────────────────────────────────
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    
    // Explicitly allow local networks to prevent the tool from flagging itself
    if (hostname === "localhost" || hostname === "127.0.0.1") {
      return _buildResult(0, { ai: 0, googleSB: 0, phishTank: 0, heuristic: 0 }, url, "Local development network URL (System Safe)");
    }

    // Strip www. to match standard global domain lists
    const cleanHostname = hostname.startsWith("www.") ? hostname.substring(4) : hostname;
    
    if (WHITELIST_DOMAINS.has(cleanHostname) || hostname.endsWith(".google.com")) {
      return _buildResult(0, { ai: 0, googleSB: 0, phishTank: 0, heuristic: 0 }, url, "Verified Genuine Website (SafeLink Global Allowlist)");
    }
  } catch(e) {}


  // ── Compute component scores (0–100) ───────────────────────────────────────

  // AI score: convert probability (0-1) to 0-100
  const aiScore = Math.round((aiResult?.probability || 0) * 100);

  // Google Safe Browsing score
  const sbScore = sbResult?.isMalicious ? (sbResult.score || 90) : 0;

  // PhishTank score
  const ptScore = ptResult?.isPhishing ? (ptResult.score || 85) : 0;

  // URL heuristic score
  let heuristicScore = computeHeuristicScore(url);

  // Apply DNS penalty penalty
  if (dnsResult && !dnsResult.resolves) {
    heuristicScore = Math.min(heuristicScore + 30, 100);
  }

  // ── Weighted combination ───────────────────────────────────────────────────
  const weightedScore =
    aiScore * WEIGHTS.ai +
    sbScore * WEIGHTS.googleSB +
    ptScore * WEIGHTS.phishTank +
    heuristicScore * WEIGHTS.heuristic;

  const finalScore = Math.round(Math.min(weightedScore, 100));

  // Build a human-readable explanation
  const explanationParts = [];
  if (aiResult?.explanation?.summary) {
    explanationParts.push(aiResult.explanation.summary);
  }
  if (sbResult?.isMalicious) {
    explanationParts.push(`Google Safe Browsing flagged this as ${sbResult.threatType}.`);
  }
  if (ptResult?.isPhishing) {
    explanationParts.push("PhishTank database confirmed this as a phishing URL.");
  }
  if (dnsResult && !dnsResult.resolves) {
    explanationParts.push("Domain does not resolve to an active IP address, indicating a potential throwaway or sinkhole domain.");
  }
  if (aiResult?.explanation?.risk_factors?.length > 0) {
    const factors = aiResult.explanation.risk_factors.filter(
      (f) => f !== "No specific red flags detected" && f !== "No obvious red flags"
    );
    if (factors.length > 0) {
      explanationParts.push(`Risk factors: ${factors.slice(0, 3).join("; ")}.`);
    }
  }

  const explanation = explanationParts.length > 0
    ? explanationParts.join(" ")
    : "No specific threats detected.";

  return _buildResult(finalScore, {
    ai: aiScore,
    googleSB: sbScore,
    phishTank: ptScore,
    heuristic: heuristicScore,
  }, url, explanation, aiResult);
}

/**
 * Build the standardized result object.
 */
function _buildResult(finalScore, breakdown, url, explanation, aiResult = null) {
  let verdict, label, color, emoji, actions;

  if (finalScore <= THRESHOLDS.safe) {
    verdict = "safe";
    label = "Safe";
    color = "#22c55e";
    emoji = "✅";
    actions = ["This URL appears safe to visit."];
  } else if (finalScore <= THRESHOLDS.suspicious) {
    verdict = "suspicious";
    label = "Suspicious";
    color = "#f59e0b";
    emoji = "⚠️";
    actions = [
      "Proceed with caution.",
      "Do not enter personal information.",
      "Verify the URL is correct before proceeding.",
    ];
  } else {
    verdict = "malicious";
    label = "Malicious";
    color = "#ef4444";
    emoji = "🚨";
    actions = [
      "Do NOT visit this URL.",
      "This URL is likely a phishing or malware site.",
      "Report this URL if encountered.",
    ];
  }

  return {
    riskScore: finalScore,
    verdict,
    label,
    color,
    emoji,
    explanation,
    breakdown: {
      ai_score: breakdown.ai,
      google_sb_score: breakdown.googleSB,
      phishtank_score: breakdown.phishTank,
      heuristic_score: breakdown.heuristic,
      weights: WEIGHTS,
    },
    actions,
    ai_confidence: aiResult?.confidence || "unknown",
    ai_label: aiResult?.label || "unknown",
    ai_probability: aiResult?.probability || 0,
    ai_risk_factors: aiResult?.explanation?.risk_factors || [],
  };
}

/**
 * Assess file risk based on extension and hash.
 *
 * @param {string} filename
 * @param {string|null} hash
 * @param {boolean} isHashDangerous
 * @returns {object}
 */
function computeFileRisk(filename, hash = null, isHashDangerous = false) {
  // High-risk file extensions
  const HIGH_RISK_EXTENSIONS = new Set([
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
    ".msi", ".dll", ".vbs", ".ps1", ".sh", ".jar",
    ".app", ".deb", ".rpm",
  ]);

  const MEDIUM_RISK_EXTENSIONS = new Set([
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".js", ".py", ".php",
  ]);

  const ext = filename.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || "";

  let riskScore = 0;
  let verdict, label, explanation;

  if (isHashDangerous) {
    riskScore = 95;
    verdict = "malicious";
    label = "Malicious";
    explanation = "File hash matches a known malware signature.";
  } else if (HIGH_RISK_EXTENSIONS.has(ext)) {
    riskScore = 65;
    verdict = "suspicious";
    label = "High Risk Extension";
    explanation = `File has a high-risk extension (${ext}). Executable files can contain malware.`;
  } else if (MEDIUM_RISK_EXTENSIONS.has(ext)) {
    riskScore = 30;
    verdict = "suspicious";
    label = "Medium Risk Extension";
    explanation = `File type (${ext}) can contain macros or scripts. Scan before opening.`;
  } else {
    riskScore = 5;
    verdict = "safe";
    label = "Safe";
    explanation = "File extension does not appear to be high-risk.";
  }

  return {
    riskScore,
    verdict,
    label,
    explanation,
    fileExtension: ext,
    hashChecked: hash !== null,
    isHashDangerous,
  };
}

module.exports = {
  computeRiskScore,
  computeFileRisk,
  computeHeuristicScore,
  THRESHOLDS,
};
