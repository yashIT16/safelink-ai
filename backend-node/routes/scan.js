/**
 * scan.js
 * -------
 * Express router for URL and file scanning API endpoints.
 *
 * POST /scan-url   - Scan a URL for threats
 * POST /scan-file  - Scan a file by name/hash for threats
 * GET  /stats      - Get database statistics
 * GET  /history    - Get recent scan history
 */

const express = require("express");
const router = express.Router();
const crypto = require("crypto");

const { predictURL } = require("../services/aiService");
const { checkSafeBrowsing } = require("../services/safeBrowsing");
const { checkPhishTank } = require("../services/phishTank");
const { checkDNS } = require("../services/dnsCheck");
const { computeRiskScore, computeFileRisk } = require("../services/riskScorer");
const { scanDownload } = require("../services/fileScanner");
const db = require("../database/db");

// ─── POST /scan-url ────────────────────────────────────────────────────────────

/**
 * @route   POST /scan-url
 * @desc    Scan a URL for phishing, malware, and other threats
 * @body    { url: string }
 * @returns { url, riskScore, verdict, label, explanation, breakdown, actions, sources }
 */
router.post("/scan-url", async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'url' in request body." });
  }

  const trimmedUrl = url.trim();

  // Basic URL validation
  let parsedUrl;
  try {
    parsedUrl = new URL(trimmedUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL format. Include http:// or https://" });
  }

  console.log(`[Scan] URL: ${trimmedUrl}`);

  try {
    // ── Step 1: Check local blacklist (fastest) ───────────────────────────────
    const blacklistHit = db.isBlacklisted(trimmedUrl);

    if (blacklistHit) {
      const result = computeRiskScore({
        aiResult: { probability: 1, label: "phishing", confidence: "high", explanation: { risk_factors: [] } },
        sbResult: { isMalicious: true, score: 100 },
        ptResult: { isPhishing: true, score: 100 },
        url: trimmedUrl,
        isBlacklisted: true,
      });

      db.logScan("url", trimmedUrl, result.riskScore, result.verdict, {
        source: "blacklist",
        blacklistEntry: blacklistHit,
      });

      return res.json({
        url: trimmedUrl,
        ...result,
        sources: { blacklist: true, ai: false, googleSB: false, phishTank: false },
        scanTime: new Date().toISOString(),
      });
    }

    // ── Step 2: Run all checks in parallel for speed ──────────────────────────
    const [aiResult, sbResult, ptResult, dnsResult] = await Promise.allSettled([
      predictURL(trimmedUrl),
      checkSafeBrowsing(trimmedUrl),
      checkPhishTank(trimmedUrl),
      checkDNS(parsedUrl.hostname),
    ]);

    const ai = aiResult.status === "fulfilled" ? aiResult.value : { probability: 0, label: "safe", confidence: "low" };
    const sb = sbResult.status === "fulfilled" ? sbResult.value : { isMalicious: false, score: 0 };
    const pt = ptResult.status === "fulfilled" ? ptResult.value : { isPhishing: false, score: 0 };
    const dnsRes = dnsResult.status === "fulfilled" ? dnsResult.value : { resolves: true };

    // ── Step 3: Compute combined risk score ───────────────────────────────────
    const result = computeRiskScore({
      aiResult: ai,
      sbResult: sb,
      ptResult: pt,
      dnsResult: dnsRes,
      url: trimmedUrl,
      isBlacklisted: false,
    });

    // ── Step 4: Store in DB if suspicious/malicious ───────────────────────────
    if (result.verdict !== "safe") {
      db.addPhishingURL(trimmedUrl, ai.probability || 0, result.riskScore, "scan");
    }

    // ── Step 5: Log scan ──────────────────────────────────────────────────────
    db.logScan("url", trimmedUrl, result.riskScore, result.verdict, {
      ai: ai,
      sb: sb,
      pt: pt,
    });

    return res.json({
      url: trimmedUrl,
      ...result,
      sources: {
        blacklist: false,
        ai: ai.source !== "heuristic_fallback",
        googleSB: sb.source === "google_safe_browsing",
        phishTank: pt.source === "phishtank",
        ai_mode: ai.source || "ai_model",
        sb_mode: sb.source || "unknown",
        pt_mode: pt.source || "unknown",
      },
      scanTime: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[Scan URL Error]", error);
    return res.status(500).json({ error: "Internal server error during scan." });
  }
});

// ─── POST /scan-file ───────────────────────────────────────────────────────────

/**
 * @route   POST /scan-file
 * @desc    Scan a file by its name and optional hash, or download it from a URL and hash it
 * @body    { filename: string, hash?: string, url?: string }
 * @returns { filename, riskScore, verdict, explanation, fileExtension, hashes }
 */
router.post("/scan-file", async (req, res) => {
  const { filename, hash, url } = req.body;

  if (!filename || typeof filename !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'filename'" });
  }

  console.log(`[Scan] File: ${filename} | URL: ${url} | Hash: ${hash || "not provided"}`);

  try {
    if (url) {
      // Stream download to check actual file hash dynamically
      const scanResult = await scanDownload(url);
      if (scanResult.verdict === "error") {
        return res.status(500).json({ error: "Failed to fetch file for scanning" });
      }
      return res.json({
        filename,
        url,
        ...scanResult,
        scanTime: new Date().toISOString(),
      });
    }

    // Fallback: Check hash against known malicious hashes manually
    let isHashDangerous = false;
    if (hash) {
      const hashHit = db.isHashDangerous(hash);
      isHashDangerous = hashHit !== null;
    }

    const result = computeFileRisk(filename, hash || null, isHashDangerous);

    // Log the scan
    db.logScan("file", filename, result.riskScore, result.verdict, {
      hash,
      isHashDangerous,
      fileExtension: result.fileExtension,
    });

    return res.json({
      filename,
      hash: hash || null,
      ...result,
      scanTime: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[Scan File Error]", error);
    return res.status(500).json({ error: "Internal server error during file scan." });
  }
});

// ─── GET /stats ────────────────────────────────────────────────────────────────

/**
 * @route   GET /stats
 * @desc    Get database statistics
 */
router.get("/stats", (req, res) => {
  try {
    const stats = db.getStats();
    return res.json(stats);
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch stats." });
  }
});

// ─── GET /history ──────────────────────────────────────────────────────────────

/**
 * @route   GET /history
 * @desc    Get recent scan history
 * @query   limit (default: 20)
 */
router.get("/history", (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const scans = db.getRecentScans(limit);
    return res.json({ scans, count: scans.length });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch history." });
  }
});

module.exports = router;
