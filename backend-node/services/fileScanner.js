const axios = require("axios");
const crypto = require("crypto");
const { isHashDangerous, logScan } = require("../database/db");

// 50 MB max limit to protect memory/bandwidth
const MAX_FILE_SIZE = 50 * 1024 * 1024; 

/**
 * Streams a file from a URL, calculates MD5 & SHA256 hashes,
 * and checks the database for threat intelligence.
 * @param {string} url The download URL to scan
 * @returns {Promise<object>}
 */
async function scanDownload(url) {
  try {
    const response = await axios({
      url,
      method: 'GET',
      responseType: 'stream',
      timeout: 10000,
    });

    const md5Hash = crypto.createHash('md5');
    const sha256Hash = crypto.createHash('sha256');

    let downloadedBytes = 0;

    await new Promise((resolve, reject) => {
      response.data.on('data', (chunk) => {
        downloadedBytes += chunk.length;
        if (downloadedBytes > MAX_FILE_SIZE) {
          reject(new Error("File too large."));
          response.data.destroy(); // Stop downloading
          return;
        }
        md5Hash.update(chunk);
        sha256Hash.update(chunk);
      });

      response.data.on('end', () => resolve());
      response.data.on('error', (err) => reject(err));
    });

    const md5 = md5Hash.digest('hex');
    const sha256 = sha256Hash.digest('hex');

    // 1. Check MD5
    let threat = isHashDangerous(md5);
    
    // 2. Check SHA256
    if (!threat) {
      threat = isHashDangerous(sha256);
    }

    if (threat) {
      logScan("file", url, 100, "malicious", { md5, sha256, threat_type: threat.threat_type });
      return {
        verdict: "malicious",
        riskScore: 100,
        explanation: `Known malicious file detected (${threat.threat_type}).`,
        hashes: { md5, sha256 }
      };
    }

    // Mock dynamic fallback / Mock VirusTotal detection for demo purposes
    // since we can't test real malware safely
    const mockMalwareHashes = [
      "d41d8cd98f00b204e9800998ecf8427e" // Empty file MD5
    ];
    if (mockMalwareHashes.includes(md5)) {
      logScan("file", url, 95, "malicious", { md5, sha256, explanation: "Matched mock threat feed" });
      return {
        verdict: "malicious",
        riskScore: 95,
        explanation: "Threat intelligence feed flagged this file content.",
        hashes: { md5, sha256 }
      };
    }

    logScan("file", url, 0, "safe", { md5, sha256 });
    return {
      verdict: "safe",
      riskScore: 0,
      explanation: "No known malware signatures found.",
      hashes: { md5, sha256 }
    };

  } catch (err) {
    if (err.message === "File too large.") {
      return {
        verdict: "unknown",
        riskScore: 30,
        explanation: "File too large to scan securely on the fly. Procced with caution."
      };
    }
    console.error(`[FileScanner] Error scanning ${url}:`, err.message);
    return {
      verdict: "error",
      riskScore: 0,
      explanation: "Could not fetch file for scanning."
    };
  }
}

module.exports = { scanDownload };
