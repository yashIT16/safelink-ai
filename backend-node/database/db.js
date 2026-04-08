/**
 * db.js
 * -----
 * SQLite database using sql.js (pure JavaScript — no native build required).
 * Persists data to disk using fs.writeFileSync.
 */

const initSqlJs = require("sql.js");
const fs = require("fs");
const path = require("path");

// ─── Paths ─────────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, "..", "data");
const DB_PATH  = path.join(DATA_DIR, "safelink.db");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/** @type {import('sql.js').Database} */
let db = null;

/**
 * Persist in-memory DB to disk after each write.
 */
function persist() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err) {
    console.error("[DB] Persist error:", err.message);
  }
}

/**
 * Run a single SQL statement (no rows returned).
 * @param {string} sql
 * @param {any[]} [params]
 */
function run(sql, params = []) {
  db.run(sql, params);
  persist();
}

/**
 * Get a single row.
 * @param {string} sql
 * @param {any[]} [params]
 * @returns {object|null}
 */
function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

/**
 * Get all matching rows.
 * @param {string} sql
 * @param {any[]} [params]
 * @returns {object[]}
 */
function all(sql, params = []) {
  const rows = [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

// ─── Seed Data ─────────────────────────────────────────────────────────────────
const SEED_URLS = [
  ["http://secure-paypal-login.xyz/verify",          "phishtank", "phishing"],
  ["http://amazon-account-suspended.tk/billing",     "phishtank", "phishing"],
  ["http://192.168.1.1/admin/login",                 "manual",    "phishing"],
  ["http://login-verify-bank.ml/confirm",            "manual",    "phishing"],
  ["http://google.com.fake-login.ga/signin",         "phishtank", "phishing"],
  ["http://update-your-account.cf/update",           "manual",    "phishing"],
  ["http://fake-amazon-login-2024.xyz/signin",       "auto",      "phishing"],
  ["http://paypal-verify-account.tk/update",         "auto",      "phishing"],
  ["http://secure-bank-login.ml/confirm",            "auto",      "phishing"],
  ["http://netflix-billing-update.ga/payment",       "auto",      "phishing"],
];

const SEED_HASHES = [
  ["44d88612fea8a8f36de82e1278abb02f", "md5",    "eicar.exe",       "malware"],
  ["275a021bbfb6489e54d471899f7db9d1", "md5",    "trojan.exe",      "malware"],
  ["e3b0c44298fc1c149afbf4c8996fb924", "sha256", "ransomware.dll",  "malware"],
];

/**
 * Initialize database: create tables and seed with test data.
 */
async function initDB() {
  const SQL = await initSqlJs();

  // Load existing DB from file, or create new one
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
    console.log(`[DB] Loaded existing database from ${DB_PATH}`);
  } else {
    db = new SQL.Database();
    console.log(`[DB] Created new database at ${DB_PATH}`);
  }

  // ── Create tables ──────────────────────────────────────────────────────────
  db.run(`
    CREATE TABLE IF NOT EXISTS blacklisted_urls (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      url         TEXT NOT NULL UNIQUE,
      source      TEXT DEFAULT 'manual',
      threat_type TEXT DEFAULT 'phishing',
      added_at    TEXT DEFAULT (datetime('now')),
      expires_at  TEXT
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS phishing_urls (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      url          TEXT NOT NULL UNIQUE,
      ai_score     REAL DEFAULT 0.0,
      risk_score   INTEGER DEFAULT 0,
      source       TEXT DEFAULT 'ai',
      confirmed    INTEGER DEFAULT 0,
      added_at     TEXT DEFAULT (datetime('now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS file_hashes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      hash        TEXT NOT NULL UNIQUE,
      hash_type   TEXT DEFAULT 'md5',
      filename    TEXT,
      threat_type TEXT DEFAULT 'malware',
      source      TEXT DEFAULT 'manual',
      added_at    TEXT DEFAULT (datetime('now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scan_logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_type   TEXT NOT NULL,
      target      TEXT NOT NULL,
      risk_score  INTEGER DEFAULT 0,
      verdict     TEXT DEFAULT 'safe',
      details     TEXT,
      scanned_at  TEXT DEFAULT (datetime('now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS update_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      source     TEXT NOT NULL,
      urls_added INTEGER DEFAULT 0,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Seed phishing URLs
  for (const [url, source, threat] of SEED_URLS) {
    db.run(
      `INSERT OR IGNORE INTO blacklisted_urls (url, source, threat_type) VALUES (?, ?, ?)`,
      [url, source, threat]
    );
  }

  // Seed known file hashes
  for (const [hash, type, filename, threat] of SEED_HASHES) {
    db.run(
      `INSERT OR IGNORE INTO file_hashes (hash, hash_type, filename, threat_type) VALUES (?, ?, ?, ?)`,
      [hash, type, filename, threat]
    );
  }

  persist();
  console.log("[DB] Tables created and seeded successfully.");
  return db;
}

// ─── Query Helpers ─────────────────────────────────────────────────────────────

function isBlacklisted(url) {
  return get(
    `SELECT * FROM blacklisted_urls WHERE url = ?
     AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1`,
    [url]
  );
}

function addPhishingURL(url, aiScore, riskScore, source = "ai") {
  db.run(
    `INSERT OR REPLACE INTO phishing_urls (url, ai_score, risk_score, source) VALUES (?, ?, ?, ?)`,
    [url, aiScore, riskScore, source]
  );
  persist();
}

function isHashDangerous(hash) {
  return get(`SELECT * FROM file_hashes WHERE hash = ? LIMIT 1`, [hash]);
}

function addFileHash(hash, hashType = "md5", filename = "", threatType = "malware") {
  db.run(
    `INSERT OR IGNORE INTO file_hashes (hash, hash_type, filename, threat_type) VALUES (?, ?, ?, ?)`,
    [hash, hashType, filename, threatType]
  );
  persist();
}

function logScan(scanType, target, riskScore, verdict, details = {}) {
  db.run(
    `INSERT INTO scan_logs (scan_type, target, risk_score, verdict, details) VALUES (?, ?, ?, ?, ?)`,
    [scanType, target, riskScore, verdict, JSON.stringify(details)]
  );
  persist();
}

function bulkAddToBlacklist(urls) {
  let count = 0;
  for (const item of urls) {
    try {
      db.run(
        `INSERT OR IGNORE INTO blacklisted_urls (url, source, threat_type) VALUES (?, ?, ?)`,
        [item.url, item.source || "auto", item.threatType || "phishing"]
      );
      count++;
    } catch {}
  }
  persist();
  return count;
}

function logUpdate(source, urlsAdded) {
  db.run(`INSERT INTO update_log (source, urls_added) VALUES (?, ?)`, [source, urlsAdded]);
  persist();
}

function getRecentScans(limit = 50) {
  return all(`SELECT * FROM scan_logs ORDER BY scanned_at DESC LIMIT ?`, [limit]);
}

function getStats() {
  const blacklisted = get("SELECT COUNT(*) as count FROM blacklisted_urls");
  const phishing    = get("SELECT COUNT(*) as count FROM phishing_urls");
  const hashes      = get("SELECT COUNT(*) as count FROM file_hashes");
  const scans       = get("SELECT COUNT(*) as count FROM scan_logs");

  return {
    blacklisted_urls: blacklisted?.count ?? 0,
    phishing_urls:    phishing?.count    ?? 0,
    file_hashes:      hashes?.count      ?? 0,
    total_scans:      scans?.count       ?? 0,
  };
}

module.exports = {
  initDB,
  isBlacklisted,
  addPhishingURL,
  isHashDangerous,
  addFileHash,
  logScan,
  bulkAddToBlacklist,
  logUpdate,
  getRecentScans,
  getStats,
};
