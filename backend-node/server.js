/**
 * server.js
 * ---------
 * SafeLink AI - Node.js Express Backend
 *
 * Starts the API server, initializes the database, and begins
 * the auto-updater for phishing feeds.
 *
 * Usage:
 *   npm start          (production)
 *   npm run dev        (development with nodemon)
 */

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const path = require("path");

// Internal modules
const { initDB } = require("./database/db");
const scanRouter = require("./routes/scan");
const { startAutoUpdater, getStatus: getUpdaterStatus } = require("./services/autoUpdater");
const { checkHealth: checkAIHealth } = require("./services/aiService");

// ─── App Configuration ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || "development";

const app = express();

// ─── Security Middleware ───────────────────────────────────────────────────────
app.use(helmet());

// CORS – allow Chrome extension and local development
app.use(cors({
  origin: [
    "chrome-extension://*",     // Chrome extensions
    "http://localhost:3000",    // Local dev
    "http://localhost:5173",    // Vite dev
    "*",                        // Allow all for development
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Rate limiting – prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,                  // Max 200 requests per window
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ─── General Middleware ────────────────────────────────────────────────────────
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// HTTP request logging (skip in test)
if (NODE_ENV !== "test") {
  app.use(morgan("dev"));
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get("/health", async (req, res) => {
  const aiHealthy = await checkAIHealth();
  const updaterStatus = getUpdaterStatus();

  res.json({
    status: "ok",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    services: {
      node_backend: "running",
      flask_ai: aiHealthy ? "running" : "unavailable (using heuristic fallback)",
      database: "connected",
      auto_updater: updaterStatus.isRunning ? "running" : "stopped",
      last_update: updaterStatus.lastUpdateTime,
    },
  });
});

// API routes
app.use("/api", scanRouter);

// Backward compatibility (without /api prefix)
app.use("/", scanRouter);

// ─── Error Handlers ───────────────────────────────────────────────────────────

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    availableEndpoints: [
      "POST /scan-url",
      "POST /scan-file",
      "GET  /stats",
      "GET  /history",
      "GET  /health",
    ],
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("[Server Error]", err.stack);
  res.status(500).json({
    error: "Internal server error",
    message: NODE_ENV === "development" ? err.message : "Something went wrong",
  });
});

// ─── Startup ──────────────────────────────────────────────────────────────────

async function start() {
  try {
    // Initialize database (async with sql.js)
    console.log("[Server] Initializing database...");
    await initDB();

    // Start auto-updater (every 6 hours)
    console.log("[Server] Starting auto-updater...");
    startAutoUpdater("0 */6 * * *");

    // Start HTTP server
    app.listen(PORT, () => {
      console.log(`
╔══════════════════════════════════════════╗
║       SafeLink AI Backend Server         ║
╠══════════════════════════════════════════╣
║  Status : Running                        ║
║  Port   : ${PORT}                           ║
║  Mode   : ${NODE_ENV.padEnd(28)}  ║
╠══════════════════════════════════════════╣
║  API Endpoints:                          ║
║   POST /scan-url                         ║
║   POST /scan-file                        ║
║   GET  /stats                            ║
║   GET  /history                          ║
║   GET  /health                           ║
╚══════════════════════════════════════════╝
      `);
    });
  } catch (error) {
    console.error("[Server] Failed to start:", error);
    process.exit(1);
  }
}

start();

module.exports = app; // for testing
