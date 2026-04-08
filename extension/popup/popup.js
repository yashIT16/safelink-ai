/**
 * popup.js
 * --------
 * SafeLink AI Chrome Extension Popup Logic
 *
 * Features:
 * - Scan current tab URL
 * - Manual URL scanning
 * - Risk gauge animation
 * - Score breakdown display
 * - History tab
 * - Settings management
 */

const BACKEND_URL = "http://localhost:3001";
const SCAN_API = `${BACKEND_URL}/scan-url`;

// ─── DOM Elements ──────────────────────────────────────────────────────────────
const urlInput        = document.getElementById("urlInput");
const scanBtn         = document.getElementById("scanBtn");
const clearBtn        = document.getElementById("clearBtn");
const scanCurrentBtn  = document.getElementById("scanCurrentBtn");
const currentTabUrl   = document.getElementById("currentTabUrl");
const resultsSection  = document.getElementById("resultsSection");

// Gauge elements
const gaugeArc    = document.getElementById("gaugeArc");
const gaugeNeedle = document.getElementById("gaugeNeedle");
const gaugeScore  = document.getElementById("gaugeScore");
const gaugeLabel  = document.getElementById("gaugeLabel");

// Status elements
const statusBanner  = document.getElementById("statusBanner");
const statusIcon    = document.getElementById("statusIcon");
const statusVerdict = document.getElementById("statusVerdict");
const statusUrl     = document.getElementById("statusUrl");

// Explanation
const explanationText = document.getElementById("explanationText");

// Risk factors
const riskFactors     = document.getElementById("riskFactors");
const riskFactorsList = document.getElementById("riskFactorsList");

// Breakdown bars
const aiScore = document.getElementById("aiScore");
const sbScore = document.getElementById("sbScore");
const ptScore = document.getElementById("ptScore");
const hScore  = document.getElementById("hScore");
const aiBar   = document.getElementById("aiBar");
const sbBar   = document.getElementById("sbBar");
const ptBar   = document.getElementById("ptBar");
const hBar    = document.getElementById("hBar");

// Actions
const actionsCard = document.getElementById("actionsCard");
const actionsList = document.getElementById("actionsList");

// Tabs
const tabBtns = document.querySelectorAll(".tab-btn");
const historyPanel  = document.getElementById("historyPanel");
const settingsPanel = document.getElementById("settingsPanel");
const historyList   = document.getElementById("historyList");

// Settings
const settingRealtime     = document.getElementById("settingRealtime");
const settingDownload     = document.getElementById("settingDownload");
const settingBlock        = document.getElementById("settingBlock");
const settingNotifications = document.getElementById("settingNotifications");

const backendStatusVal = document.getElementById("backendStatusVal");
const footerStats      = document.getElementById("footerStats");

// ─── State ────────────────────────────────────────────────────────────────────
let currentTabOriginalUrl = "";
let isScanning = false;
let scanHistory = [];

// ─── Initialization ───────────────────────────────────────────────────────────
async function init() {
  await loadSettings();
  await detectCurrentTab();
  await loadHistory();
  await checkBackendStatus();
}

/**
 * Detect and display the current active tab URL.
 */
async function detectCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabOriginalUrl = tab.url;
      const display = tab.url.length > 55
        ? tab.url.slice(0, 52) + "..."
        : tab.url;
      currentTabUrl.innerHTML = `<span style="color:#94a3b8">${escapeHtml(display)}</span>`;
    } else {
      currentTabUrl.innerHTML = '<span style="color:#475569">Unable to detect URL</span>';
    }
  } catch (err) {
    currentTabUrl.innerHTML = '<span style="color:#475569">Extension context unavailable</span>';
  }
}

// ─── Scanning ─────────────────────────────────────────────────────────────────

/**
 * Main scan function.
 * @param {string} url
 */
async function scanURL(url) {
  if (isScanning) return;
  if (!url || !url.trim()) {
    showError("Please enter a URL to scan.");
    return;
  }

  const trimmedUrl = url.trim();

  // Basic validation
  if (!trimmedUrl.startsWith("http://") && !trimmedUrl.startsWith("https://")) {
    showError('URL must start with http:// or https://');
    return;
  }

  isScanning = true;
  setScanningState(true);
  showResultsSection();
  resetResults();

  try {
    const response = await fetch(SCAN_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: trimmedUrl }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server error: ${response.status}`);
    }

    const data = await response.json();
    displayResults(data, trimmedUrl);
    saveToHistory(trimmedUrl, data.riskScore, data.verdict);
  } catch (err) {
    console.error("[SafeLink AI] Scan error:", err);
    if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
      showError("Cannot connect to SafeLink AI backend.\nMake sure Node.js server is running on port 3001.");
    } else {
      showError(`Scan failed: ${err.message}`);
    }
  } finally {
    isScanning = false;
    setScanningState(false);
  }
}

/**
 * Display scan results in the UI.
 * @param {object} data - Response from backend
 * @param {string} url
 */
function displayResults(data, url) {
  const { riskScore, verdict, label, emoji, explanation, breakdown, actions, ai_risk_factors } = data;

  // Animate gauge
  animateGauge(riskScore, verdict);

  // Status banner
  statusBanner.setAttribute("data-verdict", verdict);
  statusIcon.textContent = emoji || verdictEmoji(verdict);
  statusVerdict.textContent = `${label} — Score: ${riskScore}/100`;
  statusVerdict.className = `status-verdict verdict-${verdict}`;
  statusUrl.textContent = url;

  // Explanation
  explanationText.textContent = explanation || "Analysis complete.";

  // Risk factors
  if (ai_risk_factors && ai_risk_factors.length > 0 &&
      !ai_risk_factors.includes("No specific red flags detected") &&
      !ai_risk_factors.includes("No obvious red flags")) {
    riskFactors.style.display = "block";
    
    // Add dynamic aggressive styling to highlight malicious content
    if (verdict === "malicious" || verdict === "suspicious") {
      riskFactors.style.backgroundColor = "rgba(239, 68, 68, 0.1)"; // Transparent red
      riskFactors.style.borderLeft = "4px solid #ef4444"; 
      riskFactors.style.padding = "12px";
      riskFactors.style.margin = "12px 0";
      riskFactors.style.borderRadius = "4px";
      const title = riskFactors.querySelector('.risk-factors-title');
      if (title) {
        title.style.color = "#ef4444";
        title.style.fontWeight = "bold";
        title.innerHTML = "🚨 Malicious Content Detected:";
      }
    }

    riskFactorsList.innerHTML = "";
    ai_risk_factors.slice(0, 5).forEach((factor) => {
      const li = document.createElement("li");
      li.textContent = factor;
      li.style.color = "#fca5a5"; 
      li.style.fontSize = "13px";
      li.style.marginBottom = "6px";
      li.style.lineHeight = "1.4";
      riskFactorsList.appendChild(li);
    });
  } else {
    riskFactors.style.display = "none";
  }

  // Score breakdown
  if (breakdown) {
    animateBar(aiScore, aiBar, breakdown.ai_score);
    animateBar(sbScore, sbBar, breakdown.google_sb_score);
    animateBar(ptScore, ptBar, breakdown.phishtank_score);
    animateBar(hScore,  hBar,  breakdown.heuristic_score);
  }

  // Actions
  if (actions && actions.length > 0) {
    actionsCard.style.display = "block";
    actionsCard.setAttribute("data-verdict", verdict);
    actionsList.innerHTML = "";
    actions.forEach((action) => {
      const li = document.createElement("li");
      li.textContent = action;
      actionsList.appendChild(li);
    });
  }
}

/**
 * Animate the gauge widget to show the risk score.
 */
function animateGauge(score, verdict) {
  // Arc: total arc length ≈ 251.2 (half circle circumference for r=80)
  const ARC_LENGTH = 251.2;
  const filled = (score / 100) * ARC_LENGTH;

  // Color based on verdict
  const color = verdict === "safe"
    ? "#22c55e"
    : verdict === "suspicious"
    ? "#f59e0b"
    : "#ef4444";

  gaugeArc.style.stroke = color;
  gaugeArc.setAttribute("stroke-dasharray", `${filled} ${ARC_LENGTH}`);

  // Rotate needle: -90° = 0, 90° = 100%
  const angle = -90 + (score / 100) * 180;
  gaugeNeedle.setAttribute("transform", `rotate(${angle} 100 100)`);

  // Animate score counter
  animateCounter(gaugeScore, 0, score, 700);
  gaugeLabel.textContent = verdict.charAt(0).toUpperCase() + verdict.slice(1);
  gaugeLabel.className = `gauge-label verdict-${verdict}`;
}

/**
 * Animate a number counter.
 */
function animateCounter(el, from, to, duration) {
  const start = performance.now();
  const update = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // cubic ease-out
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

/**
 * Animate a score breakdown bar.
 */
function animateBar(scoreEl, barEl, score) {
  const safeScore = Math.min(Math.max(score || 0, 0), 100);

  // Delay for stagger effect
  setTimeout(() => {
    scoreEl.textContent = `${Math.round(safeScore)}`;
    barEl.style.width = `${safeScore}%`;

    // Color the bar by risk level
    if (safeScore <= 30) {
      barEl.style.background = "linear-gradient(90deg, #22c55e, #166534)";
    } else if (safeScore <= 70) {
      barEl.style.background = "linear-gradient(90deg, #f59e0b, #92400e)";
    } else {
      barEl.style.background = "linear-gradient(90deg, #ef4444, #7f1d1d)";
    }
  }, 150);
}

// ─── UI State Helpers ──────────────────────────────────────────────────────────

function setScanningState(scanning) {
  if (scanning) {
    scanBtn.classList.add("loading");
    scanBtn.disabled = true;
    scanCurrentBtn.disabled = true;
  } else {
    scanBtn.classList.remove("loading");
    scanBtn.disabled = false;
    scanCurrentBtn.disabled = false;
  }
}

function showResultsSection() {
  resultsSection.style.display = "block";
}

function resetResults() {
  gaugeScore.textContent = "--";
  gaugeLabel.textContent = "Scanning...";
  gaugeArc.setAttribute("stroke-dasharray", "0 251.2");
  statusBanner.removeAttribute("data-verdict");
  statusIcon.textContent = "🔍";
  statusVerdict.textContent = "Analyzing...";
  statusVerdict.className = "status-verdict";
  statusUrl.textContent = "";
  explanationText.textContent = "Running threat analysis...";
  riskFactors.style.display = "none";
  actionsCard.style.display = "none";
  aiScore.textContent = "--"; sbScore.textContent = "--";
  ptScore.textContent = "--"; hScore.textContent = "--";
  aiBar.style.width = "0%"; sbBar.style.width = "0%";
  ptBar.style.width = "0%"; hBar.style.width = "0%";
}

function showError(message) {
  resultsSection.style.display = "block";
  gaugeScore.textContent = "!";
  gaugeLabel.textContent = "Error";
  gaugeArc.style.stroke = "#ef4444";
  statusBanner.setAttribute("data-verdict", "malicious");
  statusIcon.textContent = "❌";
  statusVerdict.textContent = "Scan Failed";
  explanationText.textContent = message;
  riskFactors.style.display = "none";
  actionsCard.style.display = "none";
}

function verdictEmoji(verdict) {
  return { safe: "✅", suspicious: "⚠️", malicious: "🚨" }[verdict] || "🔍";
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── History ──────────────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const stored = await chrome.storage.local.get("scanHistory");
    scanHistory = stored.scanHistory || [];
    renderHistory();
  } catch {}
}

function saveToHistory(url, score, verdict) {
  const entry = {
    url,
    score,
    verdict,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  };
  scanHistory.unshift(entry);
  if (scanHistory.length > 20) scanHistory.pop();
  chrome.storage.local.set({ scanHistory }).catch(() => {});
  renderHistory();
}

function renderHistory() {
  historyList.innerHTML = "";

  if (scanHistory.length === 0) {
    historyList.innerHTML = '<div class="empty-state">No recent scans</div>';
    return;
  }

  footerStats.textContent = `${scanHistory.length} URLs scanned`;

  scanHistory.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "history-item";
    item.innerHTML = `
      <div class="history-verdict-dot ${entry.verdict}"></div>
      <div class="history-info">
        <div class="history-url">${escapeHtml(entry.url)}</div>
        <div class="history-meta">${entry.time} · ${entry.verdict.toUpperCase()}</div>
      </div>
      <div class="history-score ${entry.verdict}">${entry.score}</div>
    `;
    item.title = entry.url;
    item.addEventListener("click", () => {
      urlInput.value = entry.url;
      clearBtn.style.display = "block";
      switchTab("scanner");
    });
    historyList.appendChild(item);
  });
}

// ─── Settings ─────────────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const settings = await chrome.storage.local.get([
      "realtime", "download", "block", "notifications"
    ]);
    settingRealtime.checked = settings.realtime !== false;
    settingDownload.checked = settings.download !== false;
    settingBlock.checked    = settings.block !== false;
    settingNotifications.checked = settings.notifications !== false;
  } catch {}
}

async function saveSettings() {
  try {
    await chrome.storage.local.set({
      realtime:      settingRealtime.checked,
      download:      settingDownload.checked,
      block:         settingBlock.checked,
      notifications: settingNotifications.checked,
    });
    // Notify background script of settings change
    chrome.runtime.sendMessage({
      type: "SETTINGS_UPDATED",
      settings: {
        realtime:      settingRealtime.checked,
        download:      settingDownload.checked,
        block:         settingBlock.checked,
        notifications: settingNotifications.checked,
      }
    }).catch(() => {});
  } catch {}
}

// ─── Backend Status ────────────────────────────────────────────────────────────

async function checkBackendStatus() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(`${BACKEND_URL}/health`, { signal: controller.signal });
    clearTimeout(timeout);

    if (response.ok) {
      backendStatusVal.textContent = "Online ✓";
      backendStatusVal.className = "bs-value online";
    } else {
      throw new Error("Non-OK response");
    }
  } catch {
    backendStatusVal.textContent = "Offline ✗";
    backendStatusVal.className = "bs-value offline";
  }
}

// ─── Tab Navigation ───────────────────────────────────────────────────────────

function switchTab(tabName) {
  tabBtns.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });

  resultsSection.style.display  = tabName === "scanner" ? (resultsSection.children.length > 0 ? "block" : "none") : "none";
  historyPanel.style.display    = tabName === "history"  ? "block" : "none";
  settingsPanel.style.display   = tabName === "settings" ? "block" : "none";

  if (tabName === "settings") checkBackendStatus();
  if (tabName === "history") renderHistory();
}

// ─── Event Listeners ──────────────────────────────────────────────────────────

// Scan button
scanBtn.addEventListener("click", () => {
  scanURL(urlInput.value);
});

// Enter key
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") scanURL(urlInput.value);
});

// Show/hide clear button
urlInput.addEventListener("input", () => {
  clearBtn.style.display = urlInput.value.length > 0 ? "block" : "none";
});

// Clear button
clearBtn.addEventListener("click", () => {
  urlInput.value = "";
  clearBtn.style.display = "none";
  urlInput.focus();
});

// Scan current tab
scanCurrentBtn.addEventListener("click", () => {
  if (currentTabOriginalUrl) {
    urlInput.value = currentTabOriginalUrl;
    clearBtn.style.display = "block";
    switchTab("scanner");
    scanURL(currentTabOriginalUrl);
  }
});

// Tab switching
tabBtns.forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// Settings toggles
[settingRealtime, settingDownload, settingBlock, settingNotifications].forEach(
  (toggle) => toggle.addEventListener("change", saveSettings)
);

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();
