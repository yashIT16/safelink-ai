/**
 * content.js
 * ----------
 * SafeLink AI content script — injected into every page.
 *
 * Listens for messages from the background worker and injects
 * warning overlays for suspicious or malicious pages.
 */

(function () {
  "use strict";

  // Prevent double-injection
  if (window.__safeLinkAIInjected) return;
  window.__safeLinkAIInjected = true;

  let warningBanner = null;
  let warningOverlay = null;

  // ─── Message Listener ──────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SHOW_WARNING") {
      showWarningBanner(message.verdict, message.riskScore, message.explanation);
      sendResponse({ success: true });
    }
    if (message.type === "REMOVE_WARNING") {
      removeWarning();
      sendResponse({ success: true });
    }
  });

  // ─── Warning Banner ────────────────────────────────────────────────────────

  /**
   * Inject a warning banner at the top of the page.
   */
  function showWarningBanner(verdict, riskScore, explanation) {
    // Remove existing warning if present
    removeWarning();

    const isMalicious = verdict === "malicious";

    // Create overlay backdrop (for malicious pages)
    if (isMalicious) {
      warningOverlay = document.createElement("div");
      warningOverlay.id = "safelink-overlay";
      document.body.appendChild(warningOverlay);
    }

    // Create banner
    warningBanner = document.createElement("div");
    warningBanner.id = "safelink-warning-banner";
    warningBanner.setAttribute("data-verdict", verdict);

    const emoji     = isMalicious ? "🚨" : "⚠️";
    const title     = isMalicious ? "MALICIOUS PAGE DETECTED" : "SUSPICIOUS PAGE";
    const scoreColor = isMalicious ? "#ef4444" : "#f59e0b";
    const bgColor   = isMalicious
      ? "linear-gradient(135deg, #1a0505 0%, #2d0a0a 100%)"
      : "linear-gradient(135deg, #1a1205 0%, #2d2006 100%)";
    const borderColor = isMalicious ? "#ef4444" : "#f59e0b";

    warningBanner.innerHTML = `
      <div class="sl-banner-inner">
        <div class="sl-banner-left">
          <div class="sl-banner-icon">${emoji}</div>
          <div class="sl-banner-content">
            <div class="sl-banner-title">${title}</div>
            <div class="sl-banner-desc">${escapeHtml(explanation || "This page may be dangerous.")}</div>
          </div>
        </div>
        <div class="sl-banner-right">
          <div class="sl-score-badge" style="color:${scoreColor}">
            <span class="sl-score-num">${riskScore}</span>
            <span class="sl-score-label">/100</span>
          </div>
          ${isMalicious
            ? `<button class="sl-btn sl-btn-danger" id="sl-go-back">← Go Back</button>`
            : `<button class="sl-btn sl-btn-warn" id="sl-continue">Continue Anyway</button>`
          }
          <button class="sl-btn sl-btn-dismiss" id="sl-dismiss">✕</button>
        </div>
      </div>
    `;

    // Apply inline styles for the banner container
    Object.assign(warningBanner.style, {
      position:   "fixed",
      top:        "0",
      left:       "0",
      right:      "0",
      zIndex:     "2147483647",
      background: bgColor,
      borderBottom: `2px solid ${borderColor}`,
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', sans-serif",
      boxShadow:  "0 4px 40px rgba(0,0,0,0.6)",
      animation:  "sl-slide-in 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)",
    });

    document.body.prepend(warningBanner);

    // Shift page content down so banner doesn't overlap
    const bannerHeight = warningBanner.offsetHeight + 4;
    document.documentElement.style.setProperty(
      "--safelink-banner-height",
      `${bannerHeight}px`
    );
    document.body.style.paddingTop = `${bannerHeight}px`;

    // ─── Event listeners ──────────────────────────────────────────────────
    const dismissBtn = document.getElementById("sl-dismiss");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", removeWarning);
    }

    const backBtn = document.getElementById("sl-go-back");
    if (backBtn) {
      backBtn.addEventListener("click", () => {
        window.history.back();
        // If no history, go to new tab page
        setTimeout(() => {
          window.location.href = "https://www.google.com";
        }, 500);
      });
    }

    const continueBtn = document.getElementById("sl-continue");
    if (continueBtn) {
      continueBtn.addEventListener("click", removeWarning);
    }

    // Auto-dismiss suspicious (not malicious) after 15 seconds
    if (!isMalicious) {
      setTimeout(() => {
        if (warningBanner && document.body.contains(warningBanner)) {
          removeWarning();
        }
      }, 15000);
    }
  }

  /**
   * Remove the warning banner and overlay.
   */
  function removeWarning() {
    if (warningBanner) {
      warningBanner.style.animation = "sl-slide-out 0.25s ease forwards";
      setTimeout(() => {
        warningBanner?.remove();
        warningBanner = null;
        document.body.style.paddingTop = "";
      }, 250);
    }
    if (warningOverlay) {
      warningOverlay.remove();
      warningOverlay = null;
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

})();
