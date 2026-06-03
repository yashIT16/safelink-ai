// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = decodeURIComponent(params.get("url") || "Unknown URL");
const riskScore  = params.get("score") || "99";

// Populate values
document.getElementById("blockedUrl").textContent = blockedUrl;
document.getElementById("riskScore").textContent  = riskScore;

// Go back button
document.getElementById("goBackBtn").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "https://www.google.com";
  }
});

// Ignore danger (allow user to override)
document.getElementById("ignoreBtnDanger").addEventListener("click", () => {
  const confirmed = window.confirm(
    "⚠️ WARNING: This page is flagged as MALICIOUS.\n\n" +
    "Proceeding may expose your personal data, passwords, or device to malware.\n\n" +
    "Are you ABSOLUTELY sure you want to continue?"
  );
  if (confirmed) {
    // Tell the background service worker to temporarily whitelist this URL
    chrome.runtime.sendMessage({ type: "IGNORE_URL", url: blockedUrl }, () => {
      // Navigate to the dangerous URL
      window.location.href = blockedUrl;
    });
  }
});

// Count-up animation for score
const scoreEl = document.getElementById("riskScore");
const targetScore = parseInt(riskScore, 10) || 99;
let current = 0;
const interval = setInterval(() => {
  current = Math.min(current + 3, targetScore);
  scoreEl.textContent = current;
  if (current >= targetScore) clearInterval(interval);
}, 20);
