# 🧠 SafeLink AI: Master Developer Guidebook

This document is your personal encyclopedia for the **SafeLink AI** project. Because this tool handles massive amounts of data, artificial intelligence, and network-level browser interception, the codebase is split into **three massive engines**. 

This guide explains exactly what every incredibly powerful folder and file does.

---

## 🛡️ ENGINE 1: The Chrome Extension
**Location:** `/extension/`
This is the visual shield that blocks the user's browser. It sits natively in Chrome and acts as the "front lines", watching everything the user does and asking the backend if it is safe.

* **`manifest.json`**: The actual DNA of the extension. It tells Google Chrome what permissions your tool needs (like `downloads`, `declarativeNetRequest`, and `storage`).
* **`background/background.js`**: The silent guardian. This script runs invisibly in the browser 24/7. It listens for whenever a user opens a new tab or starts a file download. The moment a user clicks a link, this file snatches the URL and secretly fires it to your Node.js server.
* **`popup/popup.html` & `popup.js`**: The UI the user sees when they click your extension icon in the top right. It contains the beautiful gauge animation, the manual scanner, and the history table.
* **`blocked.html` & `blocked.js`**: The massive red "🚨 WARNING" hijack page. If `background.js` detects a phishing site, it instantly redirects the user's browser to this local page to physically stop them from seeing the virus.
* **`blocked-file.html`**: A similar red warning page that appears specifically when a malicious file download was cancelled.
* **`rules.json`**: The native network blocker rules that physically drop Chrome network packets before they even load.

---

## ⚡ ENGINE 2: The Node.js Express Backend
**Location:** `/backend-node/`
This is your **Command Center**. It sits between the user's browser and the heavy Artificial Intelligence. Its job is to be incredibly fast, check whitelists, and talk to external massive databases (like Google) so we don't have to use the AI on *every* single website.

* **`server.js`**: The master switch. This turns on your API (running on port 3001) so the Chrome Extension can talk to it.
* **`routes/scan.js`**: The traffic controller. When the background script says "is this URL safe?", this file receives the request and starts the threat pipeline.
* **`services/riskScorer.js`**: The Judge. This is one of the most important files. It takes the mathematical AI score, the Google Safe Browsing score, the PhishTank score, and its own heuristics, and fuses them together into a final `0-100` Risk Score.
* **`services/aiService.js`**: Reaches out to your Python ML Model (Engine 3) to ask it what the AI thinks of the URL.
* **`services/safeBrowsing.js` & `phishTank.js`**: The secret agents. These files check the URL against Google's global virus database and the live PhishTank API.
* **`services/fileScanner.js`**: Downloads a tiny chunk of any incoming file the user is downloading, calculates an MD5 hash, and checks if it's a known malware payload.
* **`database/db.js`**: The local memory bank. It checks if the URL is in the local blacklist or whitelist database.
* **`data/top_200k_whitelist.txt`**: A massive text file holding the top 200,000 most popular, safe websites in the world (like youtube.com). If a user visits one of these, Node.js instantly skips the scan so the extension is lightning fast.

---

## 🤖 ENGINE 3: The Python Machine Learning Pipeline
**Location:** `/ml-model-python/`
This is the absolute brain of the operation. This doesn't just check databases—it applies mathematical logic to actually *predict* if a website looks like a threat, even if no human has ever seen the website before.

* **`train_model.py`**: The teacher. When you run this, it takes thousands of URLs, studies them using a Random Forest algorithm, and generates a massive, highly optimized mathematical formula.
* **`generate_dataset.py`**: The raw material. This reaches out to live phishing data feeds on the internet, downloads thousands of active viruses and safe URLs, and formats them so `train_model.py` can study them.
* **`feature_extractor.py`**: The measuring tape. The AI can't read words, it only reads math. This file takes a URL like `http://paypal-login.xyz` and turns it into 22 numbers (e.g., measuring the entropy, counting the dashes, finding the word "login", etc.).
* **`app.py`**: The Python Web Server (Flask). This wraps your AI model in a web interface (running on port 5000), patiently waiting for `backend-node` to send it a set of 22 numbers to predict.
* **`model.pkl`**: The compiled physical brain. This is the output of `train_model.py`. It is a compressed heavy binary file containing the exact decision trees the AI uses.
* **`scaler.pkl`**: A statistical normalizer that ensures the 22 numbers are scaled perfectly before `model.pkl` looks at them.

---

## 📁 Root Utilities
**Location:** Main Folder
* **`start_safelink.bat`**: A highly efficient magic button you can double-click to instantly boot up `server.js` (Engine 2) and `app.py` (Engine 3) simultaneously in dual Command Prompts.
* **`AUTO_UPDATE_GUIDE.md`**: Contains the blueprint for how your `updates.xml` file silently beams background code updates to users' laptops without the Chrome Web Store.
* **`FREE_DEPLOYMENT_GUIDE.md`**: Detailed instructions on how to take Engines 2 & 3 and store them permanently on free cloud computers (so you never have to double click `start_safelink.bat` again).
