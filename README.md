# SafeLink AI 🛡️

**AI-Powered Phishing & Malware Protection Chrome Extension | Made by Yash IT16**

A production-ready cybersecurity tool combining a Chrome Extension, Node.js backend, Python Flask ML API, and SQLite database — similar to VirusTotal and McAfee, with an AI-based phishing detection engine.

---

## 📁 Folder Structure

```
safelink-ai/
├── extension/                    # Chrome Extension
│   ├── manifest.json             # Manifest V3
│   ├── blocked.html              # Page shown when URL is blocked
│   ├── popup/
│   │   ├── popup.html            # Extension popup UI
│   │   ├── popup.css             # Dark premium styling
│   │   └── popup.js              # Popup logic
│   ├── background/
│   │   └── background.js         # Service worker (real-time protection)
│   ├── content/
│   │   ├── content.js            # Page warning overlay
│   │   └── content.css           # Warning styles
│   └── icons/
│       ├── create_icons.py       # Icon generator script
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── backend-node/                 # Node.js Express Backend
│   ├── server.js                 # Main server entry point
│   ├── package.json
│   ├── .env.example              # Environment variables template
│   ├── routes/
│   │   └── scan.js               # POST /scan-url, POST /scan-file
│   ├── database/
│   │   └── db.js                 # SQLite setup & queries
│   └── services/
│       ├── aiService.js          # Calls Flask ML API
│       ├── safeBrowsing.js       # Google Safe Browsing API
│       ├── phishTank.js          # PhishTank API
│       ├── riskScorer.js         # Combined risk scoring (0-100)
│       └── autoUpdater.js        # Periodic phishing feed updates
│
└── ml-model-python/              # Python ML Model + Flask API
    ├── generate_dataset.py       # Generates synthetic training data
    ├── feature_extractor.py      # URL feature extraction
    ├── train_model.py            # Train & save model
    ├── app.py                    # Flask API (POST /predict-url)
    └── requirements.txt
```

---

## 🚀 Quick Setup (Step-by-Step)

### Prerequisites
- Python 3.9+ with pip
- Node.js 18+ with npm
- Any Chromium-based browser (Google Chrome, Microsoft Edge, Brave, Opera)

---

### Step 1: Train & Start the Flask ML API

**For Windows (PowerShell/CMD):**
```bash
cd safelink-ai\ml-model-python
pip install -r requirements.txt
python generate_dataset.py
python train_model.py
python app.py
```

**For Linux (Terminal):**
```bash
cd safelink-ai/ml-model-python
pip3 install -r requirements.txt
python3 generate_dataset.py
python3 train_model.py
python3 app.py
```

Flask will start on **http://localhost:5000** (or 5001).

---

### Step 2: Start the Node.js Backend

**For Windows:**
```bash
cd safelink-ai\backend-node
npm install
copy .env.example .env
npm start
```

**For Linux:**
```bash
cd safelink-ai/backend-node
npm install
cp .env.example .env
npm start
```

Server will start on **http://localhost:3001**

---

### Step 3: Generate Extension Icons

Create the icons needed for the browser toolbar.

**Windows/Linux:**
```bash
cd safelink-ai/extension/icons
python create_icons.py  # Use python3 on Linux
```

---

### Step 4: Load Extension into your Browser

SafeLink AI is compatible with all modern Chromium-based browsers. You will need to "side-load" the extension.

**Google Chrome / Brave:**
1. Open your browser and navigate to `chrome://extensions/` (or `brave://extensions/`).
2. Toggle **Developer Mode** ON in the top right corner.
3. Click the **"Load unpacked"** button.
4. Select the `safelink-ai/extension/` folder.

**Microsoft Edge:**
1. Navigate to `edge://extensions/`.
2. Toggle **Developer Mode** ON in the bottom left menu.
3. Click **"Load unpacked"**.
4. Select the `safelink-ai/extension/` folder.

**Opera:**
1. Navigate to `opera://extensions`.
2. Toggle **Developer Mode** ON in the top right.
3. Click **"Load unpacked"**.
4. Select the `safelink-ai/extension/` folder.

The SafeLink AI shield icon will appear in your toolbar!

---

## 🔑 API Keys (Optional)

The system works out-of-the-box with **mock API responses**. Add real keys for production:

| Key | Where to Get | .env Variable |
|-----|-------------|---------------|
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | `GOOGLE_SAFE_BROWSING_KEY` |
| PhishTank | [phishtank.com/api_register.php](https://www.phishtank.com/api_register.php) | `PHISHTANK_API_KEY` |

Edit `backend-node/.env`:
```env
GOOGLE_SAFE_BROWSING_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here
```

---

## 🔬 How the Risk Score Works

```
Risk Score (0–100) = Weighted Combination:

  AI Model (40%)         →  ML probability × 100
  Google Safe Browsing (30%) →  0 or 90+ if flagged
  PhishTank (20%)        →  0 or 85+ if confirmed
  URL Heuristics (10%)   →  Pattern analysis score

Score Ranges:
   0–30  = ✅ Safe
  31–70  = ⚠️ Suspicious
  71–100 = 🚨 Malicious
```

---

## 🤖 ML Model Features

The Random Forest classifier uses 14 URL features:

| Feature | Description |
|---------|-------------|
| `url_length` | Total URL character count |
| `num_dots` | Number of dots (.) |
| `has_at` | Contains @ symbol |
| `has_dash_in_domain` | Domain has dashes |
| `has_https` | Uses HTTPS |
| `num_subdomains` | Subdomain count |
| `has_ip_address` | Domain is an IP |
| `num_special_chars` | Count of ?=&%#! |
| `path_length` | URL path length |
| `has_suspicious_keyword` | login/verify/bank/etc. |
| `keyword_count` | Number of suspicious keywords |
| `has_www` | Has www. prefix |
| `num_digits_in_domain` | Digits in domain |
| `domain_length` | Full domain length |

---

## 🌐 API Endpoints

### Node.js Backend (port 3001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan-url` | Scan URL for threats |
| POST | `/scan-file` | Check file by name/hash |
| GET | `/stats` | Database statistics |
| GET | `/history` | Recent scan history |
| GET | `/health` | System health check |

### Flask ML API (port 5001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/predict-url` | AI URL prediction |
| POST | `/batch-predict` | Bulk URL prediction |
| GET | `/health` | API health check |

---

## 🧪 Test URLs

```bash
# Safe URL
curl -X POST http://localhost:3001/scan-url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://www.github.com\"}"

# Phishing URL (from mock blacklist)
curl -X POST http://localhost:3001/scan-url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://secure-paypal-login.xyz/verify\"}"

# Suspicious URL
curl -X POST http://localhost:3001/scan-url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://login-verify-bank.ml/confirm\"}"
```

---

## 🔒 Security Features

| Feature | Status |
|---------|--------|
| Real-time URL scanning | ✅ Active |
| AI phishing detection | ✅ Active |
| Google Safe Browsing check | ✅ Active (mock/real) |
| PhishTank database check | ✅ Active (mock/real) |
| Local blacklist database | ✅ SQLite |
| Download protection | ✅ Active |
| Auto-updates (6hr cycle) | ✅ Active |
| Rate limiting | ✅ 200 req/15min |
| HTTPS enforcement warnings | ✅ Active |

---

## 🔮 Future Improvements

1. **VirusTotal integration** — File hash scanning via VT API
2. **URL reputation scoring** — Use WHOIS data for domain age
3. **BERT/Transformer model** — Replace Random Forest with deep learning
4. **Real PhishTank feed** — Auto-update from verified CSV
5. **User whitelist** — Allow users to save trusted domains
6. **Password breach detection** — HaveIBeenPwned integration
7. **QR code scanning** — Detect phishing QR codes
8. **Mobile companion** — React Native app
9. **Dashboard UI** — Web dashboard for scan analytics
10. **CI/CD pipeline** — Auto-deploy updated models

---

## 📞 Troubleshooting

**Extension not scanning?**
→ Ensure Node.js server is running on port 3001

**Flask API errors?**
→ Run `python train_model.py` first to generate `model.pkl`

**Icons not showing?**
→ Run `python create_icons.py` in the `extension/icons/` folder

**CORS errors?**
→ Backend already has CORS enabled for all origins

---

*Built with ❤️ using Python, Node.js, and Chrome Extension APIs*
