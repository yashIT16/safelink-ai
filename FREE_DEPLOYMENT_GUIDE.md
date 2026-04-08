# ☁️ The 100% Free Cloud Deployment Guide

Because you chose **Option B**, you are keeping the incredibly powerful Node.js SQLite server and the full-scale Python Random Forest AI engine. 

To ensure you never have to pay a single dollar when you release this tool to the public, you need to host these servers on the internet using "Free Tier" cloud providers.

Here is exactly how you deploy both servers to the cloud for free:

---

## 🐍 1. Hosting the Python AI Model (PythonAnywhere)
The ML model is perfectly suited for PythonAnywhere, an amazing free hosting service for Flask APIs.

1. Go to [PythonAnywhere.com](https://www.pythonanywhere.com/) and create a free "Beginner" account.
2. In your dashboard, go to the **Web** tab and click **Add a new web app**.
3. Choose **Flask** and select **Python 3.9**.
4. In the "Files" tab, upload your entire `ml-model-python` folder (including `model.pkl` and `app.py`).
5. Your AI is now permanently hosted online! (e.g. `https://yashIT16.pythonanywhere.com/predict-url`).

---

## 🟢 2. Hosting the Node.js Backend (Render.com)
Render provides one of the best free tiers for Node servers. It will run your Express server and SQLite database beautifully.

1. Create a free account at [Render.com](https://render.com).
2. Click **New +** and select **Web Service**.
3. Connect your GitHub account and select the `safelink-ai` repository.
4. Set the **Root Directory** to `backend-node`.
5. Set the **Build Command** to `npm install`.
6. Set the **Start Command** to `npm start`.
7. Click "Create Web Service". Render will boot up your backend and give you a free URL (e.g. `https://safelink-backend-app.onrender.com`).

*(Note: Free Render servers "go to sleep" after 15 minutes of inactivity. The first scan of the day might take 10 seconds to wake the server up, but it will be lightning fast after that!)*

---

## 🔗 3. Connecting Your Chrome Extension
Once both of your servers are successfully running in the cloud, you need to tell your Chrome extension to stop looking at `localhost`.

1. Open `extension/background/background.js` and `extension/popup/popup.js`.
2. Change the `BACKEND_URL` variable at the very top:
```javascript
// OLD:
const BACKEND_URL = "http://localhost:3001";

// NEW:
const BACKEND_URL = "https://safelink-backend-app.onrender.com"; // (Replace with your actual Render URL)
```
3. Open `backend-node/services/aiService.js` and change the Python target to your PythonAnywhere URL.
4. **Pack your extension (.crx)** and upload it using your OTA Updates trick! 

You now have a massive, public Artificial Intelligence security tool deployed globally for **$0.00**.
