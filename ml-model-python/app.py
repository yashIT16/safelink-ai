"""
app.py
------
Flask REST API for SafeLink AI phishing detection.

Endpoints:
    POST /predict-url    - Predict if a URL is phishing
    GET  /health         - Health check

Usage:
    python app.py
"""

import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from feature_extractor import extract_features, FEATURE_NAMES

# ─── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("flask_api.log"),
    ],
)
logger = logging.getLogger("SafeLinkAI")

# ─── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow requests from Chrome extension / Node.js backend

# ─── Load Model ─────────────────────────────────────────────────────────────────
MODEL_FILE = "model.pkl"
SCALER_FILE = "scaler.pkl"

model = None
scaler = None

def load_model():
    """Load the trained model and scaler from disk."""
    global model, scaler
    try:
        if not os.path.exists(MODEL_FILE):
            raise FileNotFoundError(f"Model file '{MODEL_FILE}' not found. Run train_model.py first.")
        if not os.path.exists(SCALER_FILE):
            raise FileNotFoundError(f"Scaler file '{SCALER_FILE}' not found. Run train_model.py first.")

        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        logger.info("✓ Model and scaler loaded successfully")
    except Exception as e:
        logger.error(f"✗ Failed to load model: {e}")
        model = None
        scaler = None


def get_feature_explanation(url: str, features: list, phishing_probability: float) -> dict:
    """
    Generate a human-readable explanation of which features triggered the alert.
    """
    explanations = []
    risk_factors = []

    if features[0] > 75:  # url_length
        risk_factors.append("URL is unusually long")
    if features[2] == 1:  # has_at
        risk_factors.append('URL contains "@" symbol (obfuscation technique)')
    if features[3] == 1:  # has_dash_in_domain
        risk_factors.append('Domain contains "-" (common in fake domains)')
    if features[4] == 0:  # has_https
        risk_factors.append("URL does not use HTTPS (not encrypted)")
    if features[6] == 1:  # has_ip_address
        risk_factors.append("Domain is an IP address (suspicious)")
    if features[9] == 1:  # has_suspicious_keyword
        risk_factors.append(f"URL contains {features[10]} suspicious keyword(s)")
    if features[5] > 2:   # num_subdomains
        risk_factors.append(f"URL has {features[5]} subdomains (domain spoofing)")
    if features[1] > 4:   # num_dots
        risk_factors.append(f"Unusually high number of dots ({features[1]})")
    
    # New V2 features
    if len(features) > 14:
        if features[14] > 4.5: # url_entropy
            risk_factors.append("URL characters appear highly randomized (high entropy)")
        if features[20] == 1: # high_risk_tld
            risk_factors.append("Domain uses a TLD commonly associated with spam/phishing")
        if features[15] > 0.15: # digit_ratio
            risk_factors.append("Unusually high number of digits in the URL")

    if phishing_probability < 0.3:
        summary = "This URL appears legitimate based on our AI analysis."
    elif phishing_probability < 0.6:
        summary = "This URL shows some suspicious characteristics. Proceed with caution."
    else:
        summary = "High phishing probability detected! This URL exhibits multiple red flags."

    return {
        "summary": summary,
        "risk_factors": risk_factors if risk_factors else ["No specific red flags detected"],
        "feature_values": {
            name: val for name, val in zip(FEATURE_NAMES, features)
        }
    }


# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    status = "ok" if model is not None else "model_not_loaded"
    return jsonify({
        "status": status,
        "model_loaded": model is not None,
        "version": "1.0.0"
    })


@app.route("/predict-url", methods=["POST"])
def predict_url():
    """
    Predict if a URL is phishing.

    Request body (JSON):
        { "url": "https://example.com" }

    Response (JSON):
        {
            "url": "...",
            "prediction": 0 | 1,
            "label": "safe" | "phishing",
            "probability": 0.0–1.0,
            "confidence": "low" | "medium" | "high",
            "explanation": { ... },
            "features": { ... }
        }
    """
    if model is None:
        return jsonify({
            "error": "Model not loaded. Please run train_model.py first.",
            "prediction": 0,
            "probability": 0.5
        }), 503

    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    try:
        # Extract features
        features = extract_features(url)
        features_scaled = scaler.transform([features])

        # Predict
        prediction = int(model.predict(features_scaled)[0])
        probabilities = model.predict_proba(features_scaled)[0]
        phishing_prob = float(probabilities[1])
        safe_prob = float(probabilities[0])

        # Confidence level
        max_prob = max(phishing_prob, safe_prob)
        if max_prob > 0.85:
            confidence = "high"
        elif max_prob > 0.65:
            confidence = "medium"
        else:
            confidence = "low"

        # Explanation
        explanation = get_feature_explanation(url, features, phishing_prob)

        label = "phishing" if prediction == 1 else "safe"

        logger.info(f"Prediction: {label} ({phishing_prob:.3f}) → {url[:80]}")

        return jsonify({
            "url": url,
            "prediction": prediction,
            "label": label,
            "probability": round(phishing_prob, 4),
            "safe_probability": round(safe_prob, 4),
            "confidence": confidence,
            "explanation": explanation,
        })

    except Exception as e:
        logger.error(f"Error predicting URL '{url}': {e}")
        return jsonify({
            "error": f"Prediction failed: {str(e)}",
            "prediction": 0,
            "probability": 0.5
        }), 500


@app.route("/batch-predict", methods=["POST"])
def batch_predict():
    """
    Predict multiple URLs at once.

    Request body (JSON):
        { "urls": ["url1", "url2", ...] }
    """
    if model is None:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json()
    if not data or "urls" not in data:
        return jsonify({"error": "Missing 'urls' in request body"}), 400

    urls = data["urls"]
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "'urls' must be a non-empty array"}), 400

    results = []
    for url in urls[:50]:  # Limit to 50 URLs per batch
        try:
            features = extract_features(url)
            features_scaled = scaler.transform([features])
            prediction = int(model.predict(features_scaled)[0])
            prob = float(model.predict_proba(features_scaled)[0][1])
            results.append({
                "url": url,
                "prediction": prediction,
                "label": "phishing" if prediction == 1 else "safe",
                "probability": round(prob, 4),
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"results": results, "count": len(results)})


# ─── Main ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_model()
    port = int(os.environ.get("FLASK_PORT", 5001))
    logger.info(f"Starting SafeLink AI Flask API on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
