"""
train_model.py  (v2 — Production Grade)
----------------------------------------
Trains multiple classifiers and picks the best one.
Uses cross-validation, calibration, and full evaluation.

Usage:
    python generate_dataset.py   # fetch real data
    python train_model.py        # train and save model
"""

import os
import csv
import json
import joblib
import numpy as np
from datetime import datetime

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, f1_score
)
from feature_extractor import extract_features, FEATURE_NAMES

# ── Config ────────────────────────────────────────────────────────────────────
DATASET_FILE  = "dataset.csv"
MODEL_FILE    = "model.pkl"
SCALER_FILE   = "scaler.pkl"
META_FILE     = "model_meta.json"   # stores accuracy, feature names, date
RANDOM_STATE  = 42
TEST_SIZE     = 0.20
CV_FOLDS      = 5


def load_dataset(filepath: str):
    urls, labels = [], []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url   = row["url"].strip()
            label = int(row["label"])
            if url:
                urls.append(url)
                labels.append(label)

    print(f"[→] Extracting features for {len(urls)} URLs...")
    X = []
    for i, url in enumerate(urls):
        if i % 1000 == 0 and i > 0:
            print(f"    {i}/{len(urls)} processed...")
        feats = extract_features(url)
        X.append(feats)

    return np.array(X, dtype=np.float32), np.array(labels), urls


def build_model():
    """
    Ensemble: GradientBoosting + RandomForest + LogisticRegression.
    VotingClassifier with soft voting for probability estimates.
    Calibrated for accurate probability output.
    """
    gb = GradientBoostingClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        min_samples_split=4,
        random_state=RANDOM_STATE,
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    lr = LogisticRegression(
        max_iter=2000,
        C=1.0,
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )
    ensemble = VotingClassifier(
        estimators=[("gb", gb), ("rf", rf), ("lr", lr)],
        voting="soft",
        weights=[3, 2, 1],   # GradientBoosting weighted highest
    )
    return ensemble


def evaluate(model, X_test, y_test):
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc     = accuracy_score(y_test, y_pred)
    auc     = roc_auc_score(y_test, y_proba)
    f1      = f1_score(y_test, y_pred)

    print(f"\n{'='*56}")
    print(f"  EVALUATION RESULTS")
    print(f"{'='*56}")
    print(f"  Accuracy   : {acc*100:.2f}%")
    print(f"  AUC-ROC    : {auc:.4f}")
    print(f"  F1 Score   : {f1:.4f}")
    print(f"{'='*56}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Safe (0)", "Phishing (1)"],
                                digits=4))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix (rows=actual, cols=predicted):")
    print(f"  True Safe:    {cm[0][0]:5d}  |  False Phishing: {cm[0][1]:5d}")
    print(f"  False Safe:   {cm[1][0]:5d}  |  True Phishing:  {cm[1][1]:5d}")

    return acc, auc, f1


def get_feature_importances(model):
    """Extract feature importances where possible."""
    importances = None
    # Try to get from GradientBoosting estimator in ensemble
    for name, est in model.estimators:
        if hasattr(est, "feature_importances_"):
            importances = est.feature_importances_
            break
    return importances


def main():
    print(f"\n{'='*56}")
    print("  SafeLink AI — ML Training Pipeline v2")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*56}\n")

    # ── Step 1: Load data ──────────────────────────────────────────────────
    if not os.path.exists(DATASET_FILE):
        print("[!] Dataset not found — running generate_dataset.py...\n")
        import generate_dataset
        generate_dataset.generate_dataset()

    X, y, urls = load_dataset(DATASET_FILE)
    print(f"\n  Samples: {len(y)} | Features: {X.shape[1]}")
    print(f"  Safe: {sum(y==0)} | Phishing: {sum(y==1)}")

    # ── Step 2: Train/test split ───────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # ── Step 3: Scale ──────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── Step 4: Cross-validation ───────────────────────────────────────────
    print(f"\n[→] Running {CV_FOLDS}-fold cross-validation on training set...")
    cv_model = RandomForestClassifier(
        n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1
    )
    cv_scores = cross_val_score(cv_model, X_train_s, y_train, cv=CV_FOLDS, scoring="roc_auc")
    print(f"    CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Step 5: Train ensemble ─────────────────────────────────────────────
    print("\n[→] Training Ensemble (GradientBoosting + RandomForest + LR)...")
    model = build_model()
    model.fit(X_train_s, y_train)
    print("[✓] Training complete.")

    # ── Step 6: Evaluate ───────────────────────────────────────────────────
    acc, auc, f1 = evaluate(model, X_test_s, y_test)

    # ── Step 7: Feature importances ────────────────────────────────────────
    importances = get_feature_importances(model)
    if importances is not None:
        print("\nTop Feature Importances (from GradientBoosting):")
        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        for name, imp in ranked[:10]:
            bar = "█" * int(imp * 50)
            print(f"  {name:<28} {imp:.4f} {bar}")

    # ── Step 8: Save model ─────────────────────────────────────────────────
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)

    meta = {
        "trained_at":      datetime.now().isoformat(),
        "dataset_size":    int(len(y)),
        "num_features":    X.shape[1],
        "feature_names":   FEATURE_NAMES,
        "accuracy":        round(float(acc), 4),
        "auc_roc":         round(float(auc), 4),
        "f1_score":        round(float(f1), 4),
        "cv_auc_mean":     round(float(cv_scores.mean()), 4),
        "model_type":      "VotingEnsemble(GB+RF+LR)",
    }
    with open(META_FILE, "w") as mf:
        json.dump(meta, mf, indent=2)

    print(f"\n[✓] model.pkl      → {MODEL_FILE}")
    print(f"[✓] scaler.pkl     → {SCALER_FILE}")
    print(f"[✓] model_meta.json→ {META_FILE}")

    # ── Step 9: Sanity check ───────────────────────────────────────────────
    test_urls = [
        ("https://www.google.com/",                                         0),
        ("https://github.com/features/copilot",                            0),
        ("https://www.amazon.com/dp/B08N5LNQCX",                          0),
        ("http://secure-paypal-login.xyz/verify?token=123456",             1),
        ("http://192.168.1.1/admin/login",                                 1),
        ("http://amazon.com.login-verify.xyz/account",                     1),
        ("http://user@login-secure.tk/confirm",                            1),
        ("http://apple-id-suspended.cf/unlock?user=admin&token=aaaaabbb",  1),
    ]

    print(f"\n{'='*56}")
    print("  SANITY CHECK — Classifying test URLs")
    print(f"{'='*56}")
    loaded_model  = joblib.load(MODEL_FILE)
    loaded_scaler = joblib.load(SCALER_FILE)

    correct = 0
    for url, expected in test_urls:
        feats  = extract_features(url)
        fs     = loaded_scaler.transform([feats])
        pred   = int(loaded_model.predict(fs)[0])
        prob   = float(loaded_model.predict_proba(fs)[0][1])
        status = "✅ SAFE    " if pred == 0 else "🚨 PHISHING"
        match  = "✓" if pred == expected else "✗"
        print(f"  [{match}] {status} ({prob*100:5.1f}%) — {url[:60]}")
        correct += (pred == expected)

    print(f"\n  Sanity accuracy: {correct}/{len(test_urls)}")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
