"""
ScamShield AI - Reproducible Model Training & Evaluation Pipeline
Trains a Random Forest classifier on static URL lexical/structural features
and evaluates performance on a strictly held-out test split.

Outputs:
- ml/artifacts/phishing_model.joblib
- ml/artifacts/metrics.json
"""

import os
import sys
import json
import argparse
import joblib

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

from ml.dataset import generate_expanded_dataset, DATASET_METADATA
from ml.features import extract_features, features_to_vector, FEATURE_NAMES

def train_and_evaluate(seed: int = 42, output_dir: str = "ml/artifacts"):
    print(f"[*] Initializing ScamShield AI Model Training (random_seed={seed})...")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Load curated benchmark dataset
    df = generate_expanded_dataset()
    print(f"[+] Loaded {len(df)} total labeled URL instances.")
    print(f"    - Phishing samples (label=1): {int((df['label'] == 1).sum())}")
    print(f"    - Benign samples   (label=0): {int((df['label'] == 0).sum())}")

    # 2. Extract features
    print("[*] Extracting static lexical, structural, and entropy features...")
    feature_vectors = []
    for url in df['url']:
        feats = extract_features(url)
        vec = features_to_vector(feats)
        feature_vectors.append(vec)

    X = np.array(feature_vectors)
    y = df['label'].to_numpy()

    # 3. Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=seed, stratify=y
    )
    print(f"[+] Split dataset into {len(X_train)} training and {len(X_test)} held-out test samples.")

    # 4. Train Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        random_state=seed,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # 5. Evaluate strictly on held-out test set
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc_auc = float(roc_auc_score(y_test, y_proba))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    # 6. Feature importances
    importances = clf.feature_importances_
    feat_imp = [
        {"feature": name, "importance": round(float(imp), 4)}
        for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    ]

    metrics_payload = {
        "model_name": "RandomForestClassifier",
        "architecture": "RandomForestClassifier(n_estimators=100, max_depth=15, min_samples_split=4)",
        "random_seed": seed,
        "dataset_name": DATASET_METADATA["name"],
        "dataset_provenance": DATASET_METADATA["provenance"],
        "dataset_license": DATASET_METADATA["license"],
        "total_samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "true_positive": tp
            }
        },
        "feature_importances": feat_imp[:10]
    }

    # 7. Save model and metrics artifacts
    model_path = os.path.join(output_dir, "phishing_model.joblib")
    metrics_path = os.path.join(output_dir, "metrics.json")

    joblib.dump(clf, model_path)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print("\n=======================================================")
    print("      SCAMSHIELD AI - HELD-OUT EVALUATION RESULTS      ")
    print("=======================================================")
    print(f"  Test Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:        {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:           {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1-Score:         {f1:.4f} ({f1*100:.2f}%)")
    print(f"  ROC-AUC:          {roc_auc:.4f} ({roc_auc*100:.2f}%)")
    print("-------------------------------------------------------")
    print(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("=======================================================")
    print(f"[+] Artifacts written successfully to {output_dir}")
    print(f"    - Model:   {model_path}")
    print(f"    - Metrics: {metrics_path}\n")

    return metrics_payload

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScamShield AI Model Trainer")
    parser.add_argument("--seed", type=int, default=42, help="Reproducible random seed")
    parser.add_argument("--output", type=str, default="ml/artifacts", help="Output directory for model and metrics")
    args = parser.parse_args()

    train_and_evaluate(seed=args.seed, output_dir=args.output)
