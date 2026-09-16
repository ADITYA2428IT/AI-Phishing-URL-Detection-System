"""
train_model.py
---------------
Trains a Random Forest classifier on the URL feature set and saves the
model + evaluation report. Random Forest is chosen (over deep learning)
because:
  1. Feature importances are explainable - important for a SOC alert
     that needs to justify WHY a URL was flagged.
  2. Works well on small/medium tabular datasets without overfitting.
  3. Fast to train and run - suitable for real-time detection.
"""

import pandas as pd
import pickle
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

from feature_extraction import extract_features, FEATURE_ORDER

DATA_PATH = "urls_dataset.csv"
MODEL_PATH = "phishing_model.pkl"
REPORT_PATH = "training_report.json"


def build_feature_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for url in df["url"]:
        feats = extract_features(url)
        rows.append(feats)
    feat_df = pd.DataFrame(rows)[FEATURE_ORDER]
    return feat_df


def main():
    df = pd.read_csv(DATA_PATH)
    X = build_feature_dataframe(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    feature_importance = dict(
        sorted(
            zip(FEATURE_ORDER, model.feature_importances_.tolist()),
            key=lambda x: x[1], reverse=True
        )
    )
    metrics["feature_importance"] = {k: round(v, 4) for k, v in feature_importance.items()}

    print("=== Model Evaluation ===")
    print(json.dumps(metrics, indent=2))
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(REPORT_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to {MODEL_PATH}")
    print(f"Report saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
