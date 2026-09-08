"""
train_model.py

Pipeline for dataset loading, preprocessing, model training, and evaluation.
Trains both Random Forest (primary baseline) and Decision Tree (interpretable comparison)
on the cybersecurity network session dataset.
Serializes trained artifacts to models/ for Agent 1 runtime inference.
"""

import os
import sys
import shutil

# Ensure current directory is in sys.path for local module resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from evaluation.metrics import evaluate_classifier, get_academic_accuracy_critique


def prepare_and_train():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    raw_dir = os.path.join(base_dir, "data", "raw")
    processed_dir = os.path.join(base_dir, "data", "processed")
    models_dir = os.path.join(base_dir, "models")
    
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    # Resolve dataset path
    raw_csv_path = os.path.join(raw_dir, "cybersecurity_intrusion_data.csv")
    parent_csv_path = os.path.join(os.path.dirname(base_dir), "cybersecurity_intrusion_data.csv")

    if not os.path.exists(raw_csv_path):
        if os.path.exists(parent_csv_path):
            shutil.copy(parent_csv_path, raw_csv_path)
            print(f"[+] Copied raw dataset to: {raw_csv_path}")
        else:
            raise FileNotFoundError(f"Cannot locate dataset at {raw_csv_path} or {parent_csv_path}")

    print(f"[*] Loading dataset from: {raw_csv_path}")
    df = pd.read_csv(raw_csv_path)
    print(f"[+] Total records loaded: {len(df)} | Columns: {len(df.columns)}")

    # Data Preprocessing
    # Handle missing encryption_used (plain-text unencrypted traffic)
    df["encryption_used"] = df["encryption_used"].fillna("None")

    numeric_features = [
        "network_packet_size",
        "login_attempts",
        "session_duration",
        "ip_reputation_score",
        "failed_logins"
    ]
    categorical_features = [
        "protocol_type",
        "encryption_used",
        "browser_type"
    ]
    binary_features = [
        "unusual_time_access"
    ]

    target_col = "attack_detected"

    X = df[numeric_features + categorical_features + binary_features]
    y = df[target_col].values

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[+] Training split: {len(X_train)} samples | Test split: {len(X_test)} samples")
    print(f"[+] Class balance in training: Normal={np.sum(y_train==0)}, Attack={np.sum(y_train==1)}")

    # ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical_features),
            ("bin", "passthrough", binary_features)
        ]
    )

    print("[*] Fitting preprocessing pipeline on training data...")
    X_train_proc = preprocessor.fit_transform(X_train)
    X_test_proc = preprocessor.transform(X_test)

    # Save processed datasets
    joblib.dump(X_train_proc, os.path.join(processed_dir, "X_train.joblib"))
    joblib.dump(X_test_proc, os.path.join(processed_dir, "X_test.joblib"))
    joblib.dump(y_train, os.path.join(processed_dir, "y_train.joblib"))
    joblib.dump(y_test, os.path.join(processed_dir, "y_test.joblib"))
    joblib.dump(preprocessor, os.path.join(models_dir, "preprocessor.joblib"))
    print("[+] Preprocessor and processed data serialized successfully.")

    # 1. Primary Model: Random Forest
    print("\n========================================================")
    print(" TRAINING PRIMARY MODEL: RANDOM FOREST CLASSIFIER")
    print("========================================================")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=1
    )
    rf_model.fit(X_train_proc, y_train)
    y_pred_rf = rf_model.predict(X_test_proc)
    rf_metrics = evaluate_classifier(y_test, y_pred_rf)

    print(f"Accuracy:            {rf_metrics['accuracy'] * 100:.2f}%")
    print(f"Precision (Attack):  {rf_metrics['precision'] * 100:.2f}%")
    print(f"Recall (Attack):     {rf_metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:            {rf_metrics['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate: {rf_metrics['false_positive_rate'] * 100:.2f}%")
    print(f"False Negative Rate: {rf_metrics['false_negative_rate'] * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  TN: {rf_metrics['confusion_matrix']['true_negatives']} | FP: {rf_metrics['confusion_matrix']['false_positives']}")
    print(f"  FN: {rf_metrics['confusion_matrix']['false_negatives']} | TP: {rf_metrics['confusion_matrix']['true_positives']}")
    print("\nClassification Report:\n", rf_metrics['classification_report'])

    joblib.dump(rf_model, os.path.join(models_dir, "random_forest.joblib"))

    # 2. Baseline Model: Decision Tree
    print("\n========================================================")
    print(" TRAINING BASELINE COMPARISON: DECISION TREE CLASSIFIER")
    print("========================================================")
    dt_model = DecisionTreeClassifier(max_depth=5, random_state=42)
    dt_model.fit(X_train_proc, y_train)
    y_pred_dt = dt_model.predict(X_test_proc)
    dt_metrics = evaluate_classifier(y_test, y_pred_dt)

    print(f"Accuracy:            {dt_metrics['accuracy'] * 100:.2f}%")
    print(f"Precision (Attack):  {dt_metrics['precision'] * 100:.2f}%")
    print(f"Recall (Attack):     {dt_metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:            {dt_metrics['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate: {dt_metrics['false_positive_rate'] * 100:.2f}%")
    print(f"False Negative Rate: {dt_metrics['false_negative_rate'] * 100:.2f}%")

    joblib.dump(dt_model, os.path.join(models_dir, "decision_tree.joblib"))

    print("\n" + get_academic_accuracy_critique())
    print(f"\n[+] All models successfully saved to {models_dir}/")


if __name__ == "__main__":
    prepare_and_train()
