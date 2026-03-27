# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 6: AI Engine — Model Trainerclear
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Trains, evaluates, and saves the AIPET
#              vulnerability classification model.
#              Uses Random Forest with class balancing
#              to handle IoT CVE dataset imbalance.
#              Evaluates using F1-score, precision, recall,
#              and confusion matrix per the research KPIs.
# =============================================================

import pandas as pd
import numpy as np
import json
import os
import pickle
from datetime import datetime

# Machine learning imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    train_test_split,
    cross_val_score,
    StratifiedKFold
)
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score
)
from sklearn.preprocessing import LabelEncoder

# ── Constants ─────────────────────────────────────────────────

# Severity label names — must match generate_dataset.py
SEVERITY_LABELS = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical"
}

# Target F1-score from our research KPIs
# We committed to ≥ 85% F1-score in the proposal
TARGET_F1_SCORE = 0.85

# Paths
DATASET_PATH = "ai_engine/data/iot_vulnerability_dataset.csv"
MODEL_DIR    = "ai_engine/models"
MODEL_PATH   = f"{MODEL_DIR}/aipet_model.pkl"
METRICS_PATH = f"{MODEL_DIR}/model_metrics.json"


# ── Step 1: Load and prepare data ────────────────────────────
def load_and_prepare_data(dataset_path):
    """
    Load the IoT vulnerability dataset and prepare it
    for model training.

    Separates features (X) from target labels (y).
    Applies stratified train/test split to ensure all
    severity classes are represented in both sets.

    Stratified splitting is essential here because our
    dataset has class imbalance — without stratification
    the test set might have very few Low/Medium samples.

    Args:
        dataset_path (str): Path to CSV dataset file

    Returns:
        tuple: (X_train, X_test, y_train, y_test,
                feature_names)
    """
    print("[*] Loading dataset...")

    # Load CSV into pandas DataFrame
    df = pd.read_csv(dataset_path)

    print(f"    [+] Loaded {len(df)} samples, "
          f"{len(df.columns)} columns")

    # Separate features from target label
    # X = all columns except 'severity'
    # y = the 'severity' column we want to predict
    feature_columns = [
        col for col in df.columns if col != 'severity'
    ]
    X = df[feature_columns]
    y = df['severity']

    print(f"    [+] Features: {len(feature_columns)}")
    print(f"    [+] Label distribution:")
    for label, name in SEVERITY_LABELS.items():
        count = (y == label).sum()
        print(f"        {name}: {count} ({count/len(y)*100:.1f}%)")

    # Stratified train/validation/test split
    # 70% training, 15% validation, 15% test
    # stratify=y ensures class proportions are preserved
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=0.30,
        random_state=42,    # Fixed seed for reproducibility
        stratify=y          # Preserve class balance
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp
    )

    print(f"\n    [+] Train: {len(X_train)} samples")
    print(f"    [+] Validation: {len(X_val)} samples")
    print(f"    [+] Test: {len(X_test)} samples")

    return (X_train, X_val, X_test,
            y_train, y_val, y_test,
            feature_columns)


# ── Step 2: Train model ───────────────────────────────────────
def train_model(X_train, y_train, feature_names):
    """
    Train a Random Forest classifier on the IoT
    vulnerability dataset.

    Why Random Forest?
    - Handles class imbalance with class_weight='balanced'
    - Provides feature importance scores natively
    - Works well with mixed binary and categorical features
    - Resistant to overfitting due to ensemble averaging
    - Produces probability scores needed for SHAP
    - Fast training and prediction for real-time use

    The class_weight='balanced' parameter automatically
    adjusts weights inversely proportional to class
    frequency — Low/Medium get higher weight to compensate
    for being underrepresented in the training data.

    Args:
        X_train: Training features
        y_train: Training labels
        feature_names (list): Feature column names

    Returns:
        RandomForestClassifier: Trained model
    """
    print("\n[*] Training Random Forest classifier...")
    print("    [*] Using class_weight='balanced' to handle")
    print("        class imbalance in dataset")

    # Initialise Random Forest with carefully chosen params
    model = RandomForestClassifier(
        n_estimators=200,       # 200 decision trees in ensemble
                                # More trees = more stable but slower
        max_depth=15,           # Max depth of each tree
                                # Prevents overfitting
        min_samples_split=5,    # Min samples to split a node
                                # Prevents overfitting on small groups
        min_samples_leaf=2,     # Min samples in each leaf node
        class_weight='balanced',# Compensate for class imbalance
        random_state=42,        # Fixed seed for reproducibility
        n_jobs=-1,              # Use all CPU cores for speed
        oob_score=True          # Out-of-bag score for validation
    )

    # Fit the model on training data
    # This is where the 200 decision trees are built
    model.fit(X_train, y_train)

    print(f"    [+] Training complete")
    print(f"    [+] Out-of-bag score: "
          f"{model.oob_score_:.4f}")
    print(f"        (OOB score is a free validation metric")
    print(f"         from samples not used in each tree)")

    # Print top 10 most important features
    print("\n    [+] Top 10 most important features:")
    importances = pd.Series(
        model.feature_importances_,
        index=feature_names
    ).sort_values(ascending=False)

    for feature, importance in importances.head(10).items():
        bar = "█" * int(importance * 100)
        print(f"        {importance:.4f}  {feature}  {bar}")

    return model


# ── Step 3: Evaluate model ────────────────────────────────────
def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance against our research KPIs.

    Primary metric: weighted F1-score ≥ 0.85
    Secondary metrics: precision, recall, accuracy,
                       per-class F1, confusion matrix

    Weighted F1-score is appropriate here because:
    - It accounts for class imbalance
    - It balances precision (false positive rate) and
      recall (false negative rate) equally
    - It is the industry standard for imbalanced
      classification problems

    Args:
        model: Trained RandomForestClassifier
        X_test: Test features
        y_test: True test labels

    Returns:
        dict: Complete evaluation metrics
    """
    print("\n[*] Evaluating model on held-out test set...")

    # Generate predictions
    y_pred      = model.predict(X_test)
    y_pred_prob = model.predict_proba(X_test)

    # Calculate metrics
    f1        = f1_score(y_test, y_pred, average='weighted')
    precision = precision_score(
        y_test, y_pred, average='weighted', zero_division=0
    )
    recall    = recall_score(
        y_test, y_pred, average='weighted', zero_division=0
    )
    accuracy  = accuracy_score(y_test, y_pred)

    # Per-class F1 scores
    f1_per_class = f1_score(
        y_test, y_pred, average=None, zero_division=0
    )

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n    {'─' * 40}")
    print(f"    EVALUATION RESULTS")
    print(f"    {'─' * 40}")
    print(f"    Weighted F1-Score:  {f1:.4f}  "
          f"{'✅ ABOVE TARGET' if f1 >= TARGET_F1_SCORE else '⚠️  BELOW TARGET'}")
    print(f"    Target F1-Score:   {TARGET_F1_SCORE:.4f}")
    print(f"    Precision:         {precision:.4f}")
    print(f"    Recall:            {recall:.4f}")
    print(f"    Accuracy:          {accuracy:.4f}")

    print(f"\n    Per-class F1 scores:")
    for i, (label, name) in enumerate(SEVERITY_LABELS.items()):
        if i < len(f1_per_class):
            score = f1_per_class[i]
            print(f"      {name:10}: {score:.4f}")

    print(f"\n    Confusion Matrix:")
    print(f"    (rows=actual, cols=predicted)")
    header = "    " + "  ".join(
        f"{SEVERITY_LABELS[i]:8}" for i in range(4)
    )
    print(header)
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{val:8}" for val in row)
        print(f"    {SEVERITY_LABELS[i]:8}  {row_str}")

    # Full classification report
    print(f"\n    Full Classification Report:")
    report = classification_report(
        y_test, y_pred,
        target_names=[SEVERITY_LABELS[i] for i in range(4)],
        zero_division=0
    )
    for line in report.split('\n'):
        print(f"    {line}")

    # Package metrics for saving
    metrics = {
        "evaluation_date":  datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"),
        "test_samples":     len(y_test),
        "f1_weighted":      round(float(f1), 4),
        "precision":        round(float(precision), 4),
        "recall":           round(float(recall), 4),
        "accuracy":         round(float(accuracy), 4),
        "target_f1":        TARGET_F1_SCORE,
        "target_met":       bool(f1 >= TARGET_F1_SCORE),
        "f1_per_class": {
            SEVERITY_LABELS[i]: round(float(f1_per_class[i]), 4)
            for i in range(len(f1_per_class))
        },
        "confusion_matrix": cm.tolist(),
        "feature_importance": {}
    }

    return metrics


# ── Step 4: Cross-validation ──────────────────────────────────
def cross_validate_model(model, X, y):
    """
    Perform 5-fold stratified cross-validation.

    Cross-validation gives a more reliable estimate of
    model performance than a single train/test split.
    It trains and evaluates the model 5 times on different
    data splits and reports the mean and standard deviation.

    Stratified K-Fold ensures each fold has the same
    class proportion as the full dataset — essential
    for imbalanced datasets.

    Args:
        model: RandomForestClassifier to validate
        X: Full feature set
        y: Full label set

    Returns:
        dict: Cross-validation scores
    """
    print("\n[*] Running 5-fold stratified cross-validation...")
    print("    (This validates model generalises to new data)")

    # Stratified K-Fold cross-validator
    cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    # Calculate weighted F1 across all folds
    cv_scores = cross_val_score(
        model, X, y,
        cv=cv,
        scoring='f1_weighted',
        n_jobs=-1
    )

    mean_f1 = cv_scores.mean()
    std_f1  = cv_scores.std()

    print(f"    [+] CV F1 scores per fold:")
    for i, score in enumerate(cv_scores):
        print(f"        Fold {i+1}: {score:.4f}")

    print(f"\n    [+] Mean F1:  {mean_f1:.4f}")
    print(f"    [+] Std Dev:  {std_f1:.4f}")
    print(f"    [+] 95% CI:   [{mean_f1 - 2*std_f1:.4f}, "
          f"{mean_f1 + 2*std_f1:.4f}]")

    if std_f1 < 0.05:
        print("    [+] Low variance — model is stable ✅")
    else:
        print("    [!] High variance — model may be unstable")

    return {
        "cv_scores":  cv_scores.tolist(),
        "mean_f1":    round(float(mean_f1), 4),
        "std_f1":     round(float(std_f1), 4),
        "ci_lower":   round(float(mean_f1 - 2*std_f1), 4),
        "ci_upper":   round(float(mean_f1 + 2*std_f1), 4),
    }


# ── Step 5: Save model ────────────────────────────────────────
def save_model(model, metrics, feature_names):
    """
    Save the trained model and evaluation metrics to disk.

    The model is saved using pickle — Python's built-in
    object serialisation. This allows the exact trained
    model to be loaded later without retraining.

    Feature names are saved alongside the model so the
    AI engine always knows which features to extract
    from device profiles.

    Args:
        model: Trained RandomForestClassifier
        metrics (dict): Evaluation metrics
        feature_names (list): Feature column names
    """
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model with pickle
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump({
            "model":         model,
            "feature_names": feature_names,
            "severity_labels": SEVERITY_LABELS,
            "saved_at":      datetime.now().strftime(
                                 "%Y-%m-%d %H:%M:%S")
        }, f)

    print(f"\n[+] Model saved to {MODEL_PATH}")

    # Add feature importances to metrics
    importances = dict(zip(
        feature_names,
        model.feature_importances_.tolist()
    ))
    metrics["feature_importance"] = importances

    # Save metrics as JSON
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=4)

    print(f"[+] Metrics saved to {METRICS_PATH}")


# ── Main Training Pipeline ────────────────────────────────────
def train_aipet_model():
    """
    Complete model training pipeline.

    Steps:
        1. Load and prepare dataset
        2. Train Random Forest classifier
        3. Evaluate on held-out test set
        4. Cross-validate for stability check
        5. Save model and metrics

    Returns:
        tuple: (trained_model, metrics)
    """
    print("=" * 60)
    print("  AIPET — Module 6: Model Trainer")
    print("=" * 60)

    # Step 1 — Load data
    (X_train, X_val, X_test,
     y_train, y_val, y_test,
     feature_names) = load_and_prepare_data(DATASET_PATH)

    # Combine X and y for cross-validation
    import pandas as pd
    X_full = pd.read_csv(DATASET_PATH).drop(
        columns=['severity']
    )
    y_full = pd.read_csv(DATASET_PATH)['severity']

    # Step 2 — Train model
    model = train_model(X_train, y_train, feature_names)

    # Step 3 — Evaluate on test set
    metrics = evaluate_model(model, X_test, y_test)

    # Step 4 — Cross-validate
    cv_results = cross_validate_model(model, X_full, y_full)
    metrics["cross_validation"] = cv_results

    # Step 5 — Save model and metrics
    save_model(model, metrics, feature_names)

    # Final result
    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    f1 = metrics["f1_weighted"]
    print(f"  Final F1-Score: {f1:.4f}")
    print(f"  Target F1:      {TARGET_F1_SCORE:.4f}")
    if metrics["target_met"]:
        print(f"  Result: ✅ TARGET MET — "
              f"Model ready for deployment")
    else:
        print(f"  Result: ⚠️  Below target — "
              f"consider expanding dataset")
    print("=" * 60)

    return model, metrics


if __name__ == "__main__":
    train_aipet_model()