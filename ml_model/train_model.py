#!/usr/bin/env python3
"""
Random Forest Model Training for DDoS Detection

Trains a Random Forest classifier on flow-based network traffic features
to distinguish normal traffic from DDoS attacks. The trained model and
feature scaler are saved as .pkl files for use by the Ryu SDN controller
(sdn_controller/mitigation_module.py).

Dataset Requirements:
    - CSV file with 13 columns (12 features + 1 label)
    - Features defined in utilities/feature_extractor.py
    - Label: 0 = normal traffic, 1 = DDoS attack
    - No NaN or Inf values (rows with NaN are dropped automatically)

Output Files:
    - flow_model.pkl: Trained RandomForestClassifier (loaded by controller)
    - scaler.pkl: Fitted StandardScaler (loaded by controller)

Usage:
    cd ml_model
    python3 train_model.py

    With custom dataset path:
    python3 train_model.py --dataset /path/to/dataset.csv

"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)
import joblib
import hashlib
import json
import argparse
import os
import sys

# Import feature definitions from the single source of truth
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from utilities.feature_extractor import (
    FEATURE_NAMES as FEATURE_COLUMNS,
    EXPECTED_FEATURE_COUNT,
    CSV_HEADERS as EXPECTED_COLUMNS,
    LABEL_COLUMN,
)


def load_dataset(filepath):
    """
    Load and validate the flow dataset from a CSV file.

    Reads the CSV, verifies it contains the expected columns (features
    + label as defined in feature_extractor), and drops any rows with
    missing values.

    Args:
        filepath (str): Path to the CSV dataset file.

    Returns:
        tuple: (X, y) where X is a DataFrame of features and y is a Series
               of labels.

    Raises:
        FileNotFoundError: If the dataset file does not exist.
        ValueError: If the dataset has incorrect columns.
    """
    print("=" * 70)
    print("  STEP 1: Loading Dataset")
    print("=" * 70)

    # Check file exists
    if not os.path.isfile(filepath):
        raise FileNotFoundError(
            f"Dataset not found at: {filepath}\n"
            f"Generate a dataset first:\n"
            f"  cd datasets && python3 generate_full_dataset.py"
        )

    # Load CSV
    print(f"  Loading: {filepath}")
    df = pd.read_csv(filepath)
    print(f"  Loaded {len(df)} rows, {len(df.columns)} columns")

    # Validate column count
    expected_col_count = EXPECTED_FEATURE_COUNT + 1  # features + label
    if len(df.columns) != expected_col_count:
        raise ValueError(
            f"Expected {expected_col_count} columns "
            f"({EXPECTED_FEATURE_COUNT} features + 1 label), "
            f"got {len(df.columns)}.\n"
            f"Expected columns: {EXPECTED_COLUMNS}\n"
            f"Got columns: {list(df.columns)}"
        )

    # Validate column names
    missing_cols = set(EXPECTED_COLUMNS) - set(df.columns)
    if missing_cols:
        raise ValueError(
            f"Missing required columns: {missing_cols}\n"
            f"Expected: {EXPECTED_COLUMNS}\n"
            f"Got: {list(df.columns)}"
        )

    # Check for missing values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        print(f"  WARNING: Found {nan_count} missing values, dropping affected rows")
        original_len = len(df)
        df = df.dropna()
        print(f"  Dropped {original_len - len(df)} rows ({len(df)} remaining)")
    else:
        print("  No missing values found")

    # Check for infinite values
    inf_count = np.isinf(df[FEATURE_COLUMNS].values).sum()
    if inf_count > 0:
        print(f"  WARNING: Found {inf_count} infinite values, replacing with 0")
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace(
            [np.inf, -np.inf], 0
        )

    # Separate features and label
    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]

    # Print dataset statistics
    print(f"\n  Dataset Summary:")
    print(f"    Total flows:   {len(df)}")
    print(f"    Normal (0):    {(y == 0).sum()} ({(y == 0).mean() * 100:.1f}%)")
    print(f"    Attack (1):    {(y == 1).sum()} ({(y == 1).mean() * 100:.1f}%)")
    print(f"    Features:      {EXPECTED_FEATURE_COUNT}")

    return X, y


def train_and_evaluate(X, y, temporal_split=False):
    """
    Split data, normalize, train Random Forest, and evaluate performance.

    Performs the following steps:
    1. Splits data 75/25 with stratification (or temporal order if --temporal-split)
    2. Fits StandardScaler on training data only (prevents data leakage)
    3. Transforms both train and test data
    4. Trains RandomForestClassifier with 100 trees, max depth 20
    5. Evaluates on test set with multiple metrics

    Args:
        X (DataFrame): Feature matrix.
        y (Series): Label vector (0=normal, 1=attack).
        temporal_split (bool): If True, use time-based split.

    Returns:
        tuple: (model, scaler, metrics_dict) containing the trained model,
               fitted scaler, and dictionary of evaluation metrics.
    """
    # =========================================================================
    # STEP 2: Train/Test Split
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 2: Splitting Dataset")
    print("=" * 70)

    if temporal_split:
        # Time-based split — first 75% for training, last 25% for testing
        # This simulates real deployment where model trains on past data
        split_idx = int(len(X) * 0.75)
        X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
        y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
        print("  Split method:  TEMPORAL (first 75% train, last 25% test)")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.25,
            random_state=42,
            stratify=y  # Maintain class balance in both sets
        )
        print("  Split method:  Stratified random (75/25, random_state=42)")

    print(f"  Training set:  {len(X_train)} flows "
          f"({(y_train == 0).sum()} normal, {(y_train == 1).sum()} attack)")
    print(f"  Test set:      {len(X_test)} flows "
          f"({(y_test == 0).sum()} normal, {(y_test == 1).sum()} attack)")

    # =========================================================================
    # STEP 3: Feature Normalization
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 3: Normalizing Features")
    print("=" * 70)

    # Fit scaler on training data ONLY to prevent data leakage
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("  StandardScaler fitted on training data")
    print(f"  Feature means (train):  {scaler.mean_[:3]}... (first 3)")
    print(f"  Feature stds (train):   {scaler.scale_[:3]}... (first 3)")

    # =========================================================================
    # STEP 4: Model Training
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 4: Training Random Forest Classifier")
    print("=" * 70)

    model = RandomForestClassifier(
        n_estimators=100,       # 100 decision trees in the forest
        max_depth=20,           # Maximum depth of each tree
        class_weight='balanced',  # Adjust weights inversely proportional to class frequency
        random_state=42         # Reproducible results
    )

    print("  Parameters:")
    print(f"    n_estimators:  {model.n_estimators}")
    print(f"    max_depth:     {model.max_depth}")
    print(f"    random_state:  {model.random_state}")
    print("\n  Training in progress...")

    model.fit(X_train_scaled, y_train)

    print("  Training complete!")

    # =========================================================================
    # STEP 4b: 5-Fold Stratified Cross-Validation
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 4b: 5-Fold Stratified Cross-Validation")
    print("=" * 70)

    # Build a pipeline so each fold fits its own scaler (no data leakage)
    cv_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=100, max_depth=20,
            class_weight='balanced', random_state=42
        ))
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']

    print("  Running 5-fold cross-validation on training set...")
    cv_results = cross_validate(
        cv_pipeline, X_train, y_train,
        cv=cv, scoring=cv_scoring, return_train_score=False
    )

    print("\n  Cross-Validation Results (mean +/- std):")
    for metric in cv_scoring:
        key = f'test_{metric}'
        scores = cv_results[key]
        print(f"    {metric:<12s}  {scores.mean():.4f} +/- {scores.std():.4f}"
              f"  (folds: {', '.join(f'{s:.4f}' for s in scores)})")

    # =========================================================================
    # STEP 5: Model Evaluation (holdout test set)
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 5: Evaluating Model Performance (holdout test set)")
    print("=" * 70)

    # Generate predictions on test set
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    conf_matrix = confusion_matrix(y_test, y_pred)

    # Store metrics in dictionary
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'roc_auc': roc_auc,
        'confusion_matrix': conf_matrix
    }

    # Print metrics
    print(f"\n  Accuracy:      {accuracy:.4f} ({accuracy * 100:.1f}%)")
    print(f"  Precision:     {precision:.4f} ({precision * 100:.1f}%)")
    print(f"  Recall:        {recall:.4f} ({recall * 100:.1f}%)")
    print(f"  F1-Score:      {f1:.4f} ({f1 * 100:.1f}%)")
    print(f"  ROC AUC:       {roc_auc:.4f}")

    # Print confusion matrix
    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                  Normal  Attack")
    print(f"    Actual Normal   {conf_matrix[0][0]:>6}  {conf_matrix[0][1]:>6}")
    print(f"    Actual Attack   {conf_matrix[1][0]:>6}  {conf_matrix[1][1]:>6}")

    # True Negatives, False Positives, False Negatives, True Positives
    tn, fp, fn, tp = conf_matrix.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    print(f"\n  True Positives:   {tp} (attacks correctly detected)")
    print(f"  True Negatives:   {tn} (normal correctly classified)")
    print(f"  False Positives:  {fp} (normal misclassified as attack)")
    print(f"  False Negatives:  {fn} (attacks missed)")
    print(f"  False Positive Rate: {fpr:.4f} ({fpr * 100:.1f}%)")

    # Print full classification report
    print(f"\n  Classification Report:")
    report = classification_report(
        y_test, y_pred,
        target_names=['Normal (0)', 'Attack (1)']
    )
    for line in report.split('\n'):
        print(f"    {line}")

    # Feature importance
    print(f"\n  Feature Importance (top contributors):")
    importances = model.feature_importances_
    importance_pairs = sorted(
        zip(FEATURE_COLUMNS, importances),
        key=lambda x: x[1],
        reverse=True
    )
    for feature, importance in importance_pairs:
        bar = '#' * int(importance * 50)
        print(f"    {feature:<30} {importance:.4f} {bar}")

    # =========================================================================
    # STEP 5b: Baseline Comparison
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 5b: Baseline Comparison")
    print("=" * 70)
    print("  Comparing Random Forest against simpler baselines to demonstrate")
    print("  that the model adds value beyond trivial classifiers.\n")

    baselines = [
        ("Majority Class (always normal)", DummyClassifier(strategy='most_frequent')),
        ("Stratified Random", DummyClassifier(strategy='stratified', random_state=42)),
        ("Logistic Regression", LogisticRegression(
            class_weight='balanced', max_iter=1000, random_state=42
        )),
    ]

    # Also add a simple PPS threshold baseline
    # Find the best threshold on pps (packet_count_per_second)
    pps_col_idx = FEATURE_COLUMNS.index('packet_count_per_second')
    pps_test = X_test_scaled[:, pps_col_idx]

    best_pps_f1 = 0
    best_pps_thresh = 0
    for percentile in range(5, 100, 5):
        thresh = np.percentile(pps_test, percentile)
        pps_pred = (pps_test > thresh).astype(int)
        pf1 = f1_score(y_test, pps_pred, zero_division=0)
        if pf1 > best_pps_f1:
            best_pps_f1 = pf1
            best_pps_thresh = thresh

    pps_pred_best = (pps_test > best_pps_thresh).astype(int)
    pps_acc = accuracy_score(y_test, pps_pred_best)
    pps_prec = precision_score(y_test, pps_pred_best, zero_division=0)
    pps_rec = recall_score(y_test, pps_pred_best, zero_division=0)
    pps_f1_final = f1_score(y_test, pps_pred_best, zero_division=0)

    print(f"  {'Model':<32} {'Accuracy':>9} {'Precision':>10} "
          f"{'Recall':>8} {'F1':>8}")
    print(f"  {'-'*32} {'-'*9} {'-'*10} {'-'*8} {'-'*8}")

    print(f"  {'PPS Threshold (best)':<32} {pps_acc:>9.4f} {pps_prec:>10.4f} "
          f"{pps_rec:>8.4f} {pps_f1_final:>8.4f}")

    for name, clf in baselines:
        clf.fit(X_train_scaled, y_train)
        bp = clf.predict(X_test_scaled)
        b_acc = accuracy_score(y_test, bp)
        b_prec = precision_score(y_test, bp, zero_division=0)
        b_rec = recall_score(y_test, bp, zero_division=0)
        b_f1 = f1_score(y_test, bp, zero_division=0)
        print(f"  {name:<32} {b_acc:>9.4f} {b_prec:>10.4f} "
              f"{b_rec:>8.4f} {b_f1:>8.4f}")

    # Print RF results in the same table for comparison
    print(f"  {'Random Forest (ours)':<32} {accuracy:>9.4f} {precision:>10.4f} "
          f"{recall:>8.4f} {f1:>8.4f}")

    rf_lift = f1 - best_pps_f1
    print(f"\n  RF F1 lift over best PPS threshold: {rf_lift:+.4f}")
    if rf_lift > 0.01:
        print("  Random Forest provides meaningful improvement over simple threshold.")
    else:
        print("  WARNING: RF does not significantly outperform a simple threshold.")
        print("  Consider improving the feature set or using real-world data.")

    # =========================================================================
    # STEP 5c: Adversarial Robustness Test
    # =========================================================================
    print("\n" + "=" * 70)
    print("  STEP 5c: Adversarial Robustness Test")
    print("=" * 70)
    print("  Testing model accuracy under feature perturbation.\n")

    # Perturb attack samples to make them look more like normal traffic
    attack_mask = (y_test == 1).values
    noise_levels = [0.05, 0.10, 0.20, 0.50]

    print(f"  {'Noise Level':<15} {'Accuracy':>9} {'Recall':>8} {'F1':>8} {'Evaded':>8}")
    print(f"  {'-'*15} {'-'*9} {'-'*8} {'-'*8} {'-'*8}")

    for noise in noise_levels:
        X_adv = X_test_scaled.copy()
        # Add Gaussian noise to attack samples only
        rng = np.random.RandomState(42)
        perturbation = rng.normal(0, noise, X_adv[attack_mask].shape)
        X_adv[attack_mask] += perturbation

        y_adv = model.predict(X_adv)
        adv_acc = accuracy_score(y_test, y_adv)
        adv_rec = recall_score(y_test, y_adv, zero_division=0)
        adv_f1 = f1_score(y_test, y_adv, zero_division=0)
        # Count attacks that evaded detection
        evaded = int((y_adv[attack_mask] == 0).sum())
        total_attacks = int(attack_mask.sum())

        print(f"  {noise:<15.2f} {adv_acc:>9.4f} {adv_rec:>8.4f} "
              f"{adv_f1:>8.4f} {evaded:>5}/{total_attacks}")

    # Summary assessment
    # Test at 10% noise
    X_adv_10 = X_test_scaled.copy()
    rng = np.random.RandomState(42)
    X_adv_10[attack_mask] += rng.normal(0, 0.10, X_adv_10[attack_mask].shape)
    adv_f1_10 = f1_score(y_test, model.predict(X_adv_10), zero_division=0)
    f1_drop = f1 - adv_f1_10

    if f1_drop < 0.05:
        print(f"\n  Model is reasonably robust (F1 drop at 10% noise: {f1_drop:.4f})")
    else:
        print(f"\n  WARNING: Model is fragile (F1 drop at 10% noise: {f1_drop:.4f})")
        print("  Consider adversarial training or more robust features.")

    return model, scaler, metrics


def save_artifacts(model, scaler):
    """
    Save the trained model and scaler to .pkl files.

    Saves both artifacts in the current directory (ml_model/) where they
    will be loaded by the SDN controller via relative path:
        ../ml_model/flow_model.pkl
        ../ml_model/scaler.pkl

    Args:
        model: Trained RandomForestClassifier instance.
        scaler: Fitted StandardScaler instance.
    """
    print("\n" + "=" * 70)
    print("  STEP 6: Saving Model Artifacts")
    print("=" * 70)

    # Determine save directory (same directory as this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Save the trained model
    model_path = os.path.join(script_dir, 'flow_model.pkl')
    joblib.dump(model, model_path)
    model_size = os.path.getsize(model_path) / (1024 * 1024)  # MB
    print(f"  Model saved:  {model_path}")
    print(f"  Model size:   {model_size:.2f} MB")

    # Save the fitted scaler
    scaler_path = os.path.join(script_dir, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    scaler_size = os.path.getsize(scaler_path) / 1024  # KB
    print(f"  Scaler saved: {scaler_path}")
    print(f"  Scaler size:  {scaler_size:.2f} KB")

    # Verify saved files can be loaded
    print("\n  Verifying saved artifacts...")
    try:
        loaded_model = joblib.load(model_path)
        loaded_scaler = joblib.load(scaler_path)
        print("  Verification: Model loads successfully")
        print("  Verification: Scaler loads successfully")
    except Exception as e:
        print(f"  WARNING: Verification failed: {e}")

    # Generate SHA-256 hashes for model integrity verification.
    # The controller checks these hashes before loading .pkl files to
    # prevent loading tampered models (pickle deserialization RCE).
    print("\n  Generating integrity hashes (SHA-256)...")
    hashes = {}
    for filename, filepath in [('flow_model.pkl', model_path),
                               ('scaler.pkl', scaler_path)]:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        hashes[filename] = sha256.hexdigest()
        print(f"    {filename}: {hashes[filename]}")

    hash_file_path = os.path.join(script_dir, 'model_hashes.json')
    with open(hash_file_path, 'w') as f:
        json.dump(hashes, f, indent=2)
    print(f"  Hash file saved: {hash_file_path}")

    print(f"\n  These files will be loaded by the SDN controller:")
    print(f"    sdn_controller/mitigation_module.py")
    print(f"    Path used: ../ml_model/flow_model.pkl")
    print(f"    Path used: ../ml_model/scaler.pkl")
    print(f"    Path used: ../ml_model/model_hashes.json (integrity check)")


def main():
    """
    Main entry point for model training.

    Parses command-line arguments, loads the dataset, trains the model,
    evaluates performance, and saves artifacts.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Train Random Forest model for DDoS detection'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        default=None,
        help='Path to CSV dataset (default: ../datasets/flow_dataset.csv)'
    )
    parser.add_argument(
        '--temporal-split',
        action='store_true',
        help='Use time-based train/test split (first 75%% train, last 25%% test) '
             'instead of random stratified split'
    )
    args = parser.parse_args()

    # Determine dataset path
    if args.dataset:
        dataset_path = args.dataset
    else:
        # Default: relative to this script's directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dataset_path = os.path.join(script_dir, '..', 'datasets', 'flow_dataset.csv')

    # Print banner
    print("\n" + "=" * 70)
    print("  DDoS Detection - Random Forest Model Training")
    print("  SDN-ML Integration Project")
    print("=" * 70)

    try:
        # Step 1: Load and validate dataset
        X, y = load_dataset(dataset_path)

        # Steps 2-5: Train and evaluate model
        model, scaler, metrics = train_and_evaluate(
            X, y, temporal_split=args.temporal_split
        )

        # Step 6: Save model and scaler
        save_artifacts(model, scaler)

        # Final summary
        print("\n" + "=" * 70)
        print("  TRAINING COMPLETE - Summary")
        print("=" * 70)
        print(f"  Accuracy:    {metrics['accuracy'] * 100:.1f}%")
        print(f"  Precision:   {metrics['precision'] * 100:.1f}%")
        print(f"  Recall:      {metrics['recall'] * 100:.1f}%")
        print(f"  F1-Score:    {metrics['f1_score'] * 100:.1f}%")
        print(f"  ROC AUC:     {metrics['roc_auc']:.4f}")
        print(f"\n  Files created:")
        print(f"    flow_model.pkl  (Random Forest classifier)")
        print(f"    scaler.pkl      (StandardScaler)")
        print(f"\n  Next steps:")
        print(f"    1. Start the controller: cd sdn_controller && ryu-manager mitigation_module.py")
        print(f"    2. Start the network:    cd network_topology && sudo python3 topology.py")
        print("=" * 70 + "\n")

    except FileNotFoundError as e:
        print(f"\n  ERROR: {e}")
        sys.exit(1)

    except ValueError as e:
        print(f"\n  ERROR: Invalid dataset format")
        print(f"  {e}")
        sys.exit(1)

    except Exception as e:
        print(f"\n  ERROR: Training failed")
        print(f"  {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
